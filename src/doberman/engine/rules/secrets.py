"""Secret-leakage detection (Feature 3, slices 3.2 + 3.6).

This rule answers two questions about an action:

1. **Is secret material present** in what the agent is about to send/write?
   (known credential prefixes, PEM blocks, ``KEY=value`` ``.env`` lines, or
   high-entropy tokens; and base64/hex carriers that *decode* to any of those
   — the encoded-exfiltration check from slice 3.6).
2. **Where is it going** — to an external destination, or just locally?

Verdicts:

* secret content **+ an external destination** → ``BLOCK (secret_exfiltration)``
  — the headline disaster (uploading ``.env`` to an unknown endpoint).
* reading/touching a **secret file locally** → ``AUTH (sensitive_secret_access)``.
* anything ambiguous → ``AUTH`` (we bias to authentication, not blocking, except
  the clear exfil case above) — never PASS-on-doubt.

SECURITY / redaction: the secret value, its path, and any decoded payload are
**never** placed in the explanation, a reason, or a log. Detected secrets are
turned into keyed HMAC fingerprints (for the rule's own bookkeeping); the
agent-visible explanation only ever names the *rule*. This is defense-in-depth
and intentionally imperfect — it will not catch encrypted or semantically
summarized exfiltration (documented, not marketed as airtight).
"""

import base64
import binascii
import logging
import math
import re
from collections.abc import Iterable, Iterator
from urllib.parse import parse_qsl, urlsplit

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.storage.fingerprint import fingerprint

logger = logging.getLogger("doberman.engine.rules.secrets")

# --- Secret material patterns ------------------------------------------------
# Known high-confidence credential shapes. Kept conservative: a match here is
# strong evidence of a real secret, so it can drive a BLOCK when combined with
# an external destination.
_CREDENTIAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"ASIA[0-9A-Z]{16}"),  # AWS temporary access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style secret key (classic sk-…)
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),  # OpenAI project/scoped key (hyphenated)
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),  # Anthropic API key (sk-ant-api03-…)
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub classic/app tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),  # GitHub fine-grained PAT
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),  # GitLab personal access token
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    # Slack incoming-webhook URL (carries send capability)
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),  # Google API key
    re.compile(
        r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}"
    ),  # Stripe live/test secret/restricted key
    re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),  # SendGrid API key
    re.compile(r"npm_[A-Za-z0-9]{36}"),  # npm access token
    re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}"),  # PyPI API token
    # JWT: two base64url JSON segments (header/payload start with eyJ) + signature
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # DB / message-queue connection URI with embedded user:password credentials
    re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@"),
    re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----"),  # PEM private key
    # --- Azure ---------------------------------------------------------------
    # Azure Storage account key (connection-string `AccountKey=…`, 44-char base64).
    re.compile(r"AccountKey=[A-Za-z0-9+/]{40,}={0,2}"),
    # Azure Service Bus / Event Hubs / IoT Hub shared access key (`SharedAccessKey=…`).
    re.compile(r"SharedAccessKey=[A-Za-z0-9+/]{40,}={0,2}"),
    # --- GCP ----------------------------------------------------------------
    # GCP service-account key JSON marker (`"type": "service_account"`).
    re.compile(r'"type"\s*:\s*"service_account"'),
)

# ``.env``-style assignment of a secret-looking key to a non-trivial value.
# Case-INSENSITIVE on purpose (#56): a lowercase ``private_key=…`` is still a real
# secret assignment, so keeping ``(?i)`` preserves recall. Benign lowercase config
# like ``configure_token_path=/usr/local/bin`` is excluded by the VALUE check
# (``_value_looks_secretish``), not by key case — precision without a recall hit.
_ENV_ASSIGNMENT = re.compile(
    r"(?im)^\s*(?:export\s+)?"
    r"[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASS(?:WORD)?|CREDENTIAL|PRIVATE)[A-Z0-9_]*"
    r"\s*=\s*['\"]?(?P<value>[^\s'\"]{8,})"
)

# Assignment VALUES that are obviously not secrets — placeholders, paths, URLs.
# A secret-named key only counts as secret material when its value is plausibly a
# real secret (#56): a README's ``API_KEY=your_key_here`` or a config's
# ``..._path=/usr/local/bin`` must not be flagged. Anchored to the whole value so a
# real secret that merely *contains* one of these substrings is not dropped.
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:"
    r"your[_\-].*|.*[_\-]here|change[_\-]?me|placeholder.*|redacted.*|dummy.*|"
    r"example[_\-].*|sample[_\-].*|test[_\-]?(?:key|token|secret).*|"
    r"<.*>|\$\{.*\}|\*{3,}|x{4,}"
    r")$"
)

# --- Bare-token fixture / pattern-source suppression (#73) -------------------
# ``_PLACEHOLDER_VALUE`` above only ever runs against an assignment RHS
# (``KEY = <value>``). A BARE token — a credential-shaped substring in prose, a
# diff, or a markdown table, with no ``KEY =`` to anchor an allowlist check
# against — never reached it, so a hand-written test fixture (built by string
# concatenation so it still exercises the rule at runtime, e.g.
# ``"sk-ant-" + "api03-" + "EXAMPLE0123456789..."``) read as secret-shaped.
#
# The judge below is WEAK-path only and must stay RAISE-ONLY. The hard part is
# that a fixture marker (``EXAMPLE``) or ordered filler (``0123456789``) is
# ATTACKER-CONTROLLABLE: an agent exfiltrating a real secret could simply append
# ``EXAMPLE`` to dodge a naive marker filter — and for a shapeless (no known
# prefix) secret the WEAK entropy heuristic is the ONLY thing standing in the
# way, so a naive filter would be a one-line bypass of the whole control. We
# therefore do NOT trust a marker on its own. The real discriminator is that a
# hand-written fixture is built from *ordered scaffolding* (marker words plus
# ascending ``0-9``/``a-z`` runs) and, once that scaffolding is stripped, has
# little left; a real secret is *random* and keeps a high-entropy residual after
# the same stripping. So: strip the markers and the ascending runs, and suppress
# only when what remains is too short / low-entropy to be a secret on its own
# (``_looks_high_entropy_secret``). A real key wearing an ``EXAMPLE`` costume
# still fires.
#
# Regex-pattern SOURCE evidence (a literal ``[``, ``]``, ``{``, ``}``, or ``\``)
# is a separate, unconditional signal: no character class in
# ``_CREDENTIAL_PATTERNS`` / ``_ENTROPY_TOKEN`` — nor the weak-path tokenizer
# charset — ever admits those characters, so their presence in a token proves it
# is a quoted pattern (``sk-ant-[A-Za-z0-9_-]{20,}``), never a live secret; it
# can never cause a false negative on a real token.
_FIXTURE_MARKER_WORDS = ("EXAMPLE", "SAMPLE", "FAKE", "DUMMY")
_FIXTURE_MARKER_ANYWHERE = re.compile("(?i)(?:" + "|".join(_FIXTURE_MARKER_WORDS) + ")")
_PATTERN_EVIDENCE_CHARS = frozenset("[]{}\\")
_SEQUENTIAL_RUN_MIN = 8


def _has_pattern_evidence(token: str) -> bool:
    """Regex-pattern syntax (``[]{}\\``) inside ``token`` (#73) — proves the
    token is quoted pattern source, not a live secret. Safe unconditionally: the
    weak-path tokenizer charset never yields these characters in a real token."""
    return any(ch in _PATTERN_EVIDENCE_CHARS for ch in token)


def _char_rank(ch: str) -> int | None:
    """Ordinal of ``ch`` on the fixture-filler ladder, or ``None`` if off-ladder.

    Digits and lowercase form ONE continuous ladder (``0``..``9`` -> ``a``..``z``,
    so ``9``->``a`` counts as +1) since fixtures pad with ``0123456789abcdef``;
    uppercase is a separate ladder (``z``->``A`` is not a run).
    """
    if ch.isdigit():
        return ord(ch) - ord("0")  # 0..9
    if "a" <= ch <= "z":
        return 10 + ord(ch) - ord("a")  # 10..35  (contiguous with digits)
    if "A" <= ch <= "Z":
        return 40 + ord(ch) - ord("A")  # 40..65  (separate ladder)
    return None


def _strip_sequential_runs(token: str, min_len: int = _SEQUENTIAL_RUN_MIN) -> str:
    """Remove every maximal ascending alphanumeric run (each char one rank above
    the last, e.g. ``0123456789``, ``abcdefgh``) of length >= ``min_len`` (#73).

    Ordered filler is what hand-written fixtures pad with; a random secret does
    not contain long ascending runs, so stripping cannot meaningfully shrink a
    real secret (and an attacker can only *append* filler, never remove the real
    high-entropy body that survives this).
    """
    out: list[str] = []
    run: list[str] = []
    prev: int | None = None
    for ch in token:
        rank = _char_rank(ch)
        if run and rank is not None and prev is not None and rank - prev == 1:
            run.append(ch)
        else:
            out.append("" if len(run) >= min_len else "".join(run))
            run = [ch]
        prev = rank
    out.append("" if len(run) >= min_len else "".join(run))
    return "".join(out)


def _is_benign_fixture_token(token: str) -> bool:
    """Bare-token suppression (#73): ``token`` is regex-pattern source text or an
    obvious hand-written fixture, not a real secret.

    Scope: wired only into the WEAK/high-entropy path below
    (``_token_looks_like_weak_secret``, on the *value* after any ``=`` split) —
    which can only ever step up to AUTH, never drive a BLOCK. It is deliberately
    NOT wired into ``_matches_credential_pattern`` (the STRONG path that can
    drive ``secret_exfiltration``): raise-only forbids weakening a BLOCK-driving
    check, and the ``NEW_CREDENTIALS`` recall suite in ``test_rule_secrets.py``
    (EXAMPLE/digit-marked synthetic credentials sent externally must BLOCK) pins
    that. Marker/ordered-filler suppression is gated on the *residual* being
    non-secret-shaped so a real key padded with a marker (an attacker dodge, and
    the only control for a shapeless secret) still fires.
    """
    if _has_pattern_evidence(token):
        return True
    residual = _strip_sequential_runs(_FIXTURE_MARKER_ANYWHERE.sub("", token))
    if residual == token:
        return False  # no marker word and no ordered run — nothing benign here
    return not _looks_high_entropy_secret(residual)


# A run of base64/base64url characters long enough to plausibly carry a secret.
# Used by the encoded-exfil decoder (3.6); matching this alone is NOT a secret —
# only a *decode* that yields a secret pattern escalates.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{24,}={0,2}")
# A long run of hex — likewise only escalates if it decodes to a secret.
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{40,}\b")

# Filenames/paths that ARE secret stores regardless of content.
_SECRET_PATH = re.compile(
    r"""(?ix)
    (?:^|/)\.env(?:\.[\w.-]+)?$       # .env, .env.local, .env.production
    | (?:^|[./])env$                  # app.env / prod.env / .env (any .env file)
    | \.pem$                          # certificates / keys
    | \.key$                          # private keys
    | (?:^|/)id_rsa[\w.-]*$           # ssh private keys
    | (?:^|/)id_ed25519[\w.-]*$
    | (?:^|/)\.npmrc$                 # often carries auth tokens
    | (?:^|/)credentials$             # aws/gcloud credentials files
    """
)

# Entropy thresholds for the generic high-entropy heuristic. We require BOTH
# length and high Shannon entropy AND a charset that looks like a token to
# reduce false positives.
_ENTROPY_MIN_LEN = 24
_ENTROPY_BITS_PER_CHAR = 3.6  # ~ base64 randomness; below this is likely text
_ENTROPY_TOKEN = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

# A git SHA-1 (40 hex) / SHA-256 (64 hex), content digest, or AST hash is long,
# pure hex, and high-entropy — but it is NOT a credential. These are a common
# false positive in tool output (manifests, lockfiles, git output), and a
# spurious ``sensitive_secret_access`` here also poisons the host-hook taint
# ledger. A token that is *entirely* hex of hash length (>= 40) is excluded from
# the WEAK-entropy verdict path. Scope is deliberately narrow: a real base64
# secret is virtually never all-hex; a hex value carrying a credential KEY name
# is still caught by the strong env-assignment path; and the read-vs-send
# fingerprint path (``_candidate_secret_tokens``) is unchanged, so a hex secret
# that does fire is still fingerprinted.
_HASH_LIKE_HEX = re.compile(r"[0-9a-fA-F]{40,}")

# An identifier or relative path — ``DEFAULT_CHALLENGE_TIMEOUT_S``,
# ``migrations/0002_add_last_login``, ``fix/auth/challenge-deadline-fail-closed``
# — is a run of ordinary words joined by separators. It clears the length floor
# and, because the separators add symbol variety, the entropy floor too, so the
# WEAK path flagged it as a possible secret. Measured in the field at roughly a
# 6:1 false-positive ratio, which is the click-through-fatigue failure mode: it
# trains a human to approve without reading and so devalues every GENUINE prompt.
#
# Relief for this already existed but was conditioned on a LEADING ``/`` (see
# ``_token_looks_like_weak_secret``), which is an arbitrary line — a relative
# path is exactly as non-credential as an absolute one, and a bare identifier
# has no slash at all.
#
# The discriminator is SHAPE, not a threshold: a token is exempt only when it
# decomposes entirely into short, purely-alphabetic or purely-numeric segments.
# A credential does not have that shape. Base64/base64url/hex/JWT segments are
# long and mix letters with digits, so they fail ``_WORD_SEGMENT`` and are still
# judged whole — no secret can be fragmented below the length floor and dropped.
_WORD_SEGMENT = re.compile(r"^(?:[A-Za-z]+|[0-9]+)$")
_SEGMENT_SPLIT = re.compile(r"[/_.\-]")
_MAX_WORD_SEGMENT_LEN = 20

# Bounds for the encoded-exfil decoder: avoid decode bombs / runaway recursion.
# One decode layer only (no recursive base64 peeling), bounded token count/size.
_DECODE_MAX_TOKENS = 64  # at most N candidate tokens decoded per scan
_DECODE_MAX_INPUT = 4096  # don't decode tokens longer than this

# Cap how much text we scan from any single string field.
_SCAN_MAX_CHARS = 100_000


def _shannon_entropy_bits_per_char(token: str) -> float:
    """Shannon entropy (bits/char) of a string; 0 for empty."""
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_high_entropy_secret(token: str) -> bool:
    """Heuristic: a long, token-shaped, high-entropy string (possible secret)."""
    if len(token) < _ENTROPY_MIN_LEN or not _ENTROPY_TOKEN.match(token):
        return False
    return _shannon_entropy_bits_per_char(token) >= _ENTROPY_BITS_PER_CHAR


def _matches_credential_pattern(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CREDENTIAL_PATTERNS)


def _value_looks_secretish(value: str) -> bool:
    """Does an env-assignment *value* plausibly carry a real secret? (#56)

    Rejects the benign value shapes that made the rule over-block — filesystem
    paths, URLs, and obvious placeholders (``your_key_here``, ``changeme``,
    ``${VAR}``, ``<token>``). Everything else is treated as secret-shaped, so a
    real ``API_TOKEN=supersecretvalue123`` (or a hex / base64 value) is still
    caught — this only removes false positives, never weakens real detection.
    """
    if value.startswith(("/", "./", "../", "~/")):  # filesystem path
        return False
    if re.match(r"(?i)^[a-z][a-z0-9+.\-]*://", value):  # URL scheme
        return False
    return not _PLACEHOLDER_VALUE.search(value)


def _strong_secret_in_text(text: str) -> bool:
    """High-confidence secret material: a known credential shape, PEM, or a
    ``.env``-style ``SECRET=value`` assignment whose value is secret-shaped.

    "Strong" evidence is what is allowed to drive a *hard BLOCK* on exfil. It is
    deliberately specific so that a high-entropy-but-benign blob (a base64 asset,
    a lockfile hash) is NOT treated as a blockable secret on its own, and so that a
    secret-named key assigned a placeholder/path/URL value is not flagged (#56).
    """
    if not text:
        return False
    sample = text[:_SCAN_MAX_CHARS]
    if _matches_credential_pattern(sample):
        return True
    return any(_value_looks_secretish(m.group("value")) for m in _ENV_ASSIGNMENT.finditer(sample))


def contains_strong_secret(text: str) -> bool:
    """Public reuse surface (H1 hardening): does ``text`` contain STRONG secret
    evidence — a known credential shape (AWS/OpenAI/Anthropic/GitHub/GitLab/
    Slack/Google/Stripe/SendGrid/npm/JWT/DB-URI/PEM/Azure/GCP/...) or a
    ``KEY=secret-looking-value`` env assignment?

    This is the exact check :func:`SecretLeakageRule.evaluate` uses to justify
    a hard BLOCK on exfiltration — the single, canonical place credential-shape
    knowledge lives. Other modules (e.g. ``doberman.proxy.normalize``'s stopgap
    redactor) call this instead of maintaining a second, weaker pattern set.
    Never raises; a falsy ``text`` is never a secret.
    """
    return bool(text) and _strong_secret_in_text(text)


def _looks_like_identifier_or_path(token: str) -> bool:
    """Is this token a separator-joined run of ordinary words (not a credential)?

    Requires at least two segments and EVERY segment to be short and either
    all-alphabetic or all-numeric. ``a3f5-9c2e-...`` (hex, mixed classes) and a
    base64 blob both fail, so this only ever exempts identifier/path shapes.
    """
    segments = [seg for seg in _SEGMENT_SPLIT.split(token) if seg]
    if len(segments) < 2:
        return False
    return all(len(seg) <= _MAX_WORD_SEGMENT_LEN and _WORD_SEGMENT.match(seg) for seg in segments)


def _token_looks_like_weak_secret(token: str, *, exempt_identifiers: bool = True) -> bool:
    """Judge a single candidate token for the high-entropy heuristic.

    ``/`` is a base64 value char, so an *absolute* filesystem path
    (``/Users/dev/project/src/components/Widget``) otherwise reads as one long
    high-entropy token and trips a spurious AUTH on benign reads. Only a
    path-shaped token (a leading ``/``) is split on ``/`` and judged segment by
    segment — real path components are short, word-like, and low-entropy. Any
    other token, **including a base64 secret that merely contains ``/``**, is
    judged whole, so splitting can never fragment a secret below the length
    floor and silently drop it. This keeps the rule raise-only: it removes a
    false positive without ever weakening detection.

    A token that is entirely hash-shaped hex (a git SHA / content digest) is not
    a credential and is excluded up front (#56) — see ``_HASH_LIKE_HEX``.

    A value that is regex-pattern source text or an obvious hand-written fixture
    (an EXAMPLE/SAMPLE/FAKE/DUMMY marker, or ordered ``0-9``/``a-z`` filler) is
    excluded via ``_is_benign_fixture_token`` — but only AFTER the ``=`` split
    below, so it judges the *value*, never a ``KEY=`` name: a variable merely
    *named* ``DUMMY_...`` must not suppress a real secret on its right-hand side.
    """
    if _HASH_LIKE_HEX.fullmatch(token):
        return False
    if "=" in token.rstrip("="):
        # An assignment-shaped token ("name=value", interior '='; base64 padding is
        # trailing-only) is not a single secret — the name part inflates entropy and
        # over-flags benign config like ``cfg_path=/usr/local/bin`` (#56). Judge the
        # value (after the last '='), so a high-entropy RHS is still caught.
        return _token_looks_like_weak_secret(
            token.rsplit("=", 1)[-1], exempt_identifiers=exempt_identifiers
        )
    if _is_benign_fixture_token(token):
        return False
    if exempt_identifiers and _looks_like_identifier_or_path(token):
        return False
    if token.startswith("/"):
        return any(_looks_high_entropy_secret(segment) for segment in token.split("/"))
    return _looks_high_entropy_secret(token)


def _weak_secret_in_text(text: str, *, exempt_identifiers: bool = True) -> bool:
    """Low-confidence signal: a long, token-shaped, high-entropy string.

    "Weak" evidence can step up to AUTH but NEVER drives a BLOCK by itself — a
    base64-encoded image is high-entropy too. (Encoded carriers that *decode* to
    strong secrets are handled separately by the decoder and DO count as strong.)
    """
    if not text:
        return False
    sample = text[:_SCAN_MAX_CHARS]
    for token in re.findall(r"[A-Za-z0-9+/=_\-]{%d,}" % _ENTROPY_MIN_LEN, sample):
        if _token_looks_like_weak_secret(token, exempt_identifiers=exempt_identifiers):
            return True
    return False


def _safe_b64_decode(token: str) -> str | None:
    """Best-effort base64/base64url decode to UTF-8 text; ``None`` on failure.

    Bounded by the caller. Returns text only when it round-trips to something
    that could plausibly contain a secret (printable-ish), so we do not treat
    binary assets (images) as decoded text.
    """
    if len(token) > _DECODE_MAX_INPUT:
        return None
    candidate = token
    # base64url -> base64, then pad to a multiple of 4.
    candidate = candidate.replace("-", "+").replace("_", "/")
    padding = (-len(candidate)) % 4
    candidate = candidate + ("=" * padding)
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary (e.g. an image): not decodable text — do NOT treat as a secret
        # carrier on the basis of encoding alone.
        return None
    # Require mostly-printable content; otherwise it is not a text secret.
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if not text or printable / len(text) < 0.9:
        return None
    return text


def _safe_hex_decode(token: str) -> str | None:
    if len(token) > _DECODE_MAX_INPUT or len(token) % 2:
        return None
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if not text or printable / len(text) < 0.9:
        return None
    return text


def _decoded_carries_strong_secret(text: str) -> bool:
    """Slice 3.6: decode suspicious base64/hex tokens and re-scan for STRONG
    secrets (credential shapes / PEM / env-assignments).

    Bounded (token count, size, single decode layer) — no decode bomb. Escalates
    only when a *decoded* payload contains strong secret material; encoding alone
    never triggers this, so a legitimate base64 asset that decodes to random
    bytes is not treated as a secret carrier.
    """
    sample = text[:_SCAN_MAX_CHARS]
    decoded_count = 0
    for token in _B64_TOKEN.findall(sample):
        if decoded_count >= _DECODE_MAX_TOKENS:
            break
        decoded_count += 1
        decoded = _safe_b64_decode(token)
        if decoded and _strong_secret_in_text(decoded):
            return True
    for token in _HEX_TOKEN.findall(sample):
        if decoded_count >= _DECODE_MAX_TOKENS:
            break
        decoded_count += 1
        decoded = _safe_hex_decode(token)
        if decoded and _strong_secret_in_text(decoded):
            return True
    return False


def _iter_strings(value: object, depth: int = 0) -> Iterator[str]:
    """Yield every string reachable inside a nested argument structure (bounded)."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, val in value.items():
            if isinstance(key, str):
                yield key
            yield from _iter_strings(val, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item, depth + 1)


def _scan_strings(action: SecurityObject, ctx: EvalContext) -> list[str]:
    """Collect the plaintext strings this rule should inspect.

    Pulls from the **un-redacted** ``ctx.metadata["raw_arguments"]`` (in-memory
    only, never logged) so the rule can see content the redacted SecurityObject
    deliberately hides; falls back to the object's own non-secret string fields
    (target, query params, filename) so the rule still functions if raw args are
    absent. Also surfaces URL query parameters and the target's filename for the
    encoded-exfil checks (3.6).
    """
    strings: list[str] = []
    raw_arguments = ctx.metadata.get("raw_arguments") if isinstance(ctx.metadata, dict) else None
    if isinstance(raw_arguments, dict):
        strings.extend(_iter_strings(raw_arguments))

    for field in (action.target, action.external_destination):
        if field:
            strings.append(field)
            # Query-parameter smuggling: scan param values individually.
            try:
                query = urlsplit(field).query
            except ValueError:
                query = ""
            if query:
                strings.extend(val for _, val in parse_qsl(query, keep_blank_values=False))
    return strings


def _path_is_secret_store(path: str | None) -> bool:
    return bool(path) and bool(_SECRET_PATH.search(path))


def _has_external_destination(action: SecurityObject) -> bool:
    """Is this action sending data OUT to a (named) external destination?"""
    if action.external_destination:
        return True
    return action.action_type in (ActionType.network_request, ActionType.git_op)


def _strong_secret_present(strings: Iterable[str]) -> bool:
    """Any STRONG secret evidence (drives BLOCK on exfil): a known credential
    shape / PEM / env-assignment, raw or base64/hex-encoded."""
    for text in strings:
        if _strong_secret_in_text(text) or _decoded_carries_strong_secret(text):
            return True
    return False


def _weak_secret_present(strings: Iterable[str], *, exempt_identifiers: bool = True) -> bool:
    """Any WEAK secret signal (AUTH only, never BLOCK): a high-entropy token.

    ``exempt_identifiers`` MUST be ``False`` for an action that sends data out.
    The identifier/path exemption exists to stop ordinary shell and file work
    from prompting; on an egress path the same shape is a plausible payload
    (a hyphen- or underscore-joined passphrase or recovery phrase), and
    ``ExternalDestinationRule`` explicitly delegates that case here — in
    balanced mode it PASSes a merely-unknown host precisely because "a secret
    leaving to any host is still a hard block via the secrets rule". Exempting
    identifiers on egress would leave BOTH rules covering nothing.
    """
    return any(
        _weak_secret_in_text(text, exempt_identifiers=exempt_identifiers) for text in strings
    )


#: Cap on how many detected secret tokens we fingerprint per action.
_MAX_FINGERPRINTS = 16


def _detected_secret_tokens(strings: Iterable[str]) -> list[str]:
    """Return the raw substrings that matched a STRONG credential pattern.

    Used ONLY to compute fingerprints — the substrings never leave this module
    and never enter a result/explanation. Bounded so a giant payload cannot
    produce unbounded work.
    """
    tokens: list[str] = []
    for text in strings:
        if len(tokens) >= _MAX_FINGERPRINTS:
            break
        sample = text[:_SCAN_MAX_CHARS]
        for pattern in _CREDENTIAL_PATTERNS:
            for match in pattern.finditer(sample):
                tokens.append(match.group(0))
                if len(tokens) >= _MAX_FINGERPRINTS:
                    break
            if len(tokens) >= _MAX_FINGERPRINTS:
                break
    return tokens


def _fingerprint_detected(strings: Iterable[str]) -> list[str]:
    """Fingerprint detected secret tokens (HMAC, keyed) — never the plaintext.

    "Recognize a secret without storing it": the return value is a list of
    ``hmac:<hex>`` strings safe to log/correlate. Fingerprinting failures (e.g.
    the local key cannot be created) are swallowed here — they must not change
    the verdict (the detection already happened); the engine's fail-closed bias
    is unaffected because the rule's verdict does not depend on fingerprints.
    """
    fingerprints: list[str] = []
    for token in _detected_secret_tokens(strings):
        try:
            fingerprints.append(fingerprint(token))
        except Exception:  # noqa: BLE001 — fingerprinting must not alter a verdict
            logger.warning("secret fingerprinting failed; continuing without a fingerprint")
    return fingerprints


def _candidate_secret_tokens(strings: Iterable[str]) -> list[str]:
    """Secret-candidate substrings to fingerprint for the read-vs-send exfil store
    (HK.5.2b): every STRONG credential match plus any high-entropy token — the same
    token shapes the rule treats as secret-bearing. Bounded by ``_MAX_FINGERPRINTS``
    so a giant payload cannot produce unbounded work.

    Pure hash-shaped hex (git SHA / content digest, ``_HASH_LIKE_HEX``) is excluded
    here too (#56), consistently with the detection path: a hash is not a secret, so
    fingerprinting one as a candidate would let a benign hash later trip a false
    ``confirmed_exfil`` match. No recall cost — a bare hash never reaches this path
    alone (fingerprinting only runs once a real secret reason code has fired).
    """
    string_list = list(strings)
    tokens: list[str] = list(_detected_secret_tokens(string_list))
    for text in string_list:
        if len(tokens) >= _MAX_FINGERPRINTS:
            break
        sample = text[:_SCAN_MAX_CHARS]
        for token in re.findall(r"[A-Za-z0-9+/=_\-]{%d,}" % _ENTROPY_MIN_LEN, sample):
            if _HASH_LIKE_HEX.fullmatch(token):
                continue
            if _looks_high_entropy_secret(token):
                tokens.append(token)
                if len(tokens) >= _MAX_FINGERPRINTS:
                    break
    return tokens


def candidate_secret_fingerprints(text: str) -> set[str]:
    """Keyed-HMAC fingerprints of the secret-candidate tokens in ``text``.

    The read-vs-send exfil store (HK.5.2b) records these when a secret enters a
    session's context and matches them on a later egress: an outbound token whose
    fingerprint was recorded earlier is the SAME secret leaving (a confirmed
    exfil). The plaintext never leaves this module; the return is a set of
    ``hmac:<hex>`` strings. Best-effort — a fingerprinting failure drops that
    token (it must never alter a verdict).
    """
    if not text:
        return set()
    texts = [text]
    # Exfil often hides the value in a URL query parameter (``?k=<secret>``); scan
    # those values individually too, so a secret read as a bare token still matches
    # when it later leaves embedded in a query string.
    try:
        query = urlsplit(text).query
    except ValueError:
        query = ""
    if query:
        texts.extend(val for _, val in parse_qsl(query, keep_blank_values=False))
    out: set[str] = set()
    for token in _candidate_secret_tokens(texts):
        try:
            out.add(fingerprint(token))
        except Exception:  # noqa: BLE001,S112 — fingerprinting must not alter a verdict
            continue
    return out


class SecretLeakageRule:
    """Detect secret material and block clear exfiltration of it.

    Pure ``Guardrail``: reads the action + context, returns a verdict. Never
    mutates the action; never emits secret material. Uses two confidence tiers:
    only *strong* evidence (credential shapes / PEM / env-assignments, raw or
    encoded) can drive a hard BLOCK; a merely high-entropy blob steps up to AUTH.

    Detected strong secrets are turned into keyed HMAC fingerprints (logged at
    debug, fingerprints only) so the same secret can be recognized later without
    the plaintext ever being stored — the verdict never depends on them.
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        strings = _scan_strings(action, ctx)
        strong = _strong_secret_present(strings)
        secret_path = _path_is_secret_store(action.target)
        going_external = _has_external_destination(action)

        # Recognize-without-storing: fingerprint any strong tokens (safe to log).
        if strong:
            prints = _fingerprint_detected(strings)
            if prints:
                logger.debug(
                    "secret material detected (action %s): %d fingerprint(s) %s",
                    action.id,
                    len(prints),
                    prints,
                )

        # 1) Clear exfiltration: STRONG secret content (or a secret file) leaving
        #    to an external destination → BLOCK. The one place we hard-block.
        if going_external and (strong or secret_path):
            return GuardrailResult(
                verdict=Verdict.BLOCK,
                risk=Risk.critical,
                reason_codes=[ReasonCode.secret_exfiltration],
                explanation=(
                    "Action appears to send credential-like material to an "
                    "external destination; blocked to prevent secret exfiltration."
                ),
            )

        # 2) STRONG secret material (a known credential shape) or a secret file
        #    touched, staying local → AUTH. High-confidence: in the host-hook
        #    output scan this hard-blocks the tool output.
        if strong or secret_path:
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.sensitive_secret_access],
                explanation=(
                    "Action touches credential-like material; "
                    "authentication required before proceeding."
                ),
            )

        # 3) Only WEAK/high-entropy evidence (no known credential shape, no secret
        #    file): still step up to AUTH, but under a distinct, lower-confidence
        #    code. The high-entropy heuristic false-positives on hashes / UUIDs /
        #    base64 fragments, so the host-hook output scan treats this code as
        #    pass-through (still recorded + tainted), never a hard block of a read.
        #    The engine step-up (proxy / pre-hook egress) is unchanged.
        if _weak_secret_present(strings, exempt_identifiers=not going_external):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.possible_high_entropy_secret],
                explanation=(
                    "Action touches a high-entropy token that may be a secret; "
                    "authentication required before proceeding."
                ),
            )

        # 4) Nothing secret-shaped detected — this rule abstains (PASS/low).
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
