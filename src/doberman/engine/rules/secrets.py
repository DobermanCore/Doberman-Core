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
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-style secret key
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub classic/app tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),  # GitHub fine-grained PAT
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    # Slack incoming-webhook URL (carries send capability)
    re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),  # Google API key
    re.compile(r"(?:sk|rk)_live_[A-Za-z0-9]{20,}"),  # Stripe live secret/restricted key
    re.compile(r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),  # SendGrid API key
    re.compile(r"npm_[A-Za-z0-9]{36}"),  # npm access token
    # JWT: two base64url JSON segments (header/payload start with eyJ) + signature
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # DB / message-queue connection URI with embedded user:password credentials
    re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]+@"),
    re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----"),  # PEM private key
)

# ``.env``-style assignment of a secret-looking key to a non-trivial value.
# Case-SENSITIVE (#56): real ``.env`` secrets are UPPER_SNAKE (``API_KEY=``), so a
# lowercase ``configure_token_path=…`` in prose/config no longer matches the keyword.
_ENV_ASSIGNMENT = re.compile(
    r"(?m)^\s*(?:export\s+)?"
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


def _token_looks_like_weak_secret(token: str) -> bool:
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
    """
    if _HASH_LIKE_HEX.fullmatch(token):
        return False
    if "=" in token.rstrip("="):
        # An assignment-shaped token ("name=value", interior '='; base64 padding is
        # trailing-only) is not a single secret — the name part inflates entropy and
        # over-flags benign config like ``cfg_path=/usr/local/bin`` (#56). Judge the
        # value (after the last '='), so a high-entropy RHS is still caught.
        return _token_looks_like_weak_secret(token.rsplit("=", 1)[-1])
    if token.startswith("/"):
        return any(_looks_high_entropy_secret(segment) for segment in token.split("/"))
    return _looks_high_entropy_secret(token)


def _weak_secret_in_text(text: str) -> bool:
    """Low-confidence signal: a long, token-shaped, high-entropy string.

    "Weak" evidence can step up to AUTH but NEVER drives a BLOCK by itself — a
    base64-encoded image is high-entropy too. (Encoded carriers that *decode* to
    strong secrets are handled separately by the decoder and DO count as strong.)
    """
    if not text:
        return False
    sample = text[:_SCAN_MAX_CHARS]
    for token in re.findall(r"[A-Za-z0-9+/=_\-]{%d,}" % _ENTROPY_MIN_LEN, sample):
        if _token_looks_like_weak_secret(token):
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


def _weak_secret_present(strings: Iterable[str]) -> bool:
    """Any WEAK secret signal (AUTH only, never BLOCK): a high-entropy token."""
    return any(_weak_secret_in_text(text) for text in strings)


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

        # 2) Secret material present but staying local, OR only weak/high-entropy
        #    evidence, OR a secret file touched: step up to AUTH — never PASS.
        if strong or secret_path or _weak_secret_present(strings):
            return GuardrailResult(
                verdict=Verdict.AUTH,
                risk=Risk.high,
                reason_codes=[ReasonCode.sensitive_secret_access],
                explanation=(
                    "Action touches credential-like material; "
                    "authentication required before proceeding."
                ),
            )

        # 3) Nothing secret-shaped detected — this rule abstains (PASS/low).
        return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)
