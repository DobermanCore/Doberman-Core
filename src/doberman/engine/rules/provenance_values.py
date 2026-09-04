"""Whole-value keyed-HMAC extraction for the untrusted-value echo tripwire (C1).

Extracts EXACT hostname / full-URL / email VALUES from a block of text — the
untrusted-provenance leg of a later egress match (see
``engine/taint_floor.py``'s ``apply_echo_tripwire_async``). Deliberately
narrow: whole-value matching only, no n-gram shingling, no tokenization of
prose, no package-name or command-verb extraction — this is a tripwire on
exact value reuse, not flow analysis (see README's Known limitations).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from doberman.storage.fingerprint import fingerprint

#: Bound the input before scanning (mirrors engine/rules/secrets.py's
#: _SCAN_MAX_CHARS) — a scanner must never do unbounded work on a giant payload.
_SCAN_MAX_CHARS = 100_000

#: Cap on distinct values fingerprinted per call (v1_scope).
_MAX_VALUES = 200

#: A scheme-explicit URL. Length-bounded so a pathological input cannot force a
#: slow/unbounded match. "]" is deliberately excluded from the character class
#: so a URL wrapped in markdown ("[text](url)") doesn't over-consume the
#: wrapper — which also means this can never match a bracketed-IPv6 URL's own
#: "]"; that shape is handled separately by _IPV6_URL_RE below.
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]{1,2048}", re.IGNORECASE)

#: A scheme-explicit URL whose authority is a bracketed IPv6 literal
#: (``http://[2001:db8::1]/x``). _URL_RE's "]"-exclusion above means it always
#: hands urlsplit() a truncated prefix for this shape (stopping right before
#: the host's own closing bracket), which urlsplit() then rejects as
#: ``ValueError: Invalid IPv6 URL`` — silently dropping the whole match. Final
#: review, MINOR: handled as its own pattern so a bracketed-IPv6 URL and a
#: bare IPv6 mention (see _IP_LITERAL_RE) fingerprint the same host.
_IPV6_URL_RE = re.compile(r"https?://\[[0-9a-fA-F:]+\](?::\d{1,5})?[^\s<>\"'\)\]]*", re.IGNORECASE)

#: A bare, dot-shaped hostname (no scheme) — evil.com, www.evil.com. Requires an
#: alpha-only 2-24 char final label so it doesn't match IP-only strings or
#: version tags (py311).
_BARE_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}\b", re.IGNORECASE
)

#: A bare (schemeless) IPv4 dotted-quad literal. _BARE_HOST_RE above requires
#: an alpha-only final label (a TLD shape), so a bare IP address like
#: "192.0.2.1" mentioned with no scheme is otherwise invisible to it — without
#: this, a bare-IP mention and a later http://192.0.2.1/ egress would not
#: fingerprint as the same value. Shape-matched here; validated for real (not
#: just 4 dotted groups — a version string like "1.2.3.400" is not an IP) via
#: destinations._is_ip_literal before use.
_IP_LITERAL_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

#: An RFC-shaped email address, bounded.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")

#: T4 — common mail-address obfuscation forms, de-obfuscated before a SECOND
#: _EMAIL_RE pass so "user [at] host [dot] com" fingerprints the same as the
#: plain address. Three forms, case-insensitive: (1) bracketed — [at]/(at)/
#: {at}/<at> and the same four pairs around "dot", inner+outer whitespace
#: optional; (2) bare word — "at"/"dot" as a standalone word between two
#: alphanumerics; (3) spaced separator — a literal "@"/"." with whitespace on
#: BOTH sides between two alphanumerics (one-sided, e.g. a sentence-ending
#: "end. Next", is left untouched).
#:
#: Every whitespace quantifier below is bounded to \s{0,4} (or \s{1,4} where
#: at least one space is required) rather than \s*/\s+ — a real obfuscated
#: address never has more than a couple of spaces around "at"/"dot", and an
#: unbounded quantifier flanking a mandatory alternation backtracks
#: quadratically: re.finditer/.sub retries the leading \s* one character
#: shorter at EVERY start position once the alternation fails, so a large run
#: of plain whitespace (attacker-controlled, up to _SCAN_MAX_CHARS) made
#: _deobfuscated() run for tens of seconds on the hot untrusted-read path.
#: Measured: 20,000 spaces took 7.8s pre-fix; bounded, the full 100,000-char
#: bound finishes in milliseconds.
#: Known ceiling: the bound also caps coverage at 4 spaces per gap (8 outside a
#: bracket pair) -- a wider-spaced form is not de-obfuscated; raising the bound
#: stays linear, it only costs a constant. The second pass can also mint
#: prose-derived junk values ("ask Bob at example . com" -> bob@example.com):
#: harmless as matches (HMAC-keyed; at most an extra AUTH on a later send to
#: that exact address) but they count against the taint store's per-scope
#: row budget.
_DEOBFUSCATE_BRACKETED_AT_RE = re.compile(
    r"\s{0,4}(?:\[\s{0,4}at\s{0,4}\]|\(\s{0,4}at\s{0,4}\)|\{\s{0,4}at\s{0,4}\}|<\s{0,4}at\s{0,4}>)\s{0,4}",
    re.IGNORECASE,
)
_DEOBFUSCATE_BRACKETED_DOT_RE = re.compile(
    r"\s{0,4}(?:\[\s{0,4}dot\s{0,4}\]|\(\s{0,4}dot\s{0,4}\)|\{\s{0,4}dot\s{0,4}\}|<\s{0,4}dot\s{0,4}>)\s{0,4}",
    re.IGNORECASE,
)
_DEOBFUSCATE_WORD_AT_RE = re.compile(
    r"(?<=[A-Za-z0-9])\s{1,4}at\s{1,4}(?=[A-Za-z0-9])", re.IGNORECASE
)
_DEOBFUSCATE_WORD_DOT_RE = re.compile(
    r"(?<=[A-Za-z0-9])\s{1,4}dot\s{1,4}(?=[A-Za-z0-9])", re.IGNORECASE
)
_DEOBFUSCATE_SPACED_AT_RE = re.compile(r"(?<=[A-Za-z0-9])\s{1,4}@\s{1,4}(?=[A-Za-z0-9])")
_DEOBFUSCATE_SPACED_DOT_RE = re.compile(r"(?<=[A-Za-z0-9])\s{1,4}\.\s{1,4}(?=[A-Za-z0-9])")


def _deobfuscated(text: str) -> str:
    """Undo the bracketed / bare-word / spaced-separator obfuscation forms
    above, in that order. Plaintext never leaves this module."""
    out = _DEOBFUSCATE_BRACKETED_AT_RE.sub("@", text)
    out = _DEOBFUSCATE_BRACKETED_DOT_RE.sub(".", out)
    out = _DEOBFUSCATE_WORD_AT_RE.sub("@", out)
    out = _DEOBFUSCATE_WORD_DOT_RE.sub(".", out)
    out = _DEOBFUSCATE_SPACED_AT_RE.sub("@", out)
    out = _DEOBFUSCATE_SPACED_DOT_RE.sub(".", out)
    return out


# ponytail: common non-host file extensions the bare-host regex would otherwise
# treat as a "TLD" (README.md, package.json). A fingerprint of a filename is
# low-risk noise (nothing egresses to a destination literally named
# "readme.md"), but filtering the obvious cases keeps the bounded per-scope row
# budget for real hosts. Not exhaustive by design — extend if the row cap fills
# with filename noise in practice.
_NON_TLD_LABELS = frozenset(
    {
        "md",
        "txt",
        "json",
        "yaml",
        "yml",
        "toml",
        "ini",
        "cfg",
        "csv",
        "log",
        "py",
        "js",
        "ts",
        "jsx",
        "tsx",
        "css",
        "html",
        "xml",
        "sql",
        "sh",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "pdf",
        "zip",
        "lock",
        "env",
        "ipynb",
        "gitignore",
        "lockb",
    }
)


def _normalize_host(host: str) -> str:
    """Lowercase, strip a trailing dot, strip a leading ``www.``, then
    IDNA-decode (punycode <-> unicode canonicalization) through the SAME
    decoder :class:`~doberman.engine.rules.destinations.ExternalDestinationRule`
    uses (``destinations._decode_host``) — never a second, drifting decoder.

    Final review, MINOR: without this last step, a punycode-encoded host
    (``xn--caf-dma.example``) and the identical unicode host it decodes to
    (``café.example``) fingerprinted as two UNRELATED values, so a homoglyph/
    punycode-disguised repeat host slipped past the echo tripwire.
    """
    from doberman.engine.rules.destinations import _decode_host

    cleaned = host.strip().rstrip(".").lower()
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return _decode_host(cleaned)


def _looks_like_host(candidate: str) -> bool:
    tld = candidate.rsplit(".", 1)[-1]
    return tld not in _NON_TLD_LABELS


def untrusted_value_fingerprints(
    text: str, *, excluded_hosts: set[str] | frozenset[str] | None = None
) -> set[str]:
    """Keyed-HMAC fingerprints of whole hostname / URL / email VALUES in
    ``text``. Best-effort: a fingerprinting failure drops that value, never
    raises. Bounded input (``_SCAN_MAX_CHARS``) and output (``_MAX_VALUES``).
    The plaintext never leaves this function.

    ``excluded_hosts`` (already-normalized, e.g. via :func:`_normalize_host`)
    drops a URL/bare-host candidate by its HOST *before* fingerprinting — for
    one URL match this drops BOTH the bare-host value and the whole-URL value
    together, since they share the same host. This must happen pre-fingerprint:
    a caller holding only a host allowlist has no way to derive the fingerprint
    of a whole URL it never saw, so subtracting fingerprints *after* the fact
    (as callers used to) can only ever drop the bare-host form.

    Final review, IMPORTANT 1: a candidate's host is excluded by REGISTERED-
    DOMAIN SUFFIX match (host == an excluded host, or a dotted subdomain of
    one) — the SAME semantics
    :func:`~doberman.engine.rules.destinations._registered_match` uses for
    ``TRUSTED_HOSTS``, never a second, drifting definition of "trusted".
    Exact membership would miss e.g. ``api.github.com`` as a subdomain of the
    trusted ``github.com``.
    """
    if not text:
        return set()
    sample = text[:_SCAN_MAX_CHARS]
    excluded = excluded_hosts or ()

    def _is_excluded(host: str) -> bool:
        if not excluded:
            return False
        from doberman.engine.rules.destinations import _registered_match

        return _registered_match(host, excluded)

    values: set[str] = set()

    for match in _URL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        try:
            parts = urlsplit(match.group(0))
        except ValueError:
            continue
        host = _normalize_host(parts.hostname or "")
        if not host or _is_excluded(host):
            continue
        values.add(host)
        # Whole-URL value (scheme + host + path, query stripped) — an exact
        # fetch-URL reuse, not just the host.
        values.add(f"{parts.scheme.lower()}://{host}{parts.path}")

    for match in _IPV6_URL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        try:
            parts = urlsplit(match.group(0))
        except ValueError:
            continue
        host = _normalize_host(parts.hostname or "")
        if not host or _is_excluded(host):
            continue
        values.add(host)
        values.add(f"{parts.scheme.lower()}://[{host}]{parts.path}")

    for match in _BARE_HOST_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        host = _normalize_host(match.group(0))
        if host and _looks_like_host(host) and not _is_excluded(host):
            values.add(host)

    for match in _IP_LITERAL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        from doberman.engine.rules.destinations import _is_ip_literal

        candidate = match.group(0)
        if not _is_ip_literal(candidate):
            continue
        host = _normalize_host(candidate)
        if host and not _is_excluded(host):
            values.add(host)

    for match in _EMAIL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        email = match.group(0).lower()
        domain = email.rsplit("@", 1)[-1]
        if _is_excluded(_normalize_host(domain)):
            continue
        values.add(email)

    # T4: a second _EMAIL_RE pass over a de-obfuscated copy, through the SAME
    # path (same _MAX_VALUES cap, same `values` set — a duplicate of the
    # plain-address loop above collapses for free). Skipped when nothing was
    # obfuscated (deobfuscated == sample).
    deobfuscated = _deobfuscated(sample)
    if deobfuscated != sample:
        for match in _EMAIL_RE.finditer(deobfuscated):
            if len(values) >= _MAX_VALUES:
                break
            email = match.group(0).lower()
            domain = email.rsplit("@", 1)[-1]
            if _is_excluded(_normalize_host(domain)):
                continue
            values.add(email)

    out: set[str] = set()
    for value in list(values)[:_MAX_VALUES]:
        try:
            out.add(fingerprint(value))
        except Exception:  # noqa: BLE001,S112 — fingerprinting must not alter a verdict
            continue
    return out
