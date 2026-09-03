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
#: slow/unbounded match.
_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]{1,2048}", re.IGNORECASE)

#: A bare, dot-shaped hostname (no scheme) — evil.com, www.evil.com. Requires an
#: alpha-only 2-24 char final label so it doesn't match IP-only strings or
#: version tags (py311).
_BARE_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}[a-z]{2,24}\b", re.IGNORECASE
)

#: An RFC-shaped email address, bounded.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")

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
    """Lowercase, strip a trailing dot, strip a leading ``www.``."""
    cleaned = host.strip().rstrip(".").lower()
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned


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
    """
    if not text:
        return set()
    sample = text[:_SCAN_MAX_CHARS]
    excluded = excluded_hosts or ()

    values: set[str] = set()

    for match in _URL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        try:
            parts = urlsplit(match.group(0))
        except ValueError:
            continue
        host = _normalize_host(parts.hostname or "")
        if not host or host in excluded:
            continue
        values.add(host)
        # Whole-URL value (scheme + host + path, query stripped) — an exact
        # fetch-URL reuse, not just the host.
        values.add(f"{parts.scheme.lower()}://{host}{parts.path}")

    for match in _BARE_HOST_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        host = _normalize_host(match.group(0))
        if host and _looks_like_host(host) and host not in excluded:
            values.add(host)

    for match in _EMAIL_RE.finditer(sample):
        if len(values) >= _MAX_VALUES:
            break
        values.add(match.group(0).lower())

    out: set[str] = set()
    for value in list(values)[:_MAX_VALUES]:
        try:
            out.add(fingerprint(value))
        except Exception:  # noqa: BLE001,S112 — fingerprinting must not alter a verdict
            continue
    return out
