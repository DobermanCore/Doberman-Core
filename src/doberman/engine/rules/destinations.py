"""External-destination rule (Feature 3, slice 3.5).

Steps up authentication when an action sends data to a destination Doberman
does not recognize as trusted. On its own an unknown destination is ``AUTH``;
combined with secret material (the secrets rule) the engine's raise-only
``combine`` turns the pair into a ``BLOCK`` — that is how "upload the repo to an
unknown endpoint" becomes a hard block without this rule needing to know about
secrets.

Host classification is treated as adversarial. We extract the host from a
properly parsed URL (never substring-match the raw string) and:

* decode IDNA/punycode so ``xn--80ak6aa92e.com`` is compared as its unicode
  form and a homoglyph domain is **not** mistaken for a trusted one;
* reject ``user:pass@host`` credential-in-URL forms — the embedded-credential
  is itself a signal, and the real host is taken from after the ``@``;
* treat bare IP literals (and ``[::1]``) as **unknown** (never trusted) — a
  trusted *name* cannot be impersonated by an IP;
* match on the **registered domain** (host == trusted, or a dotted subdomain of
  it), so ``evil-github.com`` and ``github.com.evil.test`` are *not* trusted.

SECURITY: the explanation names only the classification, never the raw URL,
query parameters, or any embedded credential.
"""

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from doberman.models import (
    ActionType,
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

#: Destinations Doberman ships trusting. Overridable (F6 loads from policy).
#: Registered domains only — subdomains are matched structurally.
TRUSTED_HOSTS: tuple[str, ...] = (
    "registry.npmjs.org",
    "npmjs.org",
    "npmjs.com",
    "pypi.org",
    "files.pythonhosted.org",
    "pythonhosted.org",
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "objects.githubusercontent.com",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    "go.dev",
    "proxy.golang.org",
    "sum.golang.org",
)


def _decode_host(host: str) -> str:
    """Lower-case and IDNA-decode a host (punycode → unicode) for comparison.

    Decoding means a homoglyph/punycode domain is compared as the unicode it
    actually resolves to, so it cannot masquerade as an ASCII trusted host.
    Falls back to the raw lower-cased host if decoding fails.
    """
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned:
        return ""
    try:
        # encode('ascii') ensures any non-ASCII (already-unicode homoglyph) is
        # surfaced rather than silently equal to ASCII; then decode punycode.
        return cleaned.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return cleaned


def _is_ip_literal(host: str) -> bool:
    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _registered_match(host: str, trusted: Iterable[str]) -> bool:
    """True if ``host`` equals a trusted domain or is a dotted subdomain of one."""
    if not host:
        return False
    for domain in trusted:
        d = domain.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def _extract_destination(action: SecurityObject) -> str | None:
    """The destination this rule classifies. Only network requests are stepped
    up here. Domain tools (send_email/…) also carry external_destination so the
    trifecta + secret-exfil floors can see the recipient, but their unknown
    recipients are deliberately NOT auto-AUTH'd by this rule (alert fatigue);
    serious domain exfil is caught by those floors instead (ADR 0021)."""
    if action.action_type is not ActionType.network_request:
        return None
    return action.external_destination or action.target


def _parse_host(destination: str) -> tuple[str | None, bool]:
    """Return ``(decoded_host, had_embedded_credentials)`` from a destination.

    Handles bare ``host``/``host:port`` (no scheme) as well as full URLs. The
    host is taken from the authority *after* any ``user:pass@`` so a credential
    prefix cannot disguise the true host.
    """
    raw = destination.strip()
    # Give urlsplit a scheme to parse bare hosts consistently.
    candidate = raw if "://" in raw else f"//{raw}"
    try:
        parts = urlsplit(candidate if "://" in raw else f"http:{candidate}")
    except ValueError:
        return None, False
    had_credentials = "@" in (parts.netloc or "") and bool(parts.username or parts.password)
    host = parts.hostname  # already strips credentials and brackets for IPv6
    if not host:
        return None, had_credentials
    if _is_ip_literal(host):
        # Keep IP literals as-is (never IDNA-decoded); they are always unknown.
        return host.lower(), had_credentials
    return _decode_host(host), had_credentials


class ExternalDestinationRule:
    """Classify network destinations as trusted (PASS) or unknown (AUTH)."""

    def __init__(self, trusted_hosts: Iterable[str] = TRUSTED_HOSTS) -> None:
        self._trusted = tuple(h.lower() for h in trusted_hosts)

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        destination = _extract_destination(action)
        if not destination:
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        host, had_credentials = _parse_host(destination)

        # A malformed/absent host on a network action is suspicious → AUTH.
        if host is None:
            return self._auth_unknown(
                "Network destination could not be resolved to a known host; "
                "authentication required."
            )

        # Embedded credentials in the URL are a smell on their own → AUTH even
        # if the host turns out to be trusted (the credential should not be there).
        if had_credentials:
            return self._auth_unknown(
                "Destination URL embeds credentials in the authority; authentication required."
            )

        # IP literals are never trusted by name.
        if _is_ip_literal(host):
            return self._auth_unknown(
                "Network destination is a raw IP address (not a trusted host); "
                "authentication required."
            )

        if _registered_match(host, self._trusted):
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        return self._auth_unknown(
            "Network destination is not on the trusted list; authentication required."
        )

    def _auth_unknown(self, explanation: str) -> GuardrailResult:
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.unknown_external_destination],
            explanation=explanation,
        )
