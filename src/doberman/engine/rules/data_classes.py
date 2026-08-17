"""PII / financial data-class exfil rule (issue #321).

Doberman's outbound-secret defenses target credential-shaped material; this
rule adds the missing sibling class: **structured personal/financial data**
(payment card numbers, IBANs, US SSNs) leaving the workspace. It classifies a
*data class*, never a single-secret fingerprint.

Precision design (the hard part, per the issue):
  - **Co-occurrence gate:** the rule fires only when the action has an
    external destination (:func:`~doberman.engine.rules.secrets._has_external_destination`
    — the same gate the secret rule uses). A card number in a local file
    write is not exfil; presence alone never escalates.
  - **Checksum/format validation, not bare regexes:** PAN = known issuer
    prefix + Luhn; IBAN = mod-97; SSN = dashed form with SSA validity
    constraints. Random digit strings (timestamps, ids, hashes) fail these.
  - AUTH (never BLOCK), all modes: a human may legitimately send payment
    data — the point is that a *human* confirms it. Defense-in-depth: it
    feeds risk, it does not replace the secret/trifecta floors.

Boundary (F3 split): structured-format detection with public checksums is
core-basic. Anything statistical/ML (free-text name+address detection,
context-aware OTP classification) is enterprise, via the ``Detector`` seam.

SECURITY: reason codes + class labels only. The matched value never appears
in any explanation, log field, or output — the explanation names the class
("payment card number"), never the payload.

ponytail: one-time auth codes (6-digit OTPs) are deliberately NOT detected —
even destination-gated, bare 6-digit numbers false-positive far too often
(ports, ids, timestamps); a context-aware OTP classifier is enterprise work.
"""

from __future__ import annotations

import re

from doberman.engine.rules.secrets import _has_external_destination, _scan_strings
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)

_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

# ── payment card (PAN): issuer prefix + Luhn ─────────────────────────────────

# 13-19 digits, optionally space/dash separated, not embedded in a longer
# alphanumeric run (rejects epoch-ns timestamps, hashes, long ids).
_PAN_SHAPE = re.compile(r"(?<![0-9A-Za-z])\d(?:[ -]?\d){12,18}(?![0-9A-Za-z])")


# Major issuer IINs: Visa, Mastercard (51-55, 2221-2720), Amex, Discover.
# ponytail: the big-four cover the realistic exfil surface; extend the table,
# don't loosen the checks, if a real gap shows up.
def _has_known_iin(digits: str) -> bool:
    if digits.startswith("4"):
        return len(digits) in (13, 16, 19)
    two = int(digits[:2])
    if 51 <= two <= 55:
        return len(digits) == 16
    four = int(digits[:4])
    if 2221 <= four <= 2720:
        return len(digits) == 16
    if two in (34, 37):
        return len(digits) == 15
    if digits.startswith("6011") or two == 65:
        return len(digits) == 16
    return False


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _contains_pan(text: str) -> bool:
    for match in _PAN_SHAPE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and _has_known_iin(digits) and _luhn_ok(digits):
            return True
    return False


# ── IBAN: mod-97 ─────────────────────────────────────────────────────────────

_IBAN_SHAPE = re.compile(r"(?<![0-9A-Za-z])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}(?![0-9A-Za-z])")


def _iban_mod97_ok(compact: str) -> bool:
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def _contains_iban(text: str) -> bool:
    for match in _IBAN_SHAPE.finditer(text):
        compact = re.sub(r"[ -]", "", match.group())
        if 15 <= len(compact) <= 34 and _iban_mod97_ok(compact):
            return True
    return False


# ── US SSN: dashed form + SSA validity constraints ───────────────────────────
# ponytail: undashed 9-digit SSNs are indistinguishable from ordinary ids —
# only the dashed form is detected; the ceiling is recorded in issue #321.

_SSN_SHAPE = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")


def _contains_ssn(text: str) -> bool:
    for match in _SSN_SHAPE.finditer(text):
        area, group, serial = match.groups()
        if area in ("000", "666") or area >= "900":
            continue
        if group == "00" or serial == "0000":
            continue
        return True
    return False


_DETECTORS = (
    ("payment card number", _contains_pan),
    ("IBAN", _contains_iban),
    ("US SSN", _contains_ssn),
)


class PiiDataClassRule:
    """AUTH when checksum-valid PII/financial data co-occurs with egress.

    Abstains (``PASS``) without an external destination, without a validated
    match, or on any absent/odd argument shape — the escalation exists only
    for the exfil co-occurrence this rule is scoped to. Raise-only: it
    returns PASS or AUTH, never BLOCK, and never lowers another rule.
    """

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        if not _has_external_destination(action):
            return _PASS
        strings = _scan_strings(action, ctx)
        classes = [label for label, detect in _DETECTORS if any(detect(text) for text in strings)]
        if not classes:
            return _PASS
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.high,
            reason_codes=[ReasonCode.pii_data_class_egress],
            explanation=(
                f"Outbound payload contains {', '.join(classes)} "
                "(personal/financial data class) bound for an external "
                "destination; authentication required."
            ),
        )
