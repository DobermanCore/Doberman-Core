"""Slice TG2.1 + TG2.2 — Tier 0 turn signatures (deterministic, BLOCK-capable).

The only hard-stop in the turn gate, and small by design. Four signature
families, each with a stable reason code:

* ``instruction_nullification`` — "ignore/disregard your previous instructions".
* ``authority_override`` — authority impersonation, mode-switch framing, and
  policy-prompt exfiltration ("print your system prompt").
* ``secret_export`` — credential/key/token export asks.
* ``encoded_payload`` — long high-entropy base64/hex carriers and punycode hosts.

**The issue-vs-mention discriminator** is the precision core. A text-family match
is classified *issued* (an imperative directed at the agent) or *mentioned*
(quoted / discussed). The **origin rule** then decides:

* match in an untrusted (pasted / tool-fetched) segment → **BLOCK** unconditionally
  (indirect injection is essentially never benign) — quotes/fences never exempt it;
* match **typed** and *issued* → **BLOCK**;
* match **typed** and *mentioned* → **AUTH** (the researcher / meta-discussion path).

Ambiguous issue/mention → treated as issued. A typed *encoded carrier* steps up
to AUTH rather than blocking (a user pasting base64 is plausibly legitimate);
an encoded carrier in an untrusted segment blocks.

SECURITY: the scan runs over the **in-memory** raw turn text (never persisted),
and every explanation names only the *pattern class*, never the matched text.
"""

import math
import re

from doberman.engine.decision_engine import combine
from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SegmentOrigin,
    TurnObject,
    Verdict,
)
from doberman.turngate.raw import RawSegment, raw_turn_from_ctx

#: Cap on how much of any one segment is scanned (a hostile paste cannot make the
#: regex pass run unbounded; an untrusted segment blocks on its first hit anyway).
_MAX_SCAN_CHARS = 200_000

#: Min length + entropy for a base64/hex run to count as an encoded carrier.
_CARRIER_MIN_LEN = 40
_CARRIER_MIN_ENTROPY = 3.6

_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % _CARRIER_MIN_LEN)
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{%d,}\b" % _CARRIER_MIN_LEN)
_PUNYCODE = re.compile(r"\bxn--[a-z0-9-]+", re.IGNORECASE)


# --- text-family signature patterns ---------------------------------------

_INSTRUCTION_NULLIFICATION: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(ignore|disregard|forget|override|do not follow|don'?t follow)\b[^.?!]{0,40}"
        r"\b(previous|prior|earlier|above|all|your|the|system)\b[^.?!]{0,25}"
        r"\b(instruction|instructions|rule|rules|prompt|prompts|directive|directives)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(previous|prior|earlier|your|the above)\b[^.?!]{0,30}"
        r"\b(instruction|instructions|rule|rules)\b[^.?!]{0,25}"
        r"\b(no longer apply|don'?t apply|do not apply|are void|are cancell?ed|are revoked)\b",
        re.IGNORECASE,
    ),
)

_AUTHORITY_OVERRIDE: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bi am (your |the )?(administrator|admin|developer|owner|creator|root|supervisor)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(this|the following|my)\b[^.?!]{0,25}\b(supersedes?|overrides?|replaces?)\b[^.?!]{0,25}"
        r"\b(system prompt|instructions|rules|policy|guidelines)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\belevated (permissions|privileges|access|rights)\b", re.IGNORECASE),
    re.compile(
        r"\b(developer|debug|unrestricted|god|jailbreak|sudo|dan)[ -]?mode\b", re.IGNORECASE
    ),
    re.compile(
        r"\bact as (an? )?(ai|assistant|model|chatbot)\b[^.?!]{0,30}"
        r"\b(without|with no|free of|free from|ignoring)\b[^.?!]{0,15}"
        r"\b(restrictions?|rules?|limits?|guidelines?|filters?|guardrails?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(print|repeat|reveal|show|recite|output|display|tell me|give me)\b[^.?!]{0,30}"
        r"\b(system prompt|your instructions|your rules|your prompt|initial instructions|"
        r"the prompt above)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(disable|turn off|bypass|remove|ignore)\b[^.?!]{0,20}"
        r"\b(safety|security|guard|guardrails?|filters?|restrictions?|content policy)\b",
        re.IGNORECASE,
    ),
)

_SECRET_EXPORT: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(send|email|e-mail|post|upload|exfiltrate|print|show|reveal|give me|tell me|output|"
        r"paste|share|leak|export|transmit|curl|fetch|dump)\b[^.?!]{0,40}"
        r"\b(api[ _-]?key|api[ _-]?keys|secret|secret key|access key|token|tokens|password|passwd|"
        r"credential|credentials|private key|ssh key|\.env|env file|aws[ _-]?key)\b",
        re.IGNORECASE,
    ),
)

_TEXT_FAMILIES: tuple[tuple[ReasonCode, str, tuple[re.Pattern[str], ...]], ...] = (
    (
        ReasonCode.instruction_nullification,
        "instruction-nullification pattern",
        _INSTRUCTION_NULLIFICATION,
    ),
    (ReasonCode.authority_override, "authority-override pattern", _AUTHORITY_OVERRIDE),
    (ReasonCode.secret_export, "credential-export pattern", _SECRET_EXPORT),
)

#: Words that mark a match as *discussed* rather than *issued* (typed only).
_META_MARKERS: tuple[str, ...] = (
    "detect",
    "example",
    "such as",
    "e.g",
    "i.e",
    "phrase",
    "pattern",
    "signature",
    "says",
    "said",
    "saying",
    "what does",
    "what is",
    "how do",
    "how to",
    "how should",
    "is it safe",
    "should i",
    "would you",
    "respond to",
    "handle a",
    "handles",
    "check for",
    "test that",
    "test for",
    "rule that",
    "a prompt that",
    "prompts that",
    "mention",
    "quote",
)

_PASS = GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)


def _shannon_entropy(token: str) -> float:
    """Shannon entropy in bits/char (0 for empty) — a base64 asset is ~6, text ~4."""
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_quoted(text: str, start: int) -> bool:
    """Whether the match at ``start`` sits inside a double-quote or inline-backtick
    span. Triple-backtick *fences* are explicitly NOT treated as quotes — an
    attacker wrapping an injection in a fence must not thereby exempt it."""
    before = text[:start]
    if before.count('"') % 2 == 1:
        return True
    before_no_fences = before.replace("```", "")
    return before_no_fences.count("`") % 2 == 1


def _has_meta_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _META_MARKERS)


def _is_mentioned(text: str, start: int) -> bool:
    """Issue-vs-mention: a quoted match or a segment in meta-discussion is
    *mentioned*; otherwise *issued* (ambiguous → issued, the safe bias)."""
    return _is_quoted(text, start) or _has_meta_marker(text)


def _text_hits(text: str) -> list[tuple[ReasonCode, str, bool]]:
    """Return (reason, label, mentioned) for each text-family signature that fires."""
    scan = text[:_MAX_SCAN_CHARS]
    hits: list[tuple[ReasonCode, str, bool]] = []
    for reason, label, patterns in _TEXT_FAMILIES:
        for pattern in patterns:
            match = pattern.search(scan)
            if match is not None:
                hits.append((reason, label, _is_mentioned(scan, match.start())))
                break  # one hit per family is enough
    return hits


def _has_encoded_carrier(text: str) -> bool:
    scan = text[:_MAX_SCAN_CHARS]
    if _PUNYCODE.search(scan):
        return True
    for token_re in (_B64_TOKEN, _HEX_TOKEN):
        for token in token_re.findall(scan):
            if len(token) >= _CARRIER_MIN_LEN and _shannon_entropy(token) >= _CARRIER_MIN_ENTROPY:
                return True
    return False


def _block(reason: ReasonCode, label: str, *, untrusted: bool) -> GuardrailResult:
    reasons = [reason]
    detail = label
    if untrusted:
        reasons.append(ReasonCode.indirect_injection)
        detail = f"{label} in untrusted (pasted/tool-fetched) content"
    return GuardrailResult(
        verdict=Verdict.BLOCK,
        risk=Risk.high,
        reason_codes=reasons,
        explanation=f"Turn blocked: {detail} (Tier 0 signature).",
    )


def _auth(reason: ReasonCode, label: str) -> GuardrailResult:
    return GuardrailResult(
        verdict=Verdict.AUTH,
        risk=Risk.medium,
        reason_codes=[reason],
        explanation=f"Turn flagged: {label} — approve this turn before it reaches the model?",
    )


def _verdict_for_text_hit(
    reason: ReasonCode, label: str, mentioned: bool, origin: SegmentOrigin
) -> GuardrailResult:
    if origin.is_untrusted:
        return _block(reason, label, untrusted=True)
    if mentioned:
        return _auth(reason, label)
    return _block(reason, label, untrusted=False)


def _scan_segment(segment: RawSegment) -> GuardrailResult:
    worst = _PASS
    for reason, label, mentioned in _text_hits(segment.text):
        worst = combine(worst, _verdict_for_text_hit(reason, label, mentioned, segment.origin))
    if _has_encoded_carrier(segment.text):
        label = "encoded-payload carrier"
        if segment.origin.is_untrusted:
            carrier = _block(ReasonCode.encoded_payload, label, untrusted=True)
        else:
            carrier = _auth(ReasonCode.encoded_payload, label)
        worst = combine(worst, carrier)
    return worst


class Tier0SignatureGuardrail:
    """The deterministic, BLOCK-capable Tier 0 turn guardrail.

    Scans each origin-tagged raw segment and reduces the results raise-only.
    Abstains (PASS) when the context carries no in-memory raw turn (the
    redacted-only path) — it never guesses without text to match.
    """

    def evaluate(self, turn: TurnObject, ctx: EvalContext) -> GuardrailResult:
        raw = raw_turn_from_ctx(ctx)
        if raw is None:
            return _PASS
        worst = _PASS
        for segment in raw.segments:
            worst = combine(worst, _scan_segment(segment))
            if worst.verdict is Verdict.BLOCK:
                break  # cannot get worse than a hard block
        return worst
