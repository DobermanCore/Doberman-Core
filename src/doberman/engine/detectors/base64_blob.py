"""Oversized encoded-blob detection (subjective detector).

Flags a suspiciously large base64-looking payload inside a tool call's
arguments — a common exfiltration shape, where file or secret contents are
smuggled out as one big encoded blob. It runs in the subjective guardrail, so
by construction it can only **raise** risk to ``AUTH`` (the execution rule
clamps a subjective BLOCK to AUTH); it never blocks and never lowers a verdict.

It reasons about **shape and size only** — it never base64-*decodes* the payload
and never inspects, logs, or echoes its contents. A large encoded blob is often
benign (an embedded image, a patch/diff, a minified asset), so the verdict is
``AUTH``, not ``BLOCK``: a false positive costs one confirmation, and the size
threshold is configurable to tune that friction.

Scope: this targets **bulk** encoded payloads (whole file/secret dumps). Small
credentials — an API key or a short token — are below the size threshold by
design and are the objective secrets rule's job, not this detector's.

Defense-in-depth, not airtight (like every rule here): it tolerates PEM/MIME
newline wrapping, but an attacker can still evade it by splitting the payload
across several sub-threshold arguments/calls, interleaving non-alphabet
separators, or using a different encoding. It only ever *raises* to AUTH, so a
miss falls back to the rest of the stack, never to a weakened verdict.

SECURITY / redaction: the matched blob is **never** emitted. The explanation
names the signal class only — never the payload, an offset, or any argument
value.
"""

import logging
import re

from doberman.models import (
    EvalContext,
    GuardrailResult,
    ReasonCode,
    Risk,
    SecurityObject,
    Verdict,
)
from doberman.tokens import SCAN_MAX_CHARS, collect_scan_strings

logger = logging.getLogger("doberman.engine.detectors.base64_blob")

#: Default minimum length (in characters) of a contiguous base64-looking run
#: before it is treated as an oversized encoded blob. ~1500 base64 chars is
#: ~1.1 KB of encoded data — well above the short encoded values (auth tokens,
#: hashes, tiny data URIs, JWT segments) that appear in benign traffic, so
#: routine work stays PASS. Tunable per instance; a named threshold, never a
#: magic number buried in the logic.
_DEFAULT_MIN_BLOB_CHARS = 1500

#: Minimum number of *distinct* characters a run must use to read as encoded
#: binary rather than repetitive filler (e.g. a long ``AAAA…`` run).
_MIN_DISTINCT_CHARS = 20

#: Maximal runs of the base64 / base64url alphabet (standard ``+/`` and url-safe
#: ``-_``, with ``=`` padding). Natural-language and code are broken up by
#: spaces and punctuation, so only genuinely contiguous encoded data reaches the
#: length threshold below.
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/=_-]+")


def _looks_like_base64_blob(run: str) -> bool:
    """True when ``run`` has the character mix of encoded *binary* data.

    Base64 of real binary/secret data spreads across the full 64-symbol
    alphabet, so it carries upper- **and** lower-case letters **and** digits and
    many distinct symbols. Requiring all three cheaply rejects long non-base64
    runs that merely share the charset: lowercase git hashes / hex (digits +
    lowercase only), all-numeric ids (no letters), and long single-case
    identifiers or words (no digits). The distinct-character floor then rejects
    repetitive filler that happens to mix the classes.
    """
    has_upper = has_lower = has_digit = False
    for ch in run:
        if ch.isupper():
            has_upper = True
        elif ch.islower():
            has_lower = True
        elif ch.isdigit():
            has_digit = True
        if has_upper and has_lower and has_digit:
            break
    if not (has_upper and has_lower and has_digit):
        return False
    return len(set(run)) >= _MIN_DISTINCT_CHARS


class Base64BlobDetector:
    """Raise-only detector for oversized base64-looking blobs in tool arguments.

    Pure ``Guardrail``: ``evaluate(action, ctx) -> GuardrailResult``. Built-in
    instances construct with no arguments; pass ``min_blob_chars`` to tune the
    size threshold (e.g. a stricter deployment can lower it).
    """

    def __init__(self, *, min_blob_chars: int = _DEFAULT_MIN_BLOB_CHARS) -> None:
        self._min_blob_chars = max(1, int(min_blob_chars))

    def _has_oversized_blob(self, strings: list[str]) -> bool:
        for text in strings:
            # Strip line wrapping first: base64 payloads are routinely wrapped at
            # 64 (PEM) or 76 (MIME) columns with newlines, which would otherwise
            # split one blob into sub-threshold runs. Only newlines are removed —
            # spaces and tabs are left intact, so ordinary whitespace-separated
            # text still breaks into short, sub-threshold runs.
            compact = text[:SCAN_MAX_CHARS].replace("\r", "").replace("\n", "")
            for match in _BASE64_RUN.finditer(compact):
                run = match.group()
                if len(run) >= self._min_blob_chars and _looks_like_base64_blob(run):
                    return True
        return False

    def evaluate(self, action: SecurityObject, ctx: EvalContext) -> GuardrailResult:
        strings = collect_scan_strings(action, ctx)
        if not self._has_oversized_blob(strings):
            return GuardrailResult(verdict=Verdict.PASS, risk=Risk.low)

        # Redaction: log the signal + threshold class only — never the blob.
        logger.debug(
            "oversized encoded blob in action %s (>= %d base64 chars)",
            action.id,
            self._min_blob_chars,
        )
        return GuardrailResult(
            verdict=Verdict.AUTH,
            risk=Risk.medium,
            reason_codes=[ReasonCode.oversized_encoded_blob],
            explanation=(
                "Action carries a large base64-encoded blob in its arguments, a "
                "common shape for smuggling file or secret contents out as an "
                "encoded payload; authentication required before proceeding."
            ),
        )
