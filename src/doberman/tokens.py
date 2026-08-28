"""Deterministic out-of-distribution / smuggled-token channel scanner.

A dependency-free (stdlib only) detector for token-level smuggling and
out-of-distribution (OOD) channels in any text Doberman observes — tool
arguments, the action target, an external destination, a tool name. It is a
leaf utility with **no internal Doberman imports**, so both the objective rule
(:mod:`doberman.engine.rules.token_channels`) and the subjective detector
(:mod:`doberman.engine.detectors.token_channels`) can reuse it.

Channels detected
------------------
**Hard** (deterministic, near-zero false-positive — no legitimate use in tool
traffic; an objective rule may step these up to AUTH/BLOCK):

* ``tag_block``          — Unicode Tag Block ASCII smuggling (U+E0000–E007F),
  outside any well-formed emoji tag sequence ("ASCII Smuggler" class).
* ``bidi_controls``      — bidirectional overrides (Trojan-Source class): what a
  human reviews is not what executes.
* ``variation_selectors``— runs of variation selectors used as a byte channel.
* ``noncharacter``       — noncharacter / unassigned codepoints (invalid in
  interchange text).
* ``unpaired_surrogate`` — lone surrogate codepoints (a documented reassembly
  evasion for tag-block smuggling).
* ``invisible_only``     — a payload made up entirely of invisible codepoints.
* ``zero_width``         — a *run* of zero-width / invisible characters at or
  above :data:`ZERO_WIDTH_HARD_RUN` (steganographic channel).

**Soft** (probabilistic / context-dependent — raise-only signals for the
subjective layer, never a hard block here):

* ``zero_width``                — a small number of zero-width characters.
* ``private_use``               — private-use-area codepoints (undefined,
  OOD by construction).
* ``control_chars``             — C0 control characters outside tab/newline/CR.
* ``mixed_script_confusable``   — a single token mixing visually confusable
  scripts (e.g. a Cyrillic ``а`` inside a Latin word — homoglyph spoofing).
* ``nfkc_delta``                — text that *gains* ASCII content under NFKC
  normalization (compatibility-form smuggling).
* ``glitch_fragment``           — a known under-trained ("glitch") token
  fragment (SolidGoldMagikarp class; list-driven, extensible).

Design rules carried over from Doberman's invariants
-----------------------------------------------------
* **Detection only ever RAISES risk.** Nothing here lowers a verdict.
* **Grammar, not suppression, controls false positives.** Legitimate emoji tag
  sequences (waving black flag + tag chars + CANCEL TAG, UTS #51), emoji ZWJ
  sequences, and joining-script ZWNJ are exempted by their *grammar*. A
  tag-block hit outside that exact grammar is never silently dropped, including
  an invisible-only line.
* **No raw payload ever leaves this module.** Reports carry channel *classes*
  and counts only — never the decoded smuggled text, never a matched substring.
* **No model, no network, stdlib only.** O(n) single pass over the text.

This is defense-in-depth, deliberately imperfect: it does not (and cannot)
catch optimizer-generated adversarial suffixes from character statistics alone
(that needs a real perplexity model — wired separately, opt-in, in the
subjective detector). It is not marketed as airtight.
"""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

SCANNER_VERSION = "1.0.0"

#: Cap on text scanned from any single string field (matches the secrets rule).
SCAN_MAX_CHARS = 100_000

# --- Codepoint sets ----------------------------------------------------------

TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F
TAG_CANCEL = 0xE007F
TAG_BASE_FLAG = 0x1F3F4  # WAVING BLACK FLAG — the only legitimate tag-seq base (UTS #51)

#: Zero-width / invisible format characters with no glyph. A handful have
#: legitimate uses (ZWJ in emoji sequences, ZWNJ in joining scripts) that are
#: grammar-exempted in :func:`scan_text`; the rest are pure stego channels.
ZERO_WIDTH = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER (legit in Persian/Indic — grammar-exempted)
        0x200D,  # ZERO WIDTH JOINER (legit in emoji ZWJ sequences — grammar-exempted)
        0x2060,  # WORD JOINER
        0xFEFF,  # BOM / ZERO WIDTH NO-BREAK SPACE
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x00AD,  # SOFT HYPHEN
        0x034F,  # COMBINING GRAPHEME JOINER
        0x061C,  # ARABIC LETTER MARK
        0x115F,
        0x1160,  # HANGUL FILLERS
        0x17B4,
        0x17B5,  # KHMER INHERENT VOWELS
        0x3164,  # HANGUL FILLER
        0xFFA0,  # HALFWIDTH HANGUL FILLER
    }
)

BIDI_CONTROLS = frozenset(
    {
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,  # LRE RLE PDF LRO RLO
        0x2066,
        0x2067,
        0x2068,
        0x2069,  # LRI RLI FSI PDI
        0x200E,
        0x200F,  # LRM RLM
    }
)

VARIATION_SELECTORS = frozenset(set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0)))

NONCHARACTERS = frozenset(
    set(range(0xFDD0, 0xFDF0))
    | {plane << 16 | suffix for plane in range(0x11) for suffix in (0xFFFE, 0xFFFF)}
)

#: C0 controls that are normal in text and never flagged.
ALLOWED_CONTROLS = frozenset({0x09, 0x0A, 0x0D})  # tab, LF, CR

#: A run of this many variation selectors (or this many total) is byte-channel
#: smuggling, not glyph variation.
VARIATION_SELECTOR_RUN = 3
VARIATION_SELECTOR_TOTAL = 12

#: A run of this many zero-width characters is a hard steganographic channel;
#: fewer is a soft signal (a stray one can be a copy-paste artefact).
ZERO_WIDTH_HARD_RUN = 8

#: Script pairs that are visually confusable and almost never co-occur inside a
#: single whitespace-delimited token in legitimate text (homoglyph spoofing).
_CONFUSABLE_SCRIPT_PAIRS = (
    frozenset({"LATIN", "CYRILLIC"}),
    frozenset({"LATIN", "GREEK"}),
)

#: Seed list of well-known glitch / under-trained token fragments. Extensible
#: via :class:`GlitchFragmentStore`; tokenizer-specific per-model lists can be
#: generated with the "Fishing for Magikarp" methodology and supplied at
#: construction time (e.g. by an enterprise rule pack).
SEED_GLITCH_FRAGMENTS: tuple[str, ...] = (
    " SolidGoldMagikarp",
    " petertodd",
    " davidjl",
    "rawdownloadcloneembedreportprint",
    "BuyableInstoreAndOnline",
    " guiActiveUn",
    " externalToEVA",
    "quickShipAvailable",
    " unfocusedRange",
    "StreamerBot",
    "PsyNetMessage",
)

#: Channel names that are deterministic and near-zero false positive.
HARD_CHANNELS = frozenset(
    {
        "tag_block",
        "bidi_controls",
        "variation_selectors",
        "noncharacter",
        "unpaired_surrogate",
        "invisible_only",
    }
)
#: Channel names that are probabilistic / context-dependent (raise-only).
SOFT_CHANNELS = frozenset(
    {
        "private_use",
        "control_chars",
        "mixed_script_confusable",
        "nfkc_delta",
        "glitch_fragment",
    }
)


# --- Report types ------------------------------------------------------------


@dataclass(frozen=True)
class ChannelFinding:
    """One detected channel. Carries the channel *class* and a count only —
    never the matched text, decoded payload, or positions."""

    channel: str
    severity: str  # "hard" | "soft"
    count: int
    detail: str  # class-level description, never raw payload


@dataclass
class OODTokenReport:
    """The result of scanning one text. Redaction-safe: no field ever holds the
    smuggled payload, only channel classes and counts."""

    findings: list[ChannelFinding] = field(default_factory=list)
    smuggled_char_count: int = 0
    visible_char_count: int = 0
    nfkc_changed: bool = False
    scanner_version: str = SCANNER_VERSION

    @property
    def has_hard(self) -> bool:
        return any(f.severity == "hard" for f in self.findings)

    @property
    def has_soft(self) -> bool:
        return any(f.severity == "soft" for f in self.findings)

    def channels(self, severity: str | None = None) -> list[str]:
        return [f.channel for f in self.findings if severity is None or f.severity == severity]

    def to_audit_dict(self) -> dict:
        """A redaction-safe summary for logs: channel classes + counts only."""
        return {
            "scanner_version": self.scanner_version,
            "findings": [
                {"channel": f.channel, "severity": f.severity, "count": f.count}
                for f in self.findings
            ],
            "smuggled_char_count": self.smuggled_char_count,
            "nfkc_changed": self.nfkc_changed,
            "has_hard": self.has_hard,
            "has_soft": self.has_soft,
        }


class GlitchFragmentStore:
    """A substring set of known glitch / under-trained token fragments.

    Defaults to :data:`SEED_GLITCH_FRAGMENTS`; pass ``extra`` to extend it (e.g.
    a per-model list). Matching is a plain substring containment test — cheap
    and tokenizer-agnostic at the cost of being approximate.
    """

    def __init__(self, extra: Iterable[str] | None = None) -> None:
        fragments = list(SEED_GLITCH_FRAGMENTS)
        if extra is not None:
            fragments.extend(extra)
        # Drop empties so an accidental "" does not match every string.
        self._fragments: tuple[str, ...] = tuple(f for f in fragments if f)

    def count(self, text: str) -> int:
        return sum(1 for fragment in self._fragments if fragment in text)


# --- Emoji tag-sequence grammar exemption (UTS #51) --------------------------


def _legit_tag_sequence_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` spans of well-formed emoji tag sequences: U+1F3F4
    followed by 1..30 tag chars (E0020–E007E) terminated by CANCEL TAG.
    Anything outside this exact grammar is NOT exempted."""
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        if ord(text[i]) == TAG_BASE_FLAG:
            j = i + 1
            tag_count = 0
            while j < n and 0xE0020 <= ord(text[j]) <= 0xE007E and tag_count <= 30:
                j += 1
                tag_count += 1
            if tag_count >= 1 and j < n and ord(text[j]) == TAG_CANCEL:
                spans.append((i, j + 1))
                i = j + 1
                continue
        i += 1
    return spans


def _in_spans(idx: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= idx < end for start, end in spans)


def decode_tag_block(text: str) -> str:
    """Decode ASCII hidden in tag-block characters (outside the legit emoji tag
    grammar). INTERNAL USE ONLY — used to establish that a smuggled payload was
    present and to count it. The decoded text is attacker-controlled and MUST
    NOT be surfaced to the agent or written to any log."""
    spans = _legit_tag_sequence_spans(text)
    out: list[str] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if TAG_BLOCK_START <= cp <= TAG_BLOCK_END and not _in_spans(i, spans):
            base = cp - 0xE0000
            if 0x20 <= base <= 0x7E:
                out.append(chr(base))
    return "".join(out)


# --- Main scan ---------------------------------------------------------------


def scan_text(text: str, glitch_store: GlitchFragmentStore | None = None) -> OODTokenReport:
    """Scan ``text`` for OOD / smuggled-token channels. Single O(n) pass; never
    raises on any input; never returns the payload."""
    report = OODTokenReport()
    if not text:
        return report

    glitch_store = glitch_store or GlitchFragmentStore()
    legit_spans = _legit_tag_sequence_spans(text)

    tag_hits = 0
    zw_hits = 0
    bidi_hits = 0
    vs_positions: list[int] = []
    pua_hits = 0
    nonchar_hits = 0
    ctrl_hits = 0
    surrogate_hits = 0
    visible = 0
    n = len(text)

    for i, ch in enumerate(text):
        cp = ord(ch)
        if TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            if not _in_spans(i, legit_spans):
                tag_hits += 1
            continue
        if cp in ZERO_WIDTH:
            # ZWJ between two non-ASCII symbols → emoji ZWJ sequence (legit).
            if cp == 0x200D and (
                (i > 0 and ord(text[i - 1]) > 0x2000) or (i + 1 < n and ord(text[i + 1]) > 0x2000)
            ):
                continue
            # ZWNJ between two letters of a joining script (Arabic/Persian/Indic).
            if cp == 0x200C and 0 < i < n - 1:
                prev_cp, next_cp = ord(text[i - 1]), ord(text[i + 1])
                if (0x0600 <= prev_cp <= 0x08FF or 0x0900 <= prev_cp <= 0x0DFF) and (
                    0x0600 <= next_cp <= 0x08FF or 0x0900 <= next_cp <= 0x0DFF
                ):
                    continue
            zw_hits += 1
            continue
        if cp in BIDI_CONTROLS:
            bidi_hits += 1
            continue
        if cp in VARIATION_SELECTORS:
            vs_positions.append(i)
            continue
        if (0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD) or (0x100000 <= cp <= 0x10FFFD):
            pua_hits += 1
            continue
        if cp in NONCHARACTERS:
            nonchar_hits += 1
            continue
        if 0xD800 <= cp <= 0xDFFF:
            surrogate_hits += 1
            continue
        if cp < 0x20 and cp not in ALLOWED_CONTROLS:
            ctrl_hits += 1
            continue
        if unicodedata.category(ch) == "Cn":
            nonchar_hits += 1
            continue
        if not ch.isspace():
            visible += 1

    report.visible_char_count = visible

    if tag_hits:
        report.smuggled_char_count = tag_hits + len(decode_tag_block(text))
        report.findings.append(
            ChannelFinding(
                "tag_block",
                "hard",
                tag_hits,
                "Unicode Tag Block characters outside any emoji tag sequence "
                "(ASCII-smuggling channel; no legitimate use)",
            )
        )

    if zw_hits:
        severity = "hard" if zw_hits >= ZERO_WIDTH_HARD_RUN else "soft"
        report.findings.append(
            ChannelFinding(
                "zero_width",
                severity,
                zw_hits,
                "invisible zero-width characters outside emoji / joining-script "
                "grammar (steganographic channel)",
            )
        )

    if bidi_hits:
        report.findings.append(
            ChannelFinding(
                "bidi_controls",
                "hard",
                bidi_hits,
                "bidirectional control characters (Trojan-Source class: what is "
                "reviewed is not what executes)",
            )
        )

    if vs_positions:
        max_run = run = 1
        for a, b in zip(vs_positions, vs_positions[1:], strict=False):
            run = run + 1 if b == a + 1 else 1
            max_run = max(max_run, run)
        if max_run >= VARIATION_SELECTOR_RUN or len(vs_positions) >= VARIATION_SELECTOR_TOTAL:
            report.findings.append(
                ChannelFinding(
                    "variation_selectors",
                    "hard",
                    len(vs_positions),
                    "run of variation selectors inconsistent with glyph variation "
                    "(byte-smuggling channel)",
                )
            )

    if nonchar_hits:
        report.findings.append(
            ChannelFinding(
                "noncharacter",
                "hard",
                nonchar_hits,
                "noncharacter or unassigned codepoints (invalid in interchange text)",
            )
        )

    if surrogate_hits:
        report.findings.append(
            ChannelFinding(
                "unpaired_surrogate",
                "hard",
                surrogate_hits,
                "unpaired surrogate codepoints (known reassembly evasion for tag-block smuggling)",
            )
        )

    if pua_hits:
        report.findings.append(
            ChannelFinding(
                "private_use",
                "soft",
                pua_hits,
                "private-use-area codepoints (undefined semantics; "
                "out-of-distribution by construction)",
            )
        )

    if ctrl_hits:
        report.findings.append(
            ChannelFinding(
                "control_chars",
                "soft",
                ctrl_hits,
                "C0 control characters outside tab / newline / carriage return",
            )
        )

    _scan_mixed_script(text, report)

    try:
        nfkc = unicodedata.normalize("NFKC", text)
    except (ValueError, UnicodeError):  # pragma: no cover — defensive on pathological input
        nfkc = text
    if nfkc != text:
        report.nfkc_changed = True
        # Escalate only when normalization *adds* ASCII content (compat-form
        # smuggling), not for ordinary composed accents.
        raw_ascii = sum(1 for c in text if ord(c) < 128)
        norm_ascii = sum(1 for c in nfkc if ord(c) < 128)
        if norm_ascii > raw_ascii:
            report.findings.append(
                ChannelFinding(
                    "nfkc_delta",
                    "soft",
                    norm_ascii - raw_ascii,
                    "text gains ASCII content under NFKC normalization "
                    "(compatibility-form smuggling)",
                )
            )

    glitch = glitch_store.count(text)
    if glitch:
        report.findings.append(
            ChannelFinding(
                "glitch_fragment",
                "soft",
                glitch,
                "known under-trained ('glitch') token fragment present (Magikarp class)",
            )
        )

    # A payload made of nothing but invisible codepoints is itself a hard flag.
    invisible_total = tag_hits + zw_hits + bidi_hits + pua_hits + nonchar_hits + surrogate_hits
    if invisible_total > 0 and visible == 0:
        report.findings.append(
            ChannelFinding(
                "invisible_only",
                "hard",
                invisible_total,
                "content consists entirely of invisible codepoints",
            )
        )

    return report


# --- Perplexity threshold calibration -----------------------------------------
# The pure-stats half of the opt-in perplexity_fn seam (TokenChannelDetector):
# calibrates a threshold against a benign corpus, no model, no dependency.


def calibrate_perplexity_threshold(benign_scores: Sequence[float], target_fpr: float) -> float:
    """Nearest-rank empirical ``(1 - target_fpr)`` quantile of ``benign_scores``,
    for the ``perplexity_fn``/``perplexity_threshold`` seam on
    :class:`~doberman.engine.detectors.token_channels.TokenChannelDetector`.
    Fails closed: raises ``ValueError`` if ``target_fpr`` is not in ``(0, 1)``,
    fewer than 20 benign scores are given, or any score is not finite.
    """
    if not 0 < target_fpr < 1:
        raise ValueError(f"target_fpr must be in (0, 1), got {target_fpr!r}")
    samples = sorted(benign_scores)
    if not all(math.isfinite(s) for s in samples):
        raise ValueError("benign_scores must all be finite, got a NaN or infinite value")
    if len(samples) < 20:
        raise ValueError(
            "need at least 20 benign samples to calibrate a false-positive "
            f"rate, got {len(samples)}"
        )
    rank = math.ceil((1 - target_fpr) * len(samples))
    return samples[rank - 1]


# --- Action surface collection -----------------------------------------------
# Duck-typed (no model import) so this module stays a leaf utility: both the
# objective rule and the subjective detector collect the same surfaces here.


def iter_strings(value: Any, depth: int = 0) -> Iterator[str]:
    """Yield every string reachable inside a nested argument structure (bounded)."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, val in value.items():
            if isinstance(key, str):
                yield key
            yield from iter_strings(val, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from iter_strings(item, depth + 1)


def collect_scan_strings(action: Any, ctx: Any) -> list[str]:
    """Collect the strings to scan for one action: the un-redacted raw arguments
    (in memory only, never logged) plus the object's own non-secret string
    fields (tool name, target, external destination, and any URL query params).

    Duck-typed against the :class:`~doberman.models.SecurityObject` /
    :class:`~doberman.models.EvalContext` shape so this stays import-free.
    """
    strings: list[str] = []
    metadata = getattr(ctx, "metadata", None)
    raw_arguments = metadata.get("raw_arguments") if isinstance(metadata, dict) else None
    if isinstance(raw_arguments, dict):
        strings.extend(iter_strings(raw_arguments))

    tool_name = getattr(action, "tool_name", None)
    if tool_name:
        strings.append(tool_name)
    for value in (getattr(action, "target", None), getattr(action, "external_destination", None)):
        if value:
            strings.append(value)
            try:
                query = urlsplit(value).query
            except ValueError:
                query = ""
            if query:
                strings.extend(val for _, val in parse_qsl(query, keep_blank_values=False))
    return strings


def _scan_mixed_script(text: str, report: OODTokenReport) -> None:
    """Flag whitespace-delimited tokens that mix visually confusable scripts."""
    suspicious = 0
    for token in text.split():
        scripts: set[str] = set()
        for ch in token:
            if not ch.isalpha():
                continue
            try:
                scripts.add(unicodedata.name(ch).split(" ", 1)[0])
            except ValueError:
                continue
        if any(pair <= scripts for pair in _CONFUSABLE_SCRIPT_PAIRS):
            suspicious += 1
    if suspicious:
        report.findings.append(
            ChannelFinding(
                "mixed_script_confusable",
                "soft",
                suspicious,
                "single tokens mixing visually confusable scripts (homoglyph spoofing)",
            )
        )
