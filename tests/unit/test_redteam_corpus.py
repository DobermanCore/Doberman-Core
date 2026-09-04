"""Unit tests for the red-team corpus generator.

Asserts:
1. Determinism: two builds with the same seed produce identical corpora.
2. Well-formedness: every item has the required keys and valid values.
3. Benign items are correctly labeled (never attack channels).
4. Legit emoji / flag sequences are labeled benign and pass scan_text clean.
5. GCG suffix fixtures pass scan_text CLEAN (no OOD channel detected), proving
   the gap the perplexity channel fills.
6. Evasion items pass scan_text CLEAN for their targeted channel, verifying that
   each item genuinely evades the deterministic detection it claims to bypass.

--- SOFT-CHANNEL ASR 0.0 IS A BASELINE, NOT A ROBUSTNESS CLAIM ---

The _gen_*soft* generators produce items where the targeted soft channel WILL fire
because they use the exact known signatures (SEED_GLITCH_FRAGMENTS, the known
confusable map, the curated whole-script lookalike set, NFKC-transformable
codepoints).  Their ASR == 0.0 is a no-regression
baseline that confirms the implementation is consistent with its own seed list.  It
is NOT evidence the defense is airtight against novel variants.

The evasion set (_gen_soft_evasions) and the GCG suffix set are the TWO DOCUMENTED
GAPS in the deterministic soft defense.  The enterprise perplexity detector
(plan slice P2.4) is designed to close these gaps.
"""

from doberman.tokens import scan_text
from tests.redteam.corpus import build_corpus

REQUIRED_KEYS = {"id", "channel", "technique", "expected", "carrier", "payload_marker", "text"}
VALID_EXPECTED = {"hard", "soft", "perplexity_only", "benign", "evasion"}
HARD_CHANNELS = {
    "tag_block",
    "bidi_controls",
    "variation_selectors",
    "noncharacter",
    "unpaired_surrogate",
    "invisible_only",
    "zero_width",  # zero_width can be hard (run >= ZERO_WIDTH_HARD_RUN)
}
SOFT_CHANNELS = {
    "zero_width",  # also soft when count < threshold
    "private_use",
    "control_chars",
    "mixed_script_confusable",
    "whole_script_confusable",
    "nfkc_delta",
    "glitch_fragment",
}


def test_deterministic_across_two_builds():
    """Same seed produces identical corpus twice."""
    corpus_a = build_corpus(seed=1337)
    corpus_b = build_corpus(seed=1337)
    assert corpus_a == corpus_b, "Corpus must be deterministic given the same seed"


def test_different_seeds_differ():
    """Different seeds produce different corpora (sanity check on seeding)."""
    corpus_a = build_corpus(seed=1337)
    corpus_b = build_corpus(seed=9999)
    # At minimum the random-generated items should differ
    texts_a = {item["text"] for item in corpus_a}
    texts_b = {item["text"] for item in corpus_b}
    assert texts_a != texts_b, "Different seeds should produce different corpora"


def test_every_item_well_formed():
    """Every corpus item has all required keys with valid values."""
    corpus = build_corpus()
    assert len(corpus) > 0, "Corpus must not be empty"

    seen_ids: set[str] = set()
    for item in corpus:
        # Required keys present
        missing = REQUIRED_KEYS - set(item.keys())
        assert not missing, f"Item {item.get('id', '?')} missing keys: {missing}"

        # ID is unique and non-empty
        assert item["id"], f"Item has empty id: {item}"
        assert item["id"] not in seen_ids, f"Duplicate id: {item['id']}"
        seen_ids.add(item["id"])

        # expected is a known value
        assert item["expected"] in VALID_EXPECTED, (
            f"Item {item['id']} has invalid expected: {item['expected']!r}"
        )

        # text is a non-empty string
        assert isinstance(item["text"], str) and item["text"], (
            f"Item {item['id']} has empty/invalid text"
        )

        # channel is a non-empty string
        assert isinstance(item["channel"], str) and item["channel"], (
            f"Item {item['id']} has empty channel"
        )

        # payload_marker is a string
        assert isinstance(item["payload_marker"], str), (
            f"Item {item['id']} has non-string payload_marker"
        )

        # Benign items must have channel == "benign"
        if item["expected"] == "benign":
            assert item["channel"] == "benign", (
                f"Benign item {item['id']} has non-benign channel: {item['channel']!r}"
            )


def test_benign_items_are_never_labeled_as_attacks():
    """Legit emoji / flag sequences are labeled benign, never hard/soft/perplexity."""
    corpus = build_corpus()
    benign_items = [item for item in corpus if item["expected"] == "benign"]
    assert len(benign_items) > 0, "Corpus must contain benign items"

    for item in benign_items:
        assert item["expected"] == "benign", (
            f"Benign item {item['id']} unexpectedly labeled as {item['expected']!r}"
        )
        assert item["channel"] == "benign", (
            f"Benign item {item['id']} has channel {item['channel']!r}, expected 'benign'"
        )


def test_legit_flag_tag_sequences_pass_scan_text_clean():
    """Emoji flag tag sequences (UTS#51 grammar) pass scan_text without hard findings.

    The scanner exempts well-formed tag sequences (WAVING BLACK FLAG + tag chars +
    CANCEL TAG), so these must NOT produce a 'tag_block' hard finding.
    """
    corpus = build_corpus()
    flag_items = [
        item for item in corpus if item["expected"] == "benign" and "flag_tag" in item["technique"]
    ]
    assert len(flag_items) > 0, "Corpus must contain flag tag sequence items"

    for item in flag_items:
        report = scan_text(item["text"])
        hard_channels = report.channels(severity="hard")
        assert "tag_block" not in hard_channels, (
            f"Legit flag tag sequence {item['id']} was incorrectly flagged as tag_block. "
            f"Hard channels found: {hard_channels}"
        )


def test_legit_emoji_zwj_pass_scan_text():
    """Legit emoji ZWJ sequences are not flagged by the scanner."""
    corpus = build_corpus()
    zwj_items = [
        item for item in corpus if item["expected"] == "benign" and "zwj" in item["technique"]
    ]
    assert len(zwj_items) > 0, "Corpus must contain ZWJ emoji items"

    for item in zwj_items:
        report = scan_text(item["text"])
        # ZWJ in emoji context is grammar-exempted; it must not produce hard findings
        hard_channels = report.channels(severity="hard")
        assert not hard_channels, (
            f"Legit ZWJ emoji item {item['id']} produced hard findings: {hard_channels}"
        )


def test_gcg_suffixes_pass_scan_text_clean():
    """GCG adversarial suffixes must NOT be caught by the deterministic scanner.

    These are syntactically valid Unicode strings — no OOD codepoints. The
    deterministic scanner cannot detect them, proving the gap that the
    perplexity channel fills. If scan_text raises a finding on a GCG suffix,
    either the suffix was wrong or the scanner was incorrectly flagging ASCII.
    """
    corpus = build_corpus()
    gcg_items = [item for item in corpus if item["expected"] == "perplexity_only"]

    # If no GCG suffixes loaded (file missing), skip gracefully
    if not gcg_items:
        import pytest

        pytest.skip("No GCG suffix fixtures found")

    for item in gcg_items:
        report = scan_text(item["text"])
        # GCG suffixes are plain ASCII/printable Unicode — no OOD channels
        assert not report.has_hard, (
            f"GCG suffix {item['id']} unexpectedly triggered hard channel(s): "
            f"{report.channels(severity='hard')}. "
            "GCG suffixes must be clean of deterministic channels — they test the "
            "perplexity seam, not the token scanner."
        )
        assert not report.has_soft, (
            f"GCG suffix {item['id']} unexpectedly triggered soft channel(s): "
            f"{report.channels(severity='soft')}. "
            "Clean GCG suffixes should not contain glitch tokens or confusables."
        )


def test_corpus_has_coverage_of_expected_categories():
    """Corpus covers all five expected categories including evasion."""
    corpus = build_corpus()
    categories = {item["expected"] for item in corpus}
    assert "hard" in categories, "Corpus must contain hard-channel items"
    assert "soft" in categories, "Corpus must contain soft-channel items"
    assert "benign" in categories, "Corpus must contain benign items"
    assert "evasion" in categories, "Corpus must contain evasion items (documented gaps)"
    # perplexity_only depends on fixture file; check if present
    if any(item["expected"] == "perplexity_only" for item in corpus):
        assert "perplexity_only" in categories


def test_hard_channel_items_use_known_channel_ids():
    """Hard-channel items use the real channel-id strings from tokens.py."""
    corpus = build_corpus()
    hard_items = [item for item in corpus if item["expected"] == "hard"]
    for item in hard_items:
        assert item["channel"] in HARD_CHANNELS, (
            f"Hard item {item['id']} uses unknown channel id: {item['channel']!r}. "
            f"Known hard channels: {HARD_CHANNELS}"
        )


def test_soft_channel_items_use_known_channel_ids():
    """Soft-channel items use the real channel-id strings from tokens.py."""
    corpus = build_corpus()
    soft_items = [item for item in corpus if item["expected"] == "soft"]
    for item in soft_items:
        assert item["channel"] in SOFT_CHANNELS, (
            f"Soft item {item['id']} uses unknown channel id: {item['channel']!r}. "
            f"Known soft channels: {SOFT_CHANNELS}"
        )


def test_evasion_items_are_well_formed():
    """Evasion items have the expected structure including bypasses_deterministic."""
    corpus = build_corpus()
    evasion_items = [item for item in corpus if item["expected"] == "evasion"]
    assert len(evasion_items) >= 9, (
        f"Corpus must contain at least 9 evasion items, found {len(evasion_items)}"
    )
    for item in evasion_items:
        assert "bypasses_deterministic" in item, (
            f"Evasion item {item['id']} missing 'bypasses_deterministic' key"
        )
        assert item["bypasses_deterministic"] is True, (
            f"Evasion item {item['id']} has bypasses_deterministic={item['bypasses_deterministic']!r}, "
            f"expected True"
        )
        assert item["channel"].endswith("_evasion"), (
            f"Evasion item {item['id']} channel {item['channel']!r} should end with '_evasion'"
        )


def test_evasion_items_genuinely_evade_targeted_channel():
    """Verify each evasion item actually evades scan_text for its targeted channel.

    This is the critical correctness check: every item with expected='evasion' and
    bypasses_deterministic=True must produce NO soft/hard findings when fed to
    scan_text().  If an item is caught, the corpus is lying about its bypass status.

    This is the documented deterministic-soft gap — the evasion set proves the gap
    EXISTS, which is what motivates the enterprise perplexity detector (P2.4).
    """
    corpus = build_corpus()
    evasion_items = [item for item in corpus if item["expected"] == "evasion"]

    for item in evasion_items:
        if not item.get("bypasses_deterministic"):
            continue  # Only verify claimed bypasses
        report = scan_text(item["text"])
        assert not report.has_hard, (
            f"Evasion item {item['id']} (channel={item['channel']!r}) "
            f"unexpectedly triggered HARD channel(s): {report.channels(severity='hard')}. "
            f"The item claims bypasses_deterministic=True but the scanner caught it. "
            f"Either the item is wrong or the scanner was strengthened — update the corpus."
        )
        assert not report.has_soft, (
            f"Evasion item {item['id']} (channel={item['channel']!r}) "
            f"unexpectedly triggered SOFT channel(s): {report.channels(severity='soft')}. "
            f"The item claims bypasses_deterministic=True but the scanner caught it. "
            f"Either the item is wrong or the scanner was strengthened — update the corpus."
        )
