"""Whole-script confusable detection and subjective AUTH escalation (issue #141).

Ported from the WIP branch (commit 8bd64d0, wip/ef2-whole-script-confusable) onto
today's code. Complements ``mixed_script_confusable`` (a Cyrillic/Greek letter
*mixed into* an otherwise-Latin token): this channel catches a token rendered
*entirely* in one non-Latin script that is a whole-word look-alike of a Latin
command/path token (e.g. an all-Cyrillic look-alike of "paypal") — no script
mixing, and NFKC-stable, so every other channel in ``doberman.tokens`` is blind
to it.

FPR guard (issue #141 requirement): genuine Cyrillic/Greek prose and a genuine
Cyrillic file name must produce zero hits — the raise-only 0.0-FPR floor.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.detectors.token_channels import TokenChannelDetector
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.tokens import scan_text

CYRILLIC_PAYPAL = "раураӏ"
CYRILLIC_ACCOUNT = "ассоунт"
CYRILLIC_SECURE = "сесуре"


def _channels(text: str, severity: str = "soft") -> set[str]:
    return set(scan_text(text).channels(severity=severity))


@pytest.mark.parametrize(
    "spoof",
    [CYRILLIC_PAYPAL, CYRILLIC_ACCOUNT, CYRILLIC_SECURE, "ροχυ"],
)
def test_whole_script_lookalikes_are_soft(spoof: str) -> None:
    report = scan_text(spoof)

    assert "whole_script_confusable" in report.channels(severity="soft")
    assert not report.has_hard


def test_genuine_cyrillic_word_with_nonlookalike_is_not_reported() -> None:
    # "пароль" (password): п/л/ь fall outside the curated lookalike set even
    # after this fix's lowercase-case audit (к/η/μ) — genuinely non-lookalike.
    assert "whole_script_confusable" not in _channels("пароль")


def test_genuine_greek_word_with_nonlookalike_is_not_reported() -> None:
    assert "whole_script_confusable" not in _channels("γλώσσα")


def test_pure_latin_word_is_not_reported() -> None:
    assert "whole_script_confusable" not in _channels("paypal")


def test_mixed_script_token_remains_owned_by_mixed_script_channel() -> None:
    channels = _channels("раураl")

    assert "whole_script_confusable" not in channels
    assert "mixed_script_confusable" in channels


def test_whole_script_finding_redacts_raw_spoof() -> None:
    report = scan_text(CYRILLIC_PAYPAL)
    details = [finding.detail for finding in report.findings]
    serialized = repr(report.to_audit_dict()) + repr(report) + repr(details)

    assert CYRILLIC_PAYPAL not in serialized


def test_whole_script_soft_channel_flows_to_auth() -> None:
    action = SecurityObject(
        id="whole-script-1",
        ts=datetime(2026, 7, 11, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_write,
        tool_name="write_file",
        target="login.ts",
    )
    ctx = EvalContext(metadata={"raw_arguments": {"content": CYRILLIC_PAYPAL}})

    result = TokenChannelDetector().evaluate(action, ctx)

    assert result.verdict is Verdict.AUTH
    assert ReasonCode.anomalous_token_pattern in result.reason_codes


# --- FPR guard (issue #141): genuine Cyrillic/Greek prose must stay silent ----


def test_genuine_cyrillic_prose_is_not_flagged() -> None:
    """A few sentences of real Russian prose — including short function words
    ("в", "на", "и") that would false-positive without the length floor."""
    sentences = [
        "Добро пожаловать в систему, пожалуйста читайте документацию.",
        "Следуйте инструкциям на сайте и сохраните файл на диске.",
        "Эта функция помогает пользователям находить нужную информацию быстро.",
    ]
    for sentence in sentences:
        assert "whole_script_confusable" not in _channels(sentence), sentence


def test_genuine_greek_prose_is_not_flagged() -> None:
    """A few sentences of real Greek prose — including short function words
    ("το", "την", "και") that would false-positive without the length floor."""
    sentences = [
        "Καλώς ορίσατε στο σύστημα, παρακαλώ διαβάστε την τεκμηρίωση.",
        "Ακολουθήστε τις οδηγίες και αποθηκεύστε το αρχείο στον υπολογιστή.",
        "Η ομάδα υποστήριξης απαντά σε ερωτήματα πελατών κάθε μέρα.",
    ]
    for sentence in sentences:
        assert "whole_script_confusable" not in _channels(sentence), sentence


def test_genuine_cyrillic_filename_is_not_flagged() -> None:
    """A README-style Cyrillic file name (real word, not a brand look-alike)."""
    assert "whole_script_confusable" not in _channels("прочтименя")


def test_short_cyrillic_function_words_are_not_flagged() -> None:
    """Common short Cyrillic words happen to be built entirely from the curated
    lookalike letters (e.g. "он"=he, "на"=on) — the length floor, not the
    per-letter curated set, is what keeps these from false-positiving."""
    for word in ("он", "на", "то", "со"):
        assert "whole_script_confusable" not in _channels(word), word


# --- Genuine-script discriminator (issue #141 controller review) -------------
# A whole-script spoof only works if it is an *isolated* non-Latin token in
# Latin context; genuine Cyrillic/Greek prose brings company — other
# same-script tokens with letters outside the curated lookalike set. These
# all-lookalike common words (Russian "тема"/"theme", Greek "θέμα"/"theme")
# previously false-positived even though real prose surrounds them.


def test_genuine_russian_sentence_with_lookalike_word_is_not_flagged() -> None:
    assert "whole_script_confusable" not in _channels("Обновить тему в конфиге")


def test_genuine_greek_sentence_with_lookalike_word_is_not_flagged() -> None:
    assert "whole_script_confusable" not in _channels("Καλή μέρα, νέο θέμα σήμερα")


def test_genuine_russian_prose_with_latin_identifier_is_not_flagged() -> None:
    assert "whole_script_confusable" not in _channels("Исправить тему в config.py")


def test_spoof_still_flagged_alongside_latin_company_only() -> None:
    """The existing spoof fixtures, in Latin sentence context, still fire —
    genuine evidence requires a same-script non-lookalike token, and none of
    these sentences have one."""
    for spoof, sentence in [
        (CYRILLIC_PAYPAL, "transfer funds via раураӏ now"),
        (CYRILLIC_ACCOUNT, "visit your ассоунт dashboard"),
        ("ροχυ", "contact support at ροχυ helpdesk"),
    ]:
        assert spoof in sentence
        assert "whole_script_confusable" in _channels(sentence), sentence


def test_spoof_with_latin_company_and_punctuation_only_is_flagged() -> None:
    assert "whole_script_confusable" in _channels("login: раураӏ")


# --- Case audit (issue #141 follow-up): lowercase confusables ----------------
# The curated set previously had uppercase Cyrillic К and Greek Η/Μ without
# their lowercase forms, even though real spoofs are lowercase.


def test_lowercase_cyrillic_ka_spoof_is_flagged() -> None:
    """ "аккаунт" (all-lookalike incl. the lowercase к added by this fix) in
    otherwise-Latin context must fire."""
    assert "whole_script_confusable" in _channels("visit your аккаунт login page")


def test_genuine_russian_sentence_with_ka_spoof_word_is_not_flagged() -> None:
    """The same all-lookalike word, surrounded by genuine Russian prose, stays
    silent — the sentence's other words carry non-lookalike Cyrillic letters."""
    assert "whole_script_confusable" not in _channels("Проверьте аккаунт и пароль")
