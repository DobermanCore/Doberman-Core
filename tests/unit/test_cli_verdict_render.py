"""Slice: every verdict-printing CLI surface routes through ``doberman.render``.

Covers ``verdict_label_str`` (the string-keyed wrapper used where a verdict is
read back from storage as a plain string, e.g. ``row['final_verdict']``) and the
TUI's verdict-cell style mapping. The color/wrap primitives themselves are
already covered by ``test_render.py``.
"""

import pytest

import doberman.render as render


def test_verdict_label_str_known_verdict_colored_when_forced(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(render, "supports_color", lambda: True)
    colored = render.verdict_label_str("BLOCK")
    assert colored != f"{'BLOCK':<5}"  # carries ANSI styling
    assert "BLOCK" in colored


def test_verdict_label_str_known_verdict_plain_with_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert render.verdict_label_str("AUTH") == f"{'AUTH':<5}"


def test_verdict_label_str_unknown_value_padded_plain_no_exception(monkeypatch):
    # Corrupt/legacy row value -- must never raise, and is never colored even
    # when color would otherwise apply.
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setattr(render, "supports_color", lambda: True)
    assert render.verdict_label_str("ALLOW") == f"{'ALLOW':<5}"


def test_verdict_label_str_plain_output_byte_identical_to_old_format(monkeypatch):
    # Alignment invariant: the pre-render.py hand-rolled f"{v:<5}" lines must
    # still line up exactly when color is off (redirected output, NO_COLOR, CI logs).
    monkeypatch.setenv("NO_COLOR", "1")
    for value in ("BLOCK", "AUTH", "PASS"):
        assert render.verdict_label_str(value) == f"{value:<5}"


def test_tui_verdict_style_mapping_covers_exactly_pass_auth_block():
    # doberman.tui imports textual at module scope (by design -- see its
    # docstring); skip cleanly in the standalone dev venv, same as test_tui.py.
    pytest.importorskip("textual")
    from doberman.tui import _VERDICT_STYLES as tui_verdict_styles

    assert set(tui_verdict_styles) == {"PASS", "AUTH", "BLOCK"}
