"""Unit tests for the pure host-selection helpers backing `doberman setup` (HK.5).

Pure functions only — no CliRunner, no real ``~/.claude``/``~/.codex``. Every
``home`` is an explicit ``tmp_path`` subdirectory, never the real machine's home.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from doberman.hosthooks.setup import (
    HOSTS,
    default_hosts,
    detect_hosts,
    host_menu_lines,
    parse_host_choice,
)

# ---------------------------------------------------------------------------
# detect_hosts
# ---------------------------------------------------------------------------


def test_detect_hosts_nothing_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    root = tmp_path / "root"
    home.mkdir()
    root.mkdir()
    assert detect_hosts(str(root), home) == set()


def test_detect_hosts_claude_in_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"claude"}


def test_detect_hosts_claude_in_project_root(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "root"
    (root / ".claude").mkdir(parents=True)
    assert detect_hosts(str(root), home) == {"claude"}


def test_detect_hosts_codex_in_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"codex"}


def test_detect_hosts_codex_in_project_root(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "root"
    (root / ".codex").mkdir(parents=True)
    assert detect_hosts(str(root), home) == {"codex"}


def test_detect_hosts_cursor_in_project_root(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "root"
    (root / ".cursor").mkdir(parents=True)
    assert detect_hosts(str(root), home) == {"mcp"}


def test_detect_hosts_cursor_in_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"mcp"}


def test_detect_hosts_claude_desktop_config_darwin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    home = tmp_path / "home"
    config = home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"mcp"}


def test_detect_hosts_claude_desktop_config_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    home = tmp_path / "home"
    config = home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"mcp"}


def test_detect_hosts_claude_desktop_config_linux(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    home = tmp_path / "home"
    config = home / ".config" / "Claude" / "claude_desktop_config.json"
    config.parent.mkdir(parents=True)
    config.write_text("{}", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"mcp"}


def test_detect_hosts_openclaw_never_auto_detected(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    root = tmp_path / "root"
    (root / "openclaw").mkdir(parents=True)  # a plausible-looking marker, still ignored
    assert "openclaw" not in detect_hosts(str(root), home)


def test_detect_hosts_multiple(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".codex").mkdir(parents=True)
    root = tmp_path / "root"
    root.mkdir()
    assert detect_hosts(str(root), home) == {"claude", "codex"}


# ---------------------------------------------------------------------------
# default_hosts
# ---------------------------------------------------------------------------


def test_default_hosts_nothing_detected_falls_back_to_claude() -> None:
    assert default_hosts(set()) == ["claude"]


def test_default_hosts_preserves_hosts_order() -> None:
    assert default_hosts({"codex", "claude"}) == ["claude", "codex"]


def test_default_hosts_single_non_claude() -> None:
    assert default_hosts({"mcp"}) == ["mcp"]


# ---------------------------------------------------------------------------
# host_menu_lines
# ---------------------------------------------------------------------------


def test_host_menu_lines_covers_all_hosts() -> None:
    lines = host_menu_lines(set())
    assert len(lines) == len(HOSTS)
    for host in HOSTS:
        assert any(host.label in line for line in lines)


def test_host_menu_lines_marks_only_detected() -> None:
    lines = host_menu_lines({"claude"})
    claude_line = next(line for line in lines if "Claude Code" in line)
    codex_line = next(line for line in lines if "Codex CLI" in line)
    assert "detected" in claude_line
    assert "detected" not in codex_line


def test_host_menu_lines_detected_tags_align() -> None:
    """Every ``<- detected`` tag starts at the same column, regardless of label length."""
    lines = host_menu_lines({h.key for h in HOSTS})
    columns = {line.index("<- detected") for line in lines}
    assert len(columns) == 1, f"tags not aligned: {lines}"


def test_host_menu_lines_have_no_trailing_whitespace() -> None:
    """A non-detected host's line must not carry the padding spaces its label
    column left behind once no ``<- detected`` tag follows them."""
    lines = host_menu_lines(set())
    for line in lines:
        assert line == line.rstrip(), f"trailing whitespace: {line!r}"


# ---------------------------------------------------------------------------
# parse_host_choice
# ---------------------------------------------------------------------------


def test_parse_host_choice_by_number() -> None:
    assert parse_host_choice("1", set()) == ["claude"]
    assert parse_host_choice("2", set()) == ["codex"]


def test_parse_host_choice_by_name() -> None:
    assert parse_host_choice("claude", set()) == ["claude"]
    assert parse_host_choice("CODEX", set()) == ["codex"]


def test_parse_host_choice_multiple_comma_separated() -> None:
    assert parse_host_choice("1,2", set()) == ["claude", "codex"]


def test_parse_host_choice_multiple_space_separated() -> None:
    assert parse_host_choice("1 2", set()) == ["claude", "codex"]


def test_parse_host_choice_mixed_names_and_numbers() -> None:
    assert parse_host_choice("claude, 2", set()) == ["claude", "codex"]


def test_parse_host_choice_all() -> None:
    assert parse_host_choice("all", set()) == [h.key for h in HOSTS]


def test_parse_host_choice_blank_returns_detected() -> None:
    assert parse_host_choice("", {"codex"}) == ["codex"]


def test_parse_host_choice_blank_returns_default_when_nothing_detected() -> None:
    assert parse_host_choice("   ", set()) == ["claude"]


def test_parse_host_choice_preserves_hosts_order_and_dedupes() -> None:
    assert parse_host_choice("2,1,2,1", set()) == ["claude", "codex"]


def test_parse_host_choice_unknown_name_raises() -> None:
    with pytest.raises(ValueError):
        parse_host_choice("cursor", set())


def test_parse_host_choice_out_of_range_number_raises() -> None:
    with pytest.raises(ValueError):
        parse_host_choice("9", set())
