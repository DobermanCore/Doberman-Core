"""Telemetry documentation guardrails.

Covers:
  - Every event in ``doberman.telemetry._EVENT_PROPERTIES`` is documented in
    ``docs/TELEMETRY.md`` and no extra or stale events remain in the doc.
  - Every event's documented extra properties match ``_EVENT_PROPERTIES``.
  - Every fixed property returned by ``base_properties()`` matches the fixed
    properties table in ``docs/TELEMETRY.md``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from doberman.telemetry import _EVENT_PROPERTIES, base_properties

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_FILE = REPO_ROOT / "docs" / "TELEMETRY.md"

_SEPARATOR_RE = re.compile(r"^\|(?:\s*:?-+:?\s*\|)+$")
_PARENS_RE = re.compile(r"\([^)]*\)")
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def _parse_markdown_tables(filepath: Path) -> list[tuple[list[str], list[list[str]]]]:
    """Extract all pipe-delimited markdown tables as ``(headers_lower, rows)``."""
    tables: list[tuple[list[str], list[list[str]]]] = []
    block: list[str] = []

    def _flush() -> None:
        nonlocal block
        if len(block) >= 2:
            headers = [col.strip().lower() for col in block[0].split("|")[1:-1]]
            rows = [
                [col.strip() for col in line.split("|")[1:-1]]
                for line in block[1:]
                if not _SEPARATOR_RE.match(line)
            ]
            if headers and rows:
                tables.append((headers, rows))
        block = []

    for raw_line in filepath.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            block.append(stripped)
        else:
            _flush()
    _flush()
    return tables


def parse_event_properties_table(filepath: Path) -> dict[str, frozenset[str]]:
    """Parse the Event / Extra properties table in ``docs/TELEMETRY.md``."""
    for headers, rows in _parse_markdown_tables(filepath):
        if "event" in headers and "extra properties" in headers:
            event_idx = headers.index("event")
            props_idx = headers.index("extra properties")
            min_cols = max(event_idx, props_idx) + 1
            documented: dict[str, frozenset[str]] = {}
            for cols in rows:
                if len(cols) < min_cols:
                    continue
                event_match = _BACKTICK_RE.search(cols[event_idx])
                event_name = event_match.group(1) if event_match else cols[event_idx]
                # Strip parenthetical examples such as "(..., such as `doctor` or `taint.clear`)".
                props_cell = _PARENS_RE.sub("", cols[props_idx]).strip()
                if props_cell.lower() == "none":
                    props: frozenset[str] = frozenset()
                else:
                    props = frozenset(_BACKTICK_RE.findall(props_cell))
                documented[event_name] = props
            assert documented, f"No telemetry events parsed from {filepath}"
            return documented
    raise AssertionError(
        f"Table with 'Event' and 'Extra properties' headers not found in {filepath}"
    )


def parse_fixed_properties_table(filepath: Path) -> frozenset[str]:
    """Parse the fixed Property / Value table in ``docs/TELEMETRY.md``."""
    for headers, rows in _parse_markdown_tables(filepath):
        if "property" in headers and "value" in headers:
            prop_idx = headers.index("property")
            documented = frozenset(
                match.group(1) if (match := _BACKTICK_RE.search(cols[prop_idx])) else cols[prop_idx]
                for cols in rows
                if len(cols) > prop_idx
            )
            assert documented, f"No fixed telemetry properties parsed from {filepath}"
            return documented
    raise AssertionError(f"Table with 'Property' and 'Value' headers not found in {filepath}")


@pytest.fixture(scope="module")
def documented_events() -> dict[str, frozenset[str]]:
    assert DOCS_FILE.exists(), f"Doc file missing: {DOCS_FILE}"
    return parse_event_properties_table(DOCS_FILE)


@pytest.fixture(scope="module")
def documented_fixed_properties() -> frozenset[str]:
    assert DOCS_FILE.exists(), f"Doc file missing: {DOCS_FILE}"
    return parse_fixed_properties_table(DOCS_FILE)


def test_documented_telemetry_events_match_allowlist(
    documented_events: dict[str, frozenset[str]],
) -> None:
    """Ensure documented event names exactly match ``_EVENT_PROPERTIES``."""
    expected = set(_EVENT_PROPERTIES.keys())
    actual = set(documented_events.keys())
    missing = expected - actual
    extra = actual - expected
    assert not missing, f"Telemetry events missing from {DOCS_FILE}: {sorted(missing)}"
    assert not extra, f"Undocumented/stale telemetry events in {DOCS_FILE}: {sorted(extra)}"


@pytest.mark.parametrize("event_name", sorted(_EVENT_PROPERTIES))
def test_documented_telemetry_event_properties_match_allowlist(
    event_name: str,
    documented_events: dict[str, frozenset[str]],
) -> None:
    """Ensure every event's documented extra properties match ``_EVENT_PROPERTIES``."""
    assert event_name in documented_events, f"Event '{event_name}' missing from {DOCS_FILE}"
    expected = _EVENT_PROPERTIES[event_name]
    actual = documented_events[event_name]
    missing = expected - actual
    extra = actual - expected
    assert not missing, (
        f"Event '{event_name}' properties missing from {DOCS_FILE}: {sorted(missing)}"
    )
    assert not extra, f"Event '{event_name}' extra/stale properties in {DOCS_FILE}: {sorted(extra)}"


def test_documented_fixed_properties_match_base_properties(
    documented_fixed_properties: frozenset[str],
) -> None:
    """Ensure the fixed properties table matches ``base_properties().keys()``."""
    expected = frozenset(base_properties().keys())
    missing = expected - documented_fixed_properties
    extra = documented_fixed_properties - expected
    assert not missing, f"Fixed telemetry properties missing from {DOCS_FILE}: {sorted(missing)}"
    assert not extra, f"Extra/stale fixed telemetry properties in {DOCS_FILE}: {sorted(extra)}"
