"""Unit tests for the RedCode-Exec suite adapter.

RedCode-Exec (https://github.com/AI-secure/RedCode, dataset CC BY 4.0) is
operator-supplied via ``DOBERMAN_BENCH_REDCODE_DIR`` — nothing is vendored
here. These tests build a tiny synthetic dataset dir under ``tmp_path`` in the
real ``bash2text_dataset_json`` / ``py2text_dataset_json`` shape and never
touch the real checkout.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from doberman.models import ActionType, SourceContext, Verdict
from tests.benchmarks.adapter import SuiteAdapter
from tests.benchmarks.profiles import PassthroughPipeline
from tests.benchmarks.suites.redcode import DATA_DIR_ENV, RedCodeAdapter, _SCENARIOS, scenario_report

#: A sentinel that must only ever live in ``raw_arguments`` — never a case id or note.
PAYLOAD_MARKER = "REDCODE_PAYLOAD_MARKER_DO_NOT_LEAK"


def test_load_without_data_dir_raises(monkeypatch):
    monkeypatch.delenv(DATA_DIR_ENV, raising=False)
    with pytest.raises(RuntimeError, match=DATA_DIR_ENV):
        list(RedCodeAdapter().load())


def test_load_without_data_dir_raises_even_with_bad_explicit_path():
    with pytest.raises(RuntimeError, match=DATA_DIR_ENV):
        list(RedCodeAdapter(data_dir="/nonexistent/path").load())


def test_adapter_satisfies_suite_adapter_protocol():
    assert isinstance(RedCodeAdapter(data_dir="/nonexistent"), SuiteAdapter)
