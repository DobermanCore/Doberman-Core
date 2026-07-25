"""RB.7: post-fetch artifact digest verification, wired into ``decide_and_execute``.

**Post-fetch only.** A PASS is granted BEFORE the fetch happens, and the RB.2b
broker relays TLS opaquely (never sees plaintext response bytes), so this
gate can only run where Doberman already sees returned tool-result content —
the same place the existing output secret-scan (parity-1) runs. These tests
drive the REAL, unstubbed ``decide_and_execute`` end to end, mirroring
``tests/unit/test_proxy_secret_output_gating.py``: the pre-execution decision
is stubbed to a deterministic PASS so only the POST-execution artifact gate
is under test.
"""

import hashlib
import json

import pytest

from doberman.models import ReasonCode
from doberman.proxy import executor
from doberman.storage.db import db_path
from doberman.storage.log import read_decisions
from tests.unit.test_proxy_taint_floor import _FakeSession, _ok_result, _pass_decision

_URL = "https://example.com/tool.tar.gz"
_CONTENT = "totally-ordinary-fetched-artifact-content"
_CONTENT_DIGEST = f"sha256:{hashlib.sha256(_CONTENT.encode('utf-8')).hexdigest()}"


@pytest.fixture(autouse=True)
def _deterministic_baseline_decision(monkeypatch):
    monkeypatch.setattr(executor, "_safe_decide", lambda action, _ctx: _pass_decision(action))


def _write_pins(repo_root, pins: dict[str, str]) -> None:
    cfg = repo_root / ".doberman"
    cfg.mkdir(parents=True, exist_ok=True)
    body = "pins:\n" + "".join(f"  {url!r}: {digest!r}\n" for url, digest in pins.items())
    (cfg / "artifact_pins.yaml").write_text(body, encoding="utf-8")


async def _rows() -> list[dict]:
    return await read_decisions(executor.REPO_ROOT)


async def test_match_content_returned_unchanged(isolated_executor_repo_root):
    _write_pins(isolated_executor_repo_root, {_URL: _CONTENT_DIGEST})
    session = _FakeSession({"http_fetch": _ok_result(_CONTENT)})

    result = await executor.decide_and_execute(session, "http_fetch", {"url": _URL})

    assert not result.isError
    assert result.content[0].text == _CONTENT
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "PASS"


async def test_mismatch_content_not_returned_to_agent(isolated_executor_repo_root):
    """The most important property: a pinned artifact whose fetched content
    disagrees with the pin must never reach the agent — a policy error comes
    back instead, and the raw content never appears in any persisted record.
    """
    wrong_digest = "sha256:" + "0" * 64
    _write_pins(isolated_executor_repo_root, {_URL: wrong_digest})
    session = _FakeSession({"http_fetch": _ok_result(_CONTENT)})

    result = await executor.decide_and_execute(session, "http_fetch", {"url": _URL})

    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert ReasonCode.artifact_digest_mismatch.value in result.content[0].text
    assert _CONTENT not in result.content[0].text
    # The downstream WAS called — this gates the RESPONSE, not the fetch itself
    # (a PASS is granted before the fetch; the broker relays TLS opaquely).
    assert session.calls == [("http_fetch", {"url": _URL})]

    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "BLOCK"
    assert ReasonCode.artifact_digest_mismatch.value in rows[0]["reason_codes_json"]
    assert rows[0]["auth_result"] == "blocked"

    # The withheld content never appears in any persisted artifact: the parsed
    # rows, nor the raw db file bytes on disk.
    assert _CONTENT not in json.dumps(rows)
    assert _CONTENT.encode() not in db_path(executor.REPO_ROOT).read_bytes()


async def test_unpinned_content_flows_unchanged(isolated_executor_repo_root):
    _write_pins(isolated_executor_repo_root, {"https://other.example.com/x": _CONTENT_DIGEST})
    session = _FakeSession({"http_fetch": _ok_result(_CONTENT)})

    result = await executor.decide_and_execute(session, "http_fetch", {"url": _URL})

    assert not result.isError
    assert result.content[0].text == _CONTENT
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "PASS"


async def test_no_pins_configured_behavior_unchanged(isolated_executor_repo_root):
    """Regression: no ``artifact_pins.yaml`` at all -> byte-for-byte identical
    to pre-RB.7 behavior (unchanged passthrough, no gate ever fires)."""
    session = _FakeSession({"http_fetch": _ok_result(_CONTENT)})

    result = await executor.decide_and_execute(session, "http_fetch", {"url": _URL})

    assert not result.isError
    assert result.content[0].text == _CONTENT
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "PASS"


async def test_verification_exception_fails_closed(isolated_executor_repo_root, monkeypatch):
    """A broken verification check must deny, never crash or silently pass
    through unverified content."""

    class _BoomStore:
        @classmethod
        def from_repo(cls, _repo_root):
            raise RuntimeError("pin store blew up")

    monkeypatch.setattr(executor, "ArtifactPinStore", _BoomStore)
    session = _FakeSession({"http_fetch": _ok_result(_CONTENT)})

    result = await executor.decide_and_execute(session, "http_fetch", {"url": _URL})

    assert result.isError
    assert "blocked by policy" in result.content[0].text
    assert _CONTENT not in result.content[0].text
    rows = await _rows()
    assert len(rows) == 1
    assert rows[0]["final_verdict"] == "BLOCK"
