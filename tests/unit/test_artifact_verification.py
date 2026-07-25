"""RB.7: the pinned-digest artifact verification store.

``doberman.egress.artifact`` is the pure-logic half of post-fetch artifact
integrity — a small pinned-digest lookup with three outcomes (MATCH /
MISMATCH / UNPINNED). It never sees or logs raw content or the digest of an
unpinned artifact; only ``doberman.proxy.executor`` wires its verdicts into
the response path (covered separately by
``tests/integration/test_artifact_integrity.py``).
"""

import hashlib
import hmac

from doberman.egress import artifact
from doberman.egress.artifact import ArtifactPinStore, ArtifactVerdict, load_pins

_IDENTITY = "https://example.com/tool.tar.gz"
_CONTENT = b"totally-ordinary-artifact-bytes"
_CONTENT_DIGEST = f"sha256:{hashlib.sha256(_CONTENT).hexdigest()}"


def test_unpinned_when_no_pin_for_identity():
    store = ArtifactPinStore({})
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.unpinned


def test_match_when_digest_equals_pin():
    store = ArtifactPinStore({_IDENTITY: _CONTENT_DIGEST})
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.match


def test_mismatch_when_digest_differs():
    store = ArtifactPinStore({_IDENTITY: "sha256:" + "0" * 64})
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.mismatch


def test_mismatch_for_wrong_identity_pin_does_not_leak_into_unpinned_path():
    # A pin for a DIFFERENT identity must not affect this identity's verdict.
    store = ArtifactPinStore({"https://other.example.com/x": _CONTENT_DIGEST})
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.unpinned


def test_verify_uses_constant_time_compare(monkeypatch):
    calls = []
    real_compare = hmac.compare_digest

    def _spy(a, b):
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(artifact.hmac, "compare_digest", _spy)
    store = ArtifactPinStore({_IDENTITY: _CONTENT_DIGEST})

    result = store.verify(_IDENTITY, _CONTENT)

    assert result is ArtifactVerdict.match
    assert calls, "hmac.compare_digest was never called — verify() used a non-constant-time compare"


def test_load_pins_missing_file_returns_empty(tmp_path):
    assert load_pins(str(tmp_path)) == {}


def test_load_pins_malformed_yaml_returns_empty(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "artifact_pins.yaml").write_text("not: [a, mapping", encoding="utf-8")
    assert load_pins(str(tmp_path)) == {}


def test_load_pins_non_mapping_root_returns_empty(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "artifact_pins.yaml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    assert load_pins(str(tmp_path)) == {}


def test_load_pins_valid_file_loads_pins(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "artifact_pins.yaml").write_text(
        f"pins:\n  {_IDENTITY}: {_CONTENT_DIGEST!r}\n",
        encoding="utf-8",
    )
    pins = load_pins(str(tmp_path))
    assert pins == {_IDENTITY: _CONTENT_DIGEST}


def test_from_repo_wires_loaded_pins_into_verify(tmp_path):
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "artifact_pins.yaml").write_text(
        f"pins:\n  {_IDENTITY}: {_CONTENT_DIGEST!r}\n",
        encoding="utf-8",
    )
    store = ArtifactPinStore.from_repo(str(tmp_path))
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.match


def test_no_pins_configured_means_everything_unpinned(tmp_path):
    """Regression: no pins file at all -> every identity is UNPINNED, never MATCH/MISMATCH."""
    store = ArtifactPinStore.from_repo(str(tmp_path))
    assert store.verify(_IDENTITY, _CONTENT) is ArtifactVerdict.unpinned
    assert store.verify("https://anything.example.com/x", b"anything") is ArtifactVerdict.unpinned
