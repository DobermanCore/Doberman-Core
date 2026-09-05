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
import os

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


def test_load_pins_parses_once_for_unchanged_content(tmp_path):
    # Finding (#552): load_pins() re-read and re-parsed artifact_pins.yaml on
    # EVERY call with zero caching -- and ArtifactPinStore.from_repo() is
    # called once per decided network-fetch action from
    # proxy/executor.py's _verify_artifact_digest(). Instrumented count
    # (test-logs/issue-552-count-artifact-exclusions.py, BEFORE this fix): 20
    # decided actions -> 20 reads. Now content-keyed: the read still happens
    # every call (the file is tiny), but the expensive parse+validate must
    # run exactly once for N calls against unchanged content.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    (cfg / "artifact_pins.yaml").write_text(
        f"pins:\n  {_IDENTITY}: {_CONTENT_DIGEST!r}\n", encoding="utf-8"
    )
    artifact._parse_pins_yaml_data.cache_clear()

    for _ in range(20):
        assert load_pins(str(tmp_path)) == {_IDENTITY: _CONTENT_DIGEST}

    info = artifact._parse_pins_yaml_data.cache_info()
    assert info.misses == 1  # the real (disk-touching) parse ran exactly once
    assert info.hits == 19


def test_load_pins_picks_up_a_mid_process_pins_edit(tmp_path):
    # The cache must NOT go stale the way a naive full-process cache would: a
    # human can add/edit a pin while a long-lived process (the RB proxy) keeps
    # deciding actions, so the very next decision must see it. This
    # reproduces the real race a (path, mtime_ns) key missed (#552 review): a
    # newly ADDED pin landing in the same mtime tick as the prior read would
    # still verify UNPINNED instead of MISMATCH -- the loosening direction
    # prime directive 2 forbids. Force the rewrite to the EXACT SAME mtime
    # (coarse filesystem clock resolution can do this for real) rather than
    # dodging it with a +5s bump -- content-based keying must not depend on
    # the clock at all.
    cfg = tmp_path / ".doberman"
    cfg.mkdir()
    pins_path = cfg / "artifact_pins.yaml"
    pins_path.write_text(f"pins:\n  {_IDENTITY}: {_CONTENT_DIGEST!r}\n", encoding="utf-8")
    artifact._parse_pins_yaml_data.cache_clear()

    assert load_pins(str(tmp_path)) == {_IDENTITY: _CONTENT_DIGEST}

    other_identity = "https://other.example.com/tool.tar.gz"
    stat_before = pins_path.stat()
    pins_path.write_text(f"pins:\n  {other_identity}: {_CONTENT_DIGEST!r}\n", encoding="utf-8")
    os.utime(pins_path, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
    assert pins_path.stat().st_mtime_ns == stat_before.st_mtime_ns  # same-tick, by construction

    assert load_pins(str(tmp_path)) == {other_identity: _CONTENT_DIGEST}
