"""Slice 5.1 — capability enumeration (read-only).

Covers: tool-derived capability detection; sensitive-surface detection by
name/existence (.env, secrets/, key material); that secret *contents* are never
read; the depth bound; and graceful handling of an empty tool list / missing path.
"""

from doberman.discovery.scan import Capability, enumerate_capabilities

FAKE_SECRET = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105 — synthetic AWS example key


def _by_name(caps: list[Capability]) -> dict[str, Capability]:
    return {c.name: c for c in caps}


def test_tool_capabilities_detected_from_tool_names(tmp_path):
    caps = _by_name(
        enumerate_capabilities(["shell_exec", "fs_write", "net_get", "git_push"], str(tmp_path))
    )
    assert caps["shell"].present
    assert caps["filesystem_write"].present
    assert caps["network"].present
    assert caps["git"].present
    assert caps["git_push"].present
    # No read/delete tool was offered.
    assert not caps["filesystem_read"].present
    assert not caps["filesystem_delete"].present


def test_empty_tool_list_yields_no_tool_capabilities(tmp_path):
    caps = _by_name(enumerate_capabilities([], str(tmp_path)))
    assert not caps["shell"].present
    assert not caps["network"].present


def test_dotenv_detected_by_name_without_reading_contents(tmp_path):
    (tmp_path / ".env").write_text(f"AWS_SECRET={FAKE_SECRET}\n", encoding="utf-8")
    caps = _by_name(enumerate_capabilities([], str(tmp_path)))
    assert caps["dotenv_visible"].present
    assert any(".env" in e for e in caps["dotenv_visible"].evidence)
    # The secret VALUE must never appear in the evidence (we detect by name only).
    assert all(FAKE_SECRET not in e for e in caps["dotenv_visible"].evidence)


def test_secrets_dir_and_key_material_detected(tmp_path):
    (tmp_path / "secrets").mkdir()
    (tmp_path / "deploy.pem").write_text("not-a-real-key", encoding="utf-8")
    caps = _by_name(enumerate_capabilities([], str(tmp_path)))
    assert caps["secrets_dir"].present
    assert caps["secret_files"].present


def test_scan_is_depth_bounded(tmp_path):
    # A .env buried far deeper than the depth bound must not be discovered.
    deep = tmp_path
    for i in range(12):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / ".env").write_text("X=1", encoding="utf-8")
    caps = _by_name(enumerate_capabilities([], str(tmp_path)))
    assert not caps["dotenv_visible"].present


def test_missing_path_does_not_crash(tmp_path):
    caps = _by_name(enumerate_capabilities([], str(tmp_path / "does-not-exist")))
    assert not caps["dotenv_visible"].present


def test_secret_contents_never_appear_anywhere(tmp_path):
    (tmp_path / ".env").write_text(f"KEY={FAKE_SECRET}\n", encoding="utf-8")
    caps = enumerate_capabilities(["shell_exec"], str(tmp_path))
    blob = " ".join(e for c in caps for e in c.evidence)
    assert FAKE_SECRET not in blob
