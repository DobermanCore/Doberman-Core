"""The Codex plugin package stays in sync with the CLI installer (W1.4).

The plugin-bundled ``hooks.json`` and the config-channel installer
(``doberman install-hooks --host codex``) must register the **same** PreToolUse
group, or the two install channels would drift. This test locks that, and
validates the plugin manifest against the fields Codex requires.
"""

import json
from pathlib import Path

from doberman.hosthooks.install_codex import CODEX_PRE_ENTRY

ADAPTER = Path(__file__).resolve().parents[2] / "adapters" / "codex"
HOOKS = ADAPTER / "hooks.json"
MANIFEST = ADAPTER / ".codex-plugin" / "plugin.json"


def test_plugin_hooks_match_installer_entry():
    data = json.loads(HOOKS.read_text(encoding="utf-8"))
    pre_groups = data["hooks"]["PreToolUse"]
    assert CODEX_PRE_ENTRY in pre_groups, (
        "the plugin's PreToolUse group must be byte-identical to what "
        "`install-hooks --host codex` writes (install_codex.CODEX_PRE_ENTRY) — "
        "otherwise the two channels drift"
    )


def test_plugin_manifest_is_valid_and_complete():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for field in ("name", "version", "description", "license", "hooks", "interface"):
        assert field in manifest, f"plugin.json missing required field: {field}"
    assert manifest["name"] == "doberman"
    assert manifest["hooks"] == "./hooks.json"
    iface = manifest["interface"]
    for field in ("displayName", "shortDescription", "capabilities", "brandColor"):
        assert field in iface, f"plugin.json interface missing: {field}"
    assert isinstance(iface["capabilities"], list) and iface["capabilities"]
    # brandColor must be #RRGGBB (a Codex validation rule).
    assert iface["brandColor"].startswith("#") and len(iface["brandColor"]) == 7
