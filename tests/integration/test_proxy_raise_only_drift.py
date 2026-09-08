"""The mcp-proxy cell for row ``raise-only-drift`` -- "Policy weakening
requires the human-approved path" -- proven through a real proxy round trip
rather than by calling ``doberman.policy.drift.apply_change`` directly (see
``tests/unit/test_hosthook_raise_only_drift.py`` for the other four hosts and
``tests/integration/test_drift_gate.py`` for the CLI gate mechanism itself).

A file-write tool call targeting ``.doberman/policies.yaml`` is BLOCKed at
the chokepoint and the fake downstream never sees it; a weakening edit to
the repo-root ``doberman.policy.yaml`` is forwarded (the path is neither
control-plane nor a blocked glob) but the dropped glob stays enforced until
``doberman policy-file --accept``.
"""

import pytest
import yaml

from doberman.policy.sources import effective_policy, load_file_policy

from .test_proxy_passthrough import proxied_session


def _write_root_policy(repo_root, blocked: list[str]) -> str:
    text = yaml.safe_dump({"version": 1, "blocked": blocked}, sort_keys=False)
    (repo_root / "doberman.policy.yaml").write_text(text, encoding="utf-8")
    return text


@pytest.mark.guarantee("raise-only-drift", host="mcp-proxy")
async def test_proxy_blocks_doberman_write_and_clamps_a_weakening_edit(
    isolated_executor_repo_root,
):
    repo_root = isolated_executor_repo_root
    (repo_root / ".doberman").mkdir(parents=True, exist_ok=True)

    async with proxied_session() as (fake, agent):
        result = await agent.call_tool(
            "fs_write", {"path": ".doberman/policies.yaml", "content": "mode: light\n"}
        )
        assert result.isError
        assert fake.calls == []

        _write_root_policy(repo_root, ["a/**", "b/**"])
        load_file_policy(str(repo_root))  # adopt + pin {a/**, b/**}

        weakened = yaml.safe_dump({"version": 1, "blocked": ["a/**"]}, sort_keys=False)
        result2 = await agent.call_tool(
            "fs_write", {"path": "doberman.policy.yaml", "content": weakened}
        )
        assert not result2.isError
        assert fake.calls == [("fs_write", {"path": "doberman.policy.yaml", "content": weakened})]
        (repo_root / "doberman.policy.yaml").write_text(weakened, encoding="utf-8")

    assert "b/**" in effective_policy(str(repo_root)).blocked_globs
