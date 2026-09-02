"""Slice 1.3 — tests for normalize(): mapping, targets, redaction, fallback."""

import pytest

from doberman.models import ActionType, Risk, SourceContext
from doberman.proxy.normalize import MAX_VALUE_LENGTH, REDACTED, normalize


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("fs_read", ActionType.file_read),
        ("fs_write", ActionType.file_write),
        ("fs_delete", ActionType.file_delete),
        ("shell_exec", ActionType.shell_exec),
        ("net_get", ActionType.network_request),
        ("http_post", ActionType.network_request),
        ("git_commit", ActionType.git_op),
        ("pip_install", ActionType.package_install),
        ("npm_install_package", ActionType.package_install),
        ("totally_unknown_tool", ActionType.other),
        # Host-namespaced MCP tools classify by the tool part, not the server.
        ("mcp__filesystem__write_file", ActionType.file_write),
        ("mcp__my-shell__shell_exec", ActionType.shell_exec),
        ("mcp__Fetch__http_get", ActionType.network_request),
        ("mcp__pkg__npm_install", ActionType.package_install),
        ("mcp__x__totally_unknown", ActionType.other),
        ("mcp__noseparator", ActionType.other),
    ],
)
def test_tool_name_maps_to_action_type(tool_name, expected):
    assert normalize(tool_name, {}).action_type is expected


def test_filesystem_target_extracted():
    obj = normalize("fs_delete", {"path": "backend/auth/session.ts"})
    assert obj.target == "backend/auth/session.ts"
    assert obj.external_destination is None


def test_network_target_sets_external_destination():
    obj = normalize("net_get", {"url": "https://example.com/data"})
    assert obj.target == "https://example.com/data"
    assert obj.external_destination == "https://example.com/data"


def test_relative_url_still_extracted():
    obj = normalize("net_get", {"url": "/api/items"})
    assert obj.target == "/api/items"
    assert obj.action_type is ActionType.network_request


def test_shell_command_is_target():
    obj = normalize("shell_exec", {"command": "echo hi"})
    assert obj.target == "echo hi"


def test_shell_with_no_args():
    obj = normalize("shell_exec", {})
    assert obj.target is None
    assert obj.action_type is ActionType.shell_exec


def test_path_array_uses_representative_target_plus_count():
    obj = normalize("fs_delete", {"path": ["a.txt", "b.txt", "c.txt"]})
    assert obj.target == "a.txt"
    assert obj.metadata["target_count"] == 3


def test_non_string_path_array_yields_no_target():
    obj = normalize("fs_delete", {"path": [123, 456]})
    assert obj.target is None
    assert "target_count" not in obj.metadata


def test_defaults_role_and_source():
    obj = normalize("fs_write", {"path": "x", "content": "y"})
    assert obj.agent_role == "unknown"
    assert obj.source_context is SourceContext.unknown


def test_context_can_set_agent_role():
    obj = normalize("fs_write", {"path": "x"}, {"agent_role": "frontend_agent"})
    assert obj.agent_role == "frontend_agent"


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",  # AWS-style key id
        "sk-FAKEFAKEFAKEFAKEFAKE1234",  # api key prefix
        "ghp_FAKEFAKEFAKEFAKEFAKE12345",  # github token
        "-----BEGIN RSA PRIVATE KEY-----",  # PEM header
        "A" * (MAX_VALUE_LENGTH + 1),  # oversized blob
        "x" * 41,  # long unbroken token
    ],
)
def test_secret_shaped_values_are_redacted(secret):
    obj = normalize("fs_write", {"path": "ok.txt", "content": secret})
    assert obj.raw_args_redacted["content"] == REDACTED
    assert secret not in str(obj.raw_args_redacted)


@pytest.mark.parametrize("key", ["password", "PASSWORD", "api_key", "apiKey_token", "secret"])
def test_sensitive_keys_redacted_regardless_of_value(key):
    obj = normalize("net_get", {"url": "https://x.test", key: "hunter2"})
    assert obj.raw_args_redacted[key] == REDACTED


def test_benign_values_pass_through():
    obj = normalize("fs_write", {"path": "a.txt", "content": "hello world", "append": True})
    assert obj.raw_args_redacted == {"path": "a.txt", "content": "hello world", "append": True}


def test_nested_structures_are_redacted():
    secret = "ghp_FAKEFAKEFAKEFAKEFAKE12345"  # noqa: S105 — synthetic test value
    obj = normalize(
        "net_get",
        {"url": "https://x.test", "headers": {"Authorization": secret}, "tags": [secret, "ok"]},
    )
    assert obj.raw_args_redacted["headers"]["Authorization"] == REDACTED
    assert obj.raw_args_redacted["tags"] == [REDACTED, "ok"]
    assert secret not in str(obj.raw_args_redacted)


def test_authorization_header_redacted_even_when_short():
    obj = normalize("net_get", {"url": "https://x.test", "headers": {"Authorization": "hunter2"}})
    assert obj.raw_args_redacted["headers"]["Authorization"] == REDACTED


def test_target_gets_same_redaction_as_args():
    # A secret-shaped value used as the target must not survive into
    # target/external_destination either.
    secret_url = "https://x.test/cb?token=ghp_FAKEFAKEFAKEFAKEFAKE12345"  # noqa: S105
    obj = normalize("net_get", {"url": secret_url})
    assert obj.target == REDACTED
    assert obj.external_destination == REDACTED
    assert "ghp_" not in str(obj)

    long_path = "p" * (MAX_VALUE_LENGTH + 1)
    obj = normalize("fs_delete", {"path": long_path})
    assert obj.target == REDACTED


def test_deeply_nested_structures_redacted_wholesale():
    value: dict = {"v": "benign"}
    for _ in range(30):
        value = {"nested": value}
    obj = normalize("net_get", {"url": "https://x.test", "payload": value})
    assert REDACTED in str(obj.raw_args_redacted["payload"])


def test_unknown_value_types_never_pass_through_raw():
    class Weird:
        def __repr__(self) -> str:
            return "raw-internal-state"

    obj = normalize("fs_write", {"path": "a.txt", "blob": Weird()})
    assert obj.raw_args_redacted["blob"] == REDACTED


def test_malformed_input_produces_conservative_object():
    # arguments that are not a mapping at all
    obj = normalize(None, "not-a-dict")  # type: ignore[arg-type]
    assert obj.action_type is ActionType.other
    assert obj.risk is Risk.high
    assert "normalization_failed" in obj.metadata["reason_codes"]
    assert obj.raw_args_redacted == {}  # nothing copied on failure
    assert "not-a-dict" not in str(obj)


def test_each_call_gets_unique_id_and_aware_ts():
    a = normalize("fs_write", {"path": "x"})
    b = normalize("fs_write", {"path": "x"})
    assert a.id != b.id
    assert a.ts.tzinfo is not None
