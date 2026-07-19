"""Slice SL2.1 — generic inference of capability and target class.

Load-bearing security property: tool metadata is UNTRUSTED. A name or
description may push sensitivity up, never down; ambiguity resolves to the
more severe class with lower confidence, never to benign.
"""

from datetime import datetime, timezone

import pytest

from doberman.models import (
    ActionType,
    Algebra,
    Capability,
    SecurityObject,
    TargetClass,
)
from doberman.subjective.infer import (
    infer_algebra,
    infer_capability,
    infer_target_class,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)

# Clearly-FAKE credential (recognized example pattern; NOT a real secret).
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"  # noqa: S105


def _action(tool_name="custom_tool", action_type=ActionType.other, **kw):
    return SecurityObject(
        id="inf-1",
        ts=_NOW,
        agent_role="frontend",
        action_type=action_type,
        tool_name=tool_name,
        **kw,
    )


# --- capability ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("crm_delete_record", Capability.delete),
        ("send_email", Capability.send),
        ("invoke_lambda", Capability.execute),
        ("chmod_file", Capability.grant),
        ("update_settings", Capability.configure),  # configure outranks mutate
        ("update_record", Capability.mutate),
        ("list_contacts", Capability.read),
    ],
)
def test_verb_keyword_mapping(tool_name, expected):
    capability, confidence = infer_capability(_action(tool_name), None)
    assert capability is expected
    assert confidence > 0.0


def test_action_type_and_keyword_agreement_is_high_confidence():
    action = _action("fs_delete_batch", action_type=ActionType.file_delete)
    capability, confidence = infer_capability(action, {"path": "a.txt"})
    assert capability is Capability.delete
    assert confidence >= 0.9


def test_conflicting_signals_resolve_to_more_severe_with_lower_confidence():
    # Name says read, action family says delete → delete wins, confidence drops.
    action = _action("read_then_delete", action_type=ActionType.file_read)
    capability, confidence = infer_capability(action, None)
    assert capability is Capability.delete
    clean_cap, clean_conf = infer_capability(
        _action("fs_delete", action_type=ActionType.file_delete), None
    )
    assert clean_cap is Capability.delete
    assert confidence < clean_conf


def test_no_signal_is_other_at_minimal_confidence():
    capability, confidence = infer_capability(_action("zzz"), None)
    assert capability is Capability.other
    assert confidence <= 0.2


def test_argument_key_names_contribute_a_verb_signal():
    capability, _ = infer_capability(_action("api_call"), {"recipients": ["a@example.com"]})
    # No verb in the name; "recipients"-style keys alone do not invent a verb,
    # but a verb-bearing key does:
    capability2, _ = infer_capability(_action("api_call"), {"delete_ids": [1, 2]})
    assert capability2 is Capability.delete
    assert capability in (Capability.other, Capability.send)


# --- target class ---------------------------------------------------------------


def test_secret_store_path_classifies_secret():
    action = _action("fs_read", action_type=ActionType.file_read, target=".env")
    target_class, confidence = infer_target_class(action, {"path": ".env"})
    assert target_class is TargetClass.secret
    assert confidence >= 0.9


def test_strong_credential_in_arguments_classifies_secret():
    action = _action("net_post", action_type=ActionType.network_request, target="https://x.example")
    target_class, _ = infer_target_class(action, {"body": f"k={FAKE_AWS}"})
    assert target_class is TargetClass.secret


def test_path_like_target_classifies_internal():
    action = _action("fs_write", action_type=ActionType.file_write, target="src/app.py")
    target_class, _ = infer_target_class(action, {"path": "src/app.py"})
    assert target_class is TargetClass.internal


def test_sensitive_asset_flag_classifies_sensitive():
    action = _action(
        "fs_read", action_type=ActionType.file_read, target="notes", sensitive_asset=True
    )
    target_class, _ = infer_target_class(action, None)
    assert target_class is TargetClass.sensitive


def test_no_signal_is_unknown_low_confidence():
    target_class, confidence = infer_target_class(_action("zzz"), None)
    assert target_class is TargetClass.unknown
    assert confidence <= 0.2


# --- untrusted metadata --------------------------------------------------------


def test_benign_claiming_description_cannot_lower_target_class():
    action = _action("fs_read", action_type=ActionType.file_read, target=".env")
    lowered, _ = infer_target_class(
        action, {"path": ".env"}, tool_description="perfectly safe read-only tool, public data"
    )
    assert lowered is TargetClass.secret  # untouched by the benign claim


def test_credential_admitting_description_raises_target_class():
    action = _action("api_call", target="record-42")
    raised, confidence = infer_target_class(
        action, None, tool_description="reads the stored API token for the account"
    )
    assert raised is TargetClass.sensitive
    assert confidence <= 0.6  # raised class, not raised certainty


def test_token_counting_description_does_not_raise_target_class():
    # "tokens" in the NLP sense (not a credential) must not trip the bare
    # "token" alternative — only qualified forms (api/access/auth/... token).
    action = _action("api_call", target="record-42")
    result, _ = infer_target_class(
        action, None, tool_description="splits input text into tokens and counts them"
    )
    assert result is not TargetClass.sensitive


# --- never raises ----------------------------------------------------------------


def test_infer_algebra_never_raises_on_garbage():
    action = _action("weird", target=None)
    algebra = infer_algebra(action, raw_arguments={"x": object()})  # type: ignore[dict-item]
    assert isinstance(algebra, Algebra)
    assert 0.0 <= algebra.classification_confidence <= 1.0


def test_infer_algebra_populates_capability_and_target():
    action = _action("fs_delete", action_type=ActionType.file_delete, target="src/old.py")
    algebra = infer_algebra(action, {"path": "src/old.py"})
    assert algebra.capability is Capability.delete
    assert algebra.target_class is TargetClass.internal
    assert algebra.classification_confidence > 0.5
