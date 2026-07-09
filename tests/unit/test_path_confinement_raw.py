"""Security fix — protected-path confinement must match the RAW path.

Bug (confirmed): ``normalize`` (``doberman.proxy.normalize``) derives
``action.target`` from the REDACTED arguments, and ``_redact_value`` replaces
any string value longer than 256 chars (or secret-shaped) with the literal
``"<redacted>"``. ``ProtectedPathRule`` canonicalized and confined only
``action.target`` — so a path value over 256 chars (a long traversal, or a
long path that still resolves to a blocked/sensitive glob) became
``target="<redacted>"``, canonicalized to a harmless in-root string, and PASSed
while the executor forwarded the REAL path downstream. This defeats both the
``escapes_root`` block and the protected-path glob block.

Fix: the rule now evaluates the RAW (un-redacted) path from
``ctx.metadata['raw_arguments']`` for MATCHING when available, falling back to
``action.target``/``metadata['raw_paths']`` otherwise. The raw path is used
only for matching — it must never appear in ``action.target``, any log field,
or an explanation.
"""

from datetime import datetime, timezone

from doberman.engine.decision_engine import PASS_STUB, decide
from doberman.engine.rules.paths import ProtectedPathRule
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict
from doberman.proxy.normalize import REDACTED, normalize
from doberman.storage.log import build_record

RULE = ProtectedPathRule()

# Unique marker embedded in the raw traversal path so we can assert it never
# leaks into any redacted/logged field.
MARKER = "RAWPATHMARK7Q2K9"

# >256 chars, escapes the repo root — the headline bypass from the report.
TRAVERSAL_PATH = ("../" * 90) + f"etc/{MARKER}/passwd"

# >256 chars via "./" padding, but canonicalizes IN-root to a blocked glob.
PADDED_BLOCKED_PATH = ("./" * 130) + ".env"

# >256 chars via "./" padding, canonicalizes IN-root to a sensitive glob.
PADDED_SENSITIVE_PATH = ("./" * 130) + "backend/auth/session.ts"


def _action(target=None, *, action_type=ActionType.file_write, metadata=None):
    return SecurityObject(
        id="path-raw-1",
        ts=datetime(2026, 6, 7, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="t",
        target=target,
        metadata=metadata or {},
    )


def _normalized(tool_name: str, path: str, repo_root) -> tuple[SecurityObject, EvalContext]:
    """Build (action, ctx) exactly as the real pipeline does: normalize() for
    the (redacted) SecurityObject, a sibling EvalContext carrying the same raw
    arguments (mirrors proxy/executor.py::_build_ctx)."""
    action = normalize(tool_name, {"path": path}, {})
    ctx = EvalContext(metadata={"raw_arguments": {"path": path}, "repo_root": str(repo_root)})
    return action, ctx


# --- Sanity: confirm the redaction precondition the bug depends on ----------


def test_precondition_long_path_is_redacted_on_the_action(tmp_path):
    action, _ctx = _normalized("file_write", TRAVERSAL_PATH, tmp_path)
    assert len(TRAVERSAL_PATH) > 256
    assert action.target == REDACTED


# --- Bypass closed: the point ------------------------------------------------


def test_long_traversal_path_is_blocked_despite_redacted_target(tmp_path):
    action, ctx = _normalized("file_write", TRAVERSAL_PATH, tmp_path)
    decision = decide(action, objective=RULE, subjective=PASS_STUB, ctx=ctx)
    assert decision.final_verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in decision.reason_codes


def test_padded_path_resolving_to_blocked_glob_is_blocked(tmp_path):
    action, ctx = _normalized("file_write", PADDED_BLOCKED_PATH, tmp_path)
    assert action.target == REDACTED  # confirm redaction precondition
    result = RULE.evaluate(action, ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


def test_padded_path_resolving_to_sensitive_glob_requires_auth(tmp_path):
    action, ctx = _normalized("file_write", PADDED_SENSITIVE_PATH, tmp_path)
    assert action.target == REDACTED  # confirm redaction precondition
    result = RULE.evaluate(action, ctx)
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.sensitive_path_access in result.reason_codes


def test_batch_raw_paths_escalate_to_worst_member(tmp_path):
    # A batch delete whose SECOND raw path is a long traversal — the (short)
    # first path alone would PASS; the raw list must still catch member #2.
    raw_paths = ["frontend/a.tsx", TRAVERSAL_PATH]
    action = normalize("file_delete", {"path": raw_paths}, {})
    ctx = EvalContext(metadata={"raw_arguments": {"path": raw_paths}, "repo_root": str(tmp_path)})
    result = RULE.evaluate(action, ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


# --- Redaction preserved: raw path used only for matching --------------------


def test_raw_path_never_leaks_into_target_or_log_record(tmp_path):
    action, ctx = _normalized("file_write", TRAVERSAL_PATH, tmp_path)
    decision = decide(action, objective=RULE, subjective=PASS_STUB, ctx=ctx)
    assert MARKER not in (action.target or "")

    record = build_record(
        decision,
        action,
        auth_result=None,
        elevation_id=None,
        now=datetime.now(timezone.utc),
    )
    for value in record.values():
        assert MARKER not in str(value)


# --- No regression ------------------------------------------------------------


def test_short_env_path_still_blocks(tmp_path):
    action, ctx = _normalized("file_write", ".env", tmp_path)
    assert action.target == ".env"  # short — not redacted
    result = RULE.evaluate(action, ctx)
    assert result.verdict is Verdict.BLOCK


def test_normal_short_source_path_still_passes(tmp_path):
    action, ctx = _normalized("file_write", "frontend/Button.tsx", tmp_path)
    result = RULE.evaluate(action, ctx)
    assert result.verdict is Verdict.PASS


def test_no_raw_arguments_falls_back_to_action_target(tmp_path):
    # No raw_arguments in ctx.metadata at all -> falls back to action.target.
    ctx = EvalContext(metadata={"repo_root": str(tmp_path)})
    result = RULE.evaluate(_action(".env"), ctx)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes
