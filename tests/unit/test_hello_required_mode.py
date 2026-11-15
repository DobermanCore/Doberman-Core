"""Hello-required mode (ADR 0119 slice 2): a machine marker turns the proof tier into a
Windows Hello gesture, and TOTP is refused on every channel.

Runs on Linux CI: the marker path comes from the test-only ``DOBERMAN_HELLO_MARKER``
override, the machine marker locations are emptied, and a fake ``HelloBackend`` stands in
for WinRT. Every "refused" test uses a VALID TOTP code, so a pass means the mode refused
it, not that the code was wrong.
"""

import asyncio
import base64
import json

import click
import pyotp
import pytest
from typer.testing import CliRunner

from doberman.auth import async_challenge, dashboard_prompter, hello_mode, password, totp
from doberman.auth.approval import ApprovalOutcome
from doberman.auth.challenge import AuthTier, _current_challenge
from doberman.auth.gui_prompter import PrompterUnavailableError
from doberman.auth.methods.windows_hello import HelloError, HelloVerdict
from doberman.auth.provider import LocalAuthProvider
from doberman.cli import doctor
from doberman.cli.main import app
from doberman.hosthooks import hookio
from doberman.models import ReasonCode, Risk
from doberman.policy import drift
from doberman.storage import approvals
from doberman.storage.heartbeat import touch_heartbeat
from tests.unit._hello_rsa import keypair
from tests.unit.test_async_challenge import _action as _async_action
from tests.unit.test_async_challenge import _auth_decision as _async_decision
from tests.unit.test_auth_provider import _action
from tests.unit.test_auth_provider import _auth_decision as _decision

_KEY = keypair("a")
_PUBKEY = _KEY.public_key


class FakeBackend:
    """A Hello key in software. ``verdict``/``available``/``raises`` make signing fail the
    ways a real gesture can; ``prompts`` records every message it was asked to sign."""

    def __init__(self, *, available=True, verdict=HelloVerdict.verified, raises=None, tpm=True):
        self._available = available
        self._verdict = verdict
        self._raises = raises
        self._tpm = tpm
        self.prompts: list[bytes] = []
        self.key_ensured = False

    def available(self):
        if isinstance(self._available, BaseException):
            raise self._available
        return self._available

    def ensure_key(self):
        self.key_ensured = True

    def sign(self, data, *, timeout_s=None):
        self.prompts.append(data)
        if self.available() is not True:
            raise HelloError("Hello is not available")
        if self._raises is not None:
            raise self._raises
        if self._verdict is not HelloVerdict.verified:
            raise HelloError(f"signing refused: {self._verdict.value}")
        return _KEY.sign(data)

    def public_key(self):
        return _PUBKEY

    def tpm_backed(self):
        return self._tpm


class CodePrompter:
    """Answers yes and hands over a VALID TOTP code: what a phone, dashboard or
    script that holds the secret would do."""

    def __init__(self):
        self.asked: list[str] = []

    def confirm(self, message):
        self.asked.append("confirm")
        return True

    def read_code(self, message):
        self.asked.append("code")
        return _valid_code()


def _valid_code() -> str:
    return pyotp.TOTP(totp.resolve_path().read_text().strip()).now()


def _write_marker(path, **overrides):
    body = {
        "version": 1,
        "public_key": base64.b64encode(_PUBKEY).decode(),
        "enrolled_at": "2026-11-14T00:00:00+00:00",
    }
    body.update(overrides)
    path.write_text(json.dumps(body), encoding="utf-8")


@pytest.fixture
def marker(tmp_path, monkeypatch):
    """The marker path (absent). No machine-wide locations, so only the override counts."""
    path = tmp_path / "proof.json"
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(path))
    return path


@pytest.fixture
def mode_on(marker):
    _write_marker(marker)
    return marker


@pytest.fixture
def backend(monkeypatch):
    holder = {"b": FakeBackend()}
    monkeypatch.setattr(hello_mode, "backend", lambda: holder["b"])

    def _set(**kwargs):
        holder["b"] = FakeBackend(**kwargs)
        return holder["b"]

    _set.current = lambda: holder["b"]
    return _set


@pytest.fixture
def enrolled_totp():
    """A real TOTP secret on disk (written directly, so it works with the mode already on)."""
    path = totp.resolve_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pyotp.random_base32(), encoding="ascii")
    return path


# --- the marker ------------------------------------------------------------------------


def test_no_marker_anywhere_is_off(monkeypatch):
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    assert hello_mode.mode() is hello_mode.Mode.off
    assert hello_mode.is_on() is False


def test_absent_override_file_is_off(marker):
    assert hello_mode.mode() is hello_mode.Mode.off


def test_valid_marker_is_on(mode_on):
    assert hello_mode.mode() is hello_mode.Mode.on
    assert hello_mode.is_on() is True


@pytest.mark.parametrize(
    "content",
    [
        "",
        "not json",
        "[]",
        '{"version": 1}',
        '{"version": 2, "public_key": "AAAA", "enrolled_at": "x"}',
        '{"version": 1, "public_key": "!!!not-base64!!!", "enrolled_at": "x"}',
        '{"version": 1, "public_key": "", "enrolled_at": "x"}',
        '{"version": 1, "public_key": "AAAA"}',
    ],
)
def test_corrupt_marker_is_on_not_off(marker, content):
    marker.write_text(content, encoding="utf-8")
    assert hello_mode.mode() is hello_mode.Mode.corrupt
    assert hello_mode.is_on() is True


def test_marker_that_is_a_directory_is_corrupt(marker):
    marker.mkdir()
    assert hello_mode.mode() is hello_mode.Mode.corrupt


def test_unreadable_marker_is_corrupt(mode_on, monkeypatch):
    def _deny(self, *a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(type(mode_on), "read_bytes", _deny)
    assert hello_mode.mode() is hello_mode.Mode.corrupt


def test_override_cannot_mask_a_machine_marker(tmp_path, monkeypatch):
    machine = tmp_path / "machine-proof.json"
    _write_marker(machine)
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [machine])
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(tmp_path / "absent.json"))
    assert hello_mode.is_on() is True


def test_locating_the_marker_failing_means_on(monkeypatch):
    def _boom():
        raise OSError("no known folder")

    monkeypatch.setattr(hello_mode, "_machine_marker_paths", _boom)
    assert hello_mode.is_on() is True


# --- provider (_run_tier) ----------------------------------------------------------------


def _authenticate(tier, prompter=None):
    return LocalAuthProvider().authenticate(
        _decision(), _action(), tier, prompter=prompter or CodePrompter()
    )


@pytest.mark.parametrize("tier", [AuthTier.two_factor, AuthTier.role_elevation])
def test_provider_refuses_a_valid_totp_code_in_the_mode(mode_on, enrolled_totp, backend, tier):
    backend(available=False)
    prompter = CodePrompter()
    result = _authenticate(tier, prompter)
    assert result.approved is False
    assert result.method == hello_mode.HELLO_REQUIRED_METHOD
    assert prompter.asked == ["confirm"]  # shown the action, never asked for a code


def test_provider_valid_totp_still_works_with_the_mode_off(marker, enrolled_totp, backend):
    result = _authenticate(AuthTier.two_factor)
    assert result.approved is True
    assert result.method == "totp"
    assert backend.current().prompts == []


@pytest.mark.parametrize(
    ("tier", "method"),
    [(AuthTier.two_factor, "windows_hello"), (AuthTier.role_elevation, "windows_hello+elevation")],
)
def test_provider_hello_gesture_approves_in_the_mode(mode_on, backend, tier, method):
    prompter = CodePrompter()
    result = _authenticate(tier, prompter)
    assert result.approved is True
    assert result.method == method
    assert prompter.asked == ["confirm"]  # the action is shown before the gesture
    assert backend.current().prompts[0].startswith(b"doberman-proof-v1\naction_id=act-7\n")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"available": False},
        {"available": RuntimeError("check failed")},
        {"verdict": HelloVerdict.cancelled},
        {"verdict": HelloVerdict.unavailable},
        {"raises": TimeoutError()},
        {"raises": RuntimeError("prompt could not show")},
    ],
)
def test_provider_any_hello_failure_denies(mode_on, enrolled_totp, backend, kwargs):
    backend(**kwargs)
    result = _authenticate(AuthTier.two_factor)
    assert result.approved is False


def test_provider_backend_construction_failing_denies(mode_on, monkeypatch):
    def _boom():
        raise ImportError("no winrt")

    monkeypatch.setattr(hello_mode, "backend", _boom)
    assert _authenticate(AuthTier.two_factor).approved is False


def test_provider_ignores_an_enabled_approval_method_in_the_mode(mode_on, backend, monkeypatch):
    class AlwaysYes:
        name = "phone"

        def is_available(self):
            return True

        def request(self, prompt, *, action_id, timeout_s):
            return ApprovalOutcome.approved

    monkeypatch.setattr("doberman.auth.provider.resolve_approval_method", lambda: AlwaysYes())
    backend(available=False)
    assert _authenticate(AuthTier.two_factor).approved is False


def test_provider_lower_tiers_are_unchanged_in_the_mode(mode_on, backend):
    prompter = CodePrompter()
    result = _authenticate(AuthTier.local_auth, prompter)
    assert result.approved is True
    assert prompter.asked == ["confirm"]
    assert backend.current().prompts == []


# --- totp itself ---------------------------------------------------------------------------


def test_planted_totp_secret_is_ignored_in_the_mode(marker, enrolled_totp):
    code = _valid_code()
    _write_marker(marker)
    assert totp.verify(code) is False
    marker.unlink()
    assert totp.verify(code) is True  # the same step was never claimed while refused


def test_totp_setup_refuses_in_the_mode(mode_on):
    with pytest.raises(RuntimeError, match="Hello-required"):
        totp.enroll()
    assert not totp.resolve_path().exists()


# --- async challenges ----------------------------------------------------------------------


_REASON_FOR_TIER = {
    AuthTier.local_auth: ReasonCode.sensitive_path_access,
    AuthTier.two_factor: ReasonCode.policy_source_sensitive,
    AuthTier.role_elevation: ReasonCode.role_out_of_scope,
}


def _issue(tier=AuthTier.two_factor):
    be = async_challenge.InMemoryAsyncBackend()
    decision = _async_decision(reasons=(_REASON_FOR_TIER[tier],))
    handle = async_challenge.issue_challenge(decision, _async_action(), backend=be)
    assert handle.tier is tier
    return be, handle


def test_async_resolve_refuses_a_valid_totp_code_in_the_mode(mode_on, enrolled_totp):
    be, handle = _issue()
    result = async_challenge.resolve_challenge(
        handle, approved=True, totp_code=_valid_code(), backend=be
    )
    assert result.approved is False
    assert result.method == hello_mode.HELLO_REQUIRED_METHOD


def test_async_backend_resolve_refuses_a_valid_totp_code_in_the_mode(mode_on, enrolled_totp):
    be, handle = _issue(AuthTier.role_elevation)
    result = be.resolve(handle, approved=True, totp_code=_valid_code())
    assert result.approved is False


def test_async_lower_tier_unchanged_in_the_mode(mode_on):
    be, handle = _issue(AuthTier.local_auth)
    assert async_challenge.resolve_challenge(handle, approved=True, backend=be).approved is True


# --- dashboard -----------------------------------------------------------------------------


def test_dashboard_never_queues_a_proof_tier_row_in_the_mode(mode_on, tmp_path):
    repo = str(tmp_path)
    touch_heartbeat(repo)
    prompter = dashboard_prompter.DashboardPrompter(repo, timeout_s=0.01, poll_interval_s=0.01)
    token = _current_challenge.set((_decision(), _action(), AuthTier.two_factor))
    try:
        with pytest.raises(PrompterUnavailableError, match="Windows Hello"):
            prompter.confirm("approve?")
    finally:
        _current_challenge.reset(token)
    assert asyncio.run(approvals.list_pending(repo_root=repo)) == []


# --- policy weaken gate --------------------------------------------------------------------


def test_weaken_gate_refuses_a_valid_totp_code_in_the_mode(mode_on, enrolled_totp, backend):
    backend(available=False)
    approved, method = drift._run_weaken_gate({"a": 1}, {"a": 0}, "r", CodePrompter())
    assert approved is False
    assert method == hello_mode.HELLO_REQUIRED_METHOD


def test_weaken_gate_refuses_the_password_in_the_mode(mode_on, backend):
    password.enroll("correct horse battery staple")

    class PwPrompter(CodePrompter):
        def read_code(self, message):
            return "correct horse battery staple"

    backend(available=False)
    assert drift._run_weaken_gate({"a": 1}, {"a": 0}, "r", PwPrompter())[0] is False


def test_weaken_gate_hello_gesture_approves_in_the_mode(mode_on, backend):
    approved, method = drift._run_weaken_gate({"a": 1}, {"a": 0}, "r", CodePrompter())
    assert (approved, method) == (True, "windows_hello")


def test_weaken_precheck_lets_hello_be_the_factor(mode_on, backend):
    from doberman.policy.drift import Classification

    result = asyncio.run(
        drift._run_gate_if_weaken({"a": 1}, {"a": 0}, "r", Classification.weaken, CodePrompter())
    )
    assert result == (True, "windows_hello")


# --- host-hook deny message ----------------------------------------------------------------


def test_hook_deny_message_names_the_hello_fix(mode_on):
    text = hookio._auth_denied_reason(
        _decision(), channel_error=False, method=hello_mode.HELLO_REQUIRED_METHOD
    )
    assert "Windows Hello" in text
    assert "2fa setup" not in text


# --- CLI: enroll / leave -------------------------------------------------------------------


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "is_elevated", lambda: True)


def _cli(args, input_text=""):
    result = CliRunner().invoke(app, args, input=input_text, env={"NO_COLOR": "1"})
    return result, click.unstyle(result.output)


def test_enroll_writes_the_marker_and_deletes_the_secret(marker, windows, backend, enrolled_totp):
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 0, out
    data = json.loads(marker.read_text(encoding="utf-8"))
    assert base64.b64decode(data["public_key"]) == _PUBKEY
    assert data["enrolled_at"]
    assert hello_mode.mode() is hello_mode.Mode.on
    assert not enrolled_totp.exists()
    assert backend.current().key_ensured


@pytest.mark.parametrize("tpm", [None, False])
def test_enroll_refuses_without_a_tpm_key(marker, windows, backend, enrolled_totp, tpm):
    backend(tpm=tpm)
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 1
    assert "TPM" in out
    assert not marker.exists() and enrolled_totp.exists()


def test_enroll_refuses_a_key_whose_signature_does_not_verify(
    marker, windows, backend, enrolled_totp, monkeypatch
):
    # e.g. a key type or signature scheme the verifier does not support: never pinned
    monkeypatch.setattr(backend.current(), "public_key", lambda: keypair("b").public_key)
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 1
    assert "did not verify" in out
    assert not marker.exists() and enrolled_totp.exists()


def test_enroll_signs_a_probe_with_the_key_it_pins(marker, windows, backend, enrolled_totp):
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 0, out
    assert backend.current().prompts[0].startswith(b"doberman-proof-v1\naction_id=hello-enroll\n")


def test_enroll_refuses_a_wrong_totp_code(marker, windows, backend, enrolled_totp):
    good = _valid_code()
    bad = "000000" if good != "000000" else "111111"
    result, _ = _cli(["2fa", "hello", "enroll"], bad + "\n")
    assert result.exit_code == 1
    assert not marker.exists() and enrolled_totp.exists()
    assert backend.current().prompts == []


def test_enroll_refuses_without_totp_enrolled(marker, windows, backend):
    result, out = _cli(["2fa", "hello", "enroll"])
    assert result.exit_code == 1
    assert "2fa setup" in out
    assert not marker.exists()


def test_enroll_refuses_unelevated_and_prints_the_command(
    marker, windows, backend, enrolled_totp, monkeypatch
):
    monkeypatch.setattr(hello_mode, "is_elevated", lambda: False)
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 1
    assert "administrator" in out.lower()
    assert "doberman 2fa hello enroll" in out
    assert not marker.exists() and enrolled_totp.exists()


def test_enroll_refuses_on_hello_cancel(marker, windows, backend, enrolled_totp):
    backend(verdict=HelloVerdict.cancelled)
    result, _ = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 1
    assert not marker.exists() and enrolled_totp.exists()


def test_enroll_refuses_when_already_on(mode_on, windows, backend, enrolled_totp):
    result, out = _cli(["2fa", "hello", "enroll"], "123456\n")
    assert result.exit_code == 1
    assert "already" in out


@pytest.mark.parametrize("cmd", ["enroll", "leave"])
def test_hello_commands_refuse_off_windows(marker, backend, monkeypatch, cmd):
    monkeypatch.setattr(hello_mode, "supported", lambda: False)
    result, out = _cli(["2fa", "hello", cmd])
    assert result.exit_code == 1
    assert "Windows" in out


def test_leave_removes_the_marker_after_a_gesture(mode_on, windows, backend):
    result, out = _cli(["2fa", "hello", "leave"])
    assert result.exit_code == 0, out
    assert not mode_on.exists()
    assert "doberman 2fa setup" in out
    assert backend.current().prompts


def test_leave_without_a_gesture_keeps_the_mode(mode_on, windows, backend):
    backend(verdict=HelloVerdict.cancelled)
    result, _ = _cli(["2fa", "hello", "leave"])
    assert result.exit_code == 1
    assert mode_on.exists()


def test_leave_unelevated_keeps_the_mode(mode_on, windows, backend, monkeypatch):
    monkeypatch.setattr(hello_mode, "is_elevated", lambda: False)
    result, _ = _cli(["2fa", "hello", "leave"])
    assert result.exit_code == 1
    assert mode_on.exists()
    assert backend.current().prompts == []


# --- doctor --------------------------------------------------------------------------------


def _hello_check():
    return doctor._safe_check("Hello mode", False, doctor._check_hello_mode)


def test_doctor_runs_the_hello_check_in_the_auth_section(tmp_path, monkeypatch):
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    names = [r.name for r in doctor.run_checks(str(tmp_path))]
    assert names.index("Hello mode") == names.index("Password") + 1


def test_doctor_reports_off(monkeypatch):
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [])
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    check = _hello_check()
    assert check.status is doctor.CheckStatus.OK
    assert check.detail.startswith("off")


def test_doctor_reports_on_and_warns_about_the_override(mode_on):
    check = _hello_check()
    assert check.status is doctor.CheckStatus.WARN
    assert check.detail.startswith("on")
    assert hello_mode.MARKER_ENV in check.detail
    assert check.detail.isascii()


def test_doctor_reports_on_without_override(tmp_path, monkeypatch):
    machine = tmp_path / "proof.json"
    _write_marker(machine)
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [machine])
    monkeypatch.setattr(hello_mode, "_owner_sid", lambda d: hello_mode.ADMINS_SID)
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    check = _hello_check()
    assert (check.status, check.detail.split()[0]) == (doctor.CheckStatus.OK, "on:")


def test_doctor_fails_on_a_corrupt_marker(marker):
    marker.write_text("garbage", encoding="utf-8")
    check = _hello_check()
    assert check.status is doctor.CheckStatus.FAIL
    assert check.detail.startswith("corrupt")


def test_doctor_fails_when_a_totp_secret_reappears(mode_on):
    totp.resolve_path().write_text("JBSWY3DPEHPK3PXP", encoding="utf-8")
    check = _hello_check()
    assert check.status is doctor.CheckStatus.FAIL
    assert "ignored" in check.detail


# --- WinRT ensure_key over stub modules ----------------------------------------------------


def _stub_key_manager(monkeypatch, *, open_status, create_status="SUCCESS"):
    from doberman.auth.methods import windows_hello

    class _St:
        def __init__(self, name):
            self.status = type("E", (), {"name": name})()

    class KeyCredentialManager:
        created: list[tuple[str, object]] = []

        @staticmethod
        async def open_async(name):
            return _St(open_status)

        @staticmethod
        async def request_create_async(name, option):
            KeyCredentialManager.created.append((name, option))
            return _St(create_status)

    options = type("Opt", (), {"FAIL_IF_EXISTS": "fail-if-exists"})
    cred = type("cred", (), {"KeyCredentialManager": KeyCredentialManager})
    cred.KeyCredentialCreationOption = options
    monkeypatch.setattr(windows_hello, "_load_winrt", lambda: (object(), cred))
    return KeyCredentialManager


def test_ensure_key_creates_a_missing_key_without_replacing(monkeypatch):
    from doberman.auth.methods.windows_hello import KEY_NAME, WinRTHelloBackend

    mgr = _stub_key_manager(monkeypatch, open_status="NOT_FOUND")
    WinRTHelloBackend().ensure_key()
    assert mgr.created == [(KEY_NAME, "fail-if-exists")]


def test_ensure_key_keeps_an_existing_key(monkeypatch):
    from doberman.auth.methods.windows_hello import WinRTHelloBackend

    mgr = _stub_key_manager(monkeypatch, open_status="SUCCESS")
    WinRTHelloBackend().ensure_key()
    assert mgr.created == []


@pytest.mark.parametrize(
    ("open_status", "create_status"),
    [("NOT_FOUND", "USER_CANCELED"), ("SECURITY_DEVICE_LOCKED", "SUCCESS")],
)
def test_ensure_key_failure_raises(monkeypatch, open_status, create_status):
    from doberman.auth.methods.windows_hello import HelloError, WinRTHelloBackend

    _stub_key_manager(monkeypatch, open_status=open_status, create_status=create_status)
    with pytest.raises(HelloError):
        WinRTHelloBackend().ensure_key()


def test_ensure_key_without_winrt_raises(monkeypatch):
    from doberman.auth.methods import windows_hello

    monkeypatch.setattr(windows_hello, "_load_winrt", lambda: None)
    with pytest.raises(windows_hello.HelloError):
        windows_hello.WinRTHelloBackend().ensure_key()


# --- machine marker locations --------------------------------------------------------------


#: Captured at import, before the conftest stub replaces it for each test.
_REAL_MACHINE_PATHS = hello_mode._machine_marker_paths


@pytest.fixture
def real_locations(monkeypatch):
    """Run the real lookup (each test fakes the known folder and the environment)."""
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", _REAL_MACHINE_PATHS)


def test_no_machine_locations_off_windows(real_locations, monkeypatch):
    monkeypatch.setattr(hello_mode, "supported", lambda: False)
    assert hello_mode._machine_marker_paths() == []


def test_machine_locations_check_known_folder_and_env(real_locations, monkeypatch, tmp_path):
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: tmp_path / "known")
    monkeypatch.setenv("ProgramData", str(tmp_path / "env"))
    assert hello_mode._machine_marker_paths() == [
        tmp_path / "known" / "doberman" / "proof.json",
        tmp_path / "env" / "doberman" / "proof.json",
    ]
    monkeypatch.setenv("ProgramData", str(tmp_path / "known"))
    assert len(hello_mode._machine_marker_paths()) == 1


def test_machine_locations_unknown_is_an_error_so_the_mode_is_on(real_locations, monkeypatch):
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: None)
    monkeypatch.delenv("ProgramData", raising=False)
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    assert hello_mode.is_on() is True


def test_override_is_the_admin_path_only_without_a_machine_location(marker):
    assert hello_mode.admin_marker_path() == marker


def test_machine_location_is_the_admin_path(real_locations, monkeypatch, tmp_path):
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: tmp_path)
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    assert hello_mode.admin_marker_path() == tmp_path / "doberman" / "proof.json"


def test_override_with_a_machine_location_is_refused(real_locations, monkeypatch, tmp_path):
    """A script can `setx` the override; an elevated terminal would inherit it."""
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: tmp_path)
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(tmp_path / "user" / "o.json"))
    with pytest.raises(hello_mode.HelloModeError, match=hello_mode.MARKER_ENV):
        hello_mode.admin_marker_path()


@pytest.fixture
def machine_dir(tmp_path, monkeypatch):
    """A machine marker location with the Windows security helpers faked."""
    target = tmp_path / "ProgramData" / "doberman" / "proof.json"
    target.parent.parent.mkdir()
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [target])
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: target.parent.parent)
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    calls: dict[str, list] = {"created": [], "acl": []}
    owner = {"sid": hello_mode.ADMINS_SID}

    def _create(d):
        d.mkdir()
        calls["created"].append(d)

    monkeypatch.setattr(hello_mode, "_create_secure_dir", _create)
    monkeypatch.setattr(hello_mode, "_apply_marker_acl", lambda d: calls["acl"].append(d))
    monkeypatch.setattr(hello_mode, "_owner_sid", lambda d: owner["sid"])
    monkeypatch.setattr(hello_mode, "_is_reparse_point", lambda d: False)
    return target, calls, owner


def test_machine_marker_dir_is_created_with_its_security(machine_dir):
    target, calls, _ = machine_dir
    hello_mode.write_marker(target, _PUBKEY)
    assert calls["created"] == [target.parent]
    assert hello_mode._state_of(target) is hello_mode.Mode.on


def test_existing_admin_owned_dir_gets_the_acl_reapplied(machine_dir):
    target, calls, _ = machine_dir
    target.parent.mkdir()
    hello_mode.write_marker(target, _PUBKEY)
    assert calls == {"created": [], "acl": [target.parent]}
    assert hello_mode._state_of(target) is hello_mode.Mode.on


def test_dir_a_user_created_first_is_refused(machine_dir):
    target, calls, owner = machine_dir
    target.parent.mkdir()
    owner["sid"] = "S-1-5-21-1-2-3-1001"
    with pytest.raises(hello_mode.HelloModeError, match="not owned by Administrators"):
        hello_mode.write_marker(target, _PUBKEY)
    assert not target.exists() and calls["acl"] == []


def test_dir_that_is_a_reparse_point_is_refused(machine_dir, monkeypatch):
    target, calls, _ = machine_dir
    target.parent.mkdir()
    monkeypatch.setattr(hello_mode, "_is_reparse_point", lambda d: True)
    with pytest.raises(hello_mode.HelloModeError, match="reparse point"):
        hello_mode.write_marker(target, _PUBKEY)
    assert not target.exists() and calls["acl"] == []


def test_dir_securing_failure_writes_nothing(machine_dir, monkeypatch):
    target, _, _ = machine_dir

    def _fail(d):
        raise OSError("CreateDirectoryW failed")

    monkeypatch.setattr(hello_mode, "_create_secure_dir", _fail)
    with pytest.raises(OSError):
        hello_mode.write_marker(target, _PUBKEY)
    assert not target.exists()


def test_a_planted_tmp_file_is_never_reused(machine_dir):
    target, _, _ = machine_dir
    target.parent.mkdir()
    planted = target.with_name(target.name + ".tmp")
    planted.write_text("planted", encoding="utf-8")
    with pytest.raises(FileExistsError):
        hello_mode.write_marker(target, _PUBKEY)
    assert planted.read_text(encoding="utf-8") == "planted"
    assert not target.exists()


def test_reparse_check_sees_a_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("cannot create a symlink here")
    assert hello_mode._is_reparse_point(link) is True
    assert hello_mode._is_reparse_point(real) is False


@pytest.mark.parametrize("cmd", ["enroll", "leave"])
def test_cli_refuses_while_the_override_is_set_on_a_machine(
    machine_dir, windows, backend, enrolled_totp, monkeypatch, tmp_path, cmd
):
    target, _, _ = machine_dir
    if cmd == "leave":
        target.parent.mkdir()
        _write_marker(target)
    user_marker = tmp_path / "user" / "proof.json"
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(user_marker))
    result, out = _cli(["2fa", "hello", cmd], _valid_code() + "\n")
    assert result.exit_code == 1
    assert hello_mode.MARKER_ENV in out
    assert not user_marker.exists()
    assert enrolled_totp.exists()
    assert target.exists() is (cmd == "leave")


def test_cli_enroll_writes_only_the_machine_path(machine_dir, windows, backend, enrolled_totp):
    target, calls, _ = machine_dir
    result, out = _cli(["2fa", "hello", "enroll"], _valid_code() + "\n")
    assert result.exit_code == 0, out
    assert hello_mode._state_of(target) is hello_mode.Mode.on
    assert calls["created"] == [target.parent]
    assert not enrolled_totp.exists()


@pytest.mark.parametrize("problem", ["reparse", "owner"])
def test_doctor_fails_on_an_unsafe_marker_dir(machine_dir, monkeypatch, problem):
    target, _, owner = machine_dir
    target.parent.mkdir()
    if problem == "reparse":
        monkeypatch.setattr(hello_mode, "_is_reparse_point", lambda d: True)
    else:
        owner["sid"] = "S-1-5-21-1-2-3-1001"
    check = _hello_check()
    assert check.status is doctor.CheckStatus.FAIL
    assert ("reparse" if problem == "reparse" else "not owned") in check.detail


def test_doctor_says_any_marker_forces_the_mode_on(mode_on):
    detail = _hello_check().detail
    assert "even one" in detail and "administrator" in detail


def test_is_elevated_is_false_off_windows(monkeypatch):
    monkeypatch.setattr(hello_mode, "supported", lambda: False)
    assert hello_mode.is_elevated() is False


# --- approval memory never covers proof tier in the mode -----------------------------------


def _memory_case(tmp_path):
    from tests.unit.test_approval_memory import NOW, _remember
    from tests.unit.test_approval_memory import _action as mem_action
    from tests.unit.test_approval_memory import _decision as mem_decision

    root = str(tmp_path)
    action = mem_action()
    decision = mem_decision(risk=Risk.high, reasons=[ReasonCode.sensitive_secret_access])
    return root, action, decision, NOW, _remember


def test_memory_hit_in_the_mode_still_needs_hello(mode_on, backend, tmp_path, monkeypatch):
    from datetime import timedelta

    from doberman.auth.challenge import run_auth_challenge
    from doberman.auth.provider import LOCAL_PROVIDER

    root, action, decision, now, remember = _memory_case(tmp_path)
    asyncio.run(
        remember(
            root,
            action.action_fingerprint,
            required_tier=AuthTier.two_factor.value,
            approved_at=now - timedelta(minutes=2),
        )
    )
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    backend(available=False)
    prompter = CodePrompter()
    result = run_auth_challenge(
        decision, action, prompter=prompter, at=now, repo_root=root, session_id="session-a"
    )
    assert result.approved is False
    assert result.tier is AuthTier.two_factor
    assert prompter.asked == ["confirm"]  # full proof tier: no code, no memory shortcut


def test_a_hello_approval_is_not_remembered_in_the_mode(mode_on, backend, tmp_path, monkeypatch):
    from doberman.auth.challenge import run_auth_challenge
    from doberman.auth.provider import LOCAL_PROVIDER
    from doberman.storage.approval_memory import lookup

    root, action, decision, now, _ = _memory_case(tmp_path)
    monkeypatch.setattr("doberman.auth.provider.active_provider", lambda: LOCAL_PROVIDER)
    result = run_auth_challenge(
        decision, action, prompter=CodePrompter(), at=now, repo_root=root, session_id="session-a"
    )
    assert result.approved is True and result.method == "windows_hello"
    stored = asyncio.run(
        lookup(action.action_fingerprint, repo_root=root, session_id="session-a", now=now)
    )
    assert stored is None


# --- the hook deny message can never raise ------------------------------------------------


def test_hook_deny_message_survives_hello_mode_failing_to_import(monkeypatch):
    import sys

    import doberman.auth

    monkeypatch.delattr(doberman.auth, "hello_mode")
    monkeypatch.setitem(sys.modules, "doberman.auth.hello_mode", None)  # import now raises
    text = hookio._auth_denied_reason(_decision(), channel_error=False, method="hello_required")
    assert "Next step" in text


# --- async: the stored challenge's tier decides ------------------------------------------


@pytest.mark.parametrize("on", [False, True])
def test_a_lower_tier_handle_copy_cannot_approve_without_proof(marker, on):
    import dataclasses

    if on:
        _write_marker(marker)
    be, handle = _issue(AuthTier.two_factor)
    forged = dataclasses.replace(handle, tier=AuthTier.local_auth)
    result = async_challenge.resolve_challenge(forged, approved=True, backend=be)
    assert result.approved is False
    assert result.tier is AuthTier.two_factor


def test_marker_file_not_admin_owned_is_removed_and_refused(machine_dir, monkeypatch):
    """Where policy makes the creator the owner, the user could later rewrite its ACL."""
    target, _, _ = machine_dir
    target.parent.mkdir()
    monkeypatch.setattr(
        hello_mode,
        "_owner_sid",
        lambda p: hello_mode.ADMINS_SID if p == target.parent else "S-1-5-21-1-2-3-1001",
    )
    with pytest.raises(hello_mode.HelloModeError, match="not owned by Administrators"):
        hello_mode.write_marker(target, _PUBKEY)
    assert not target.exists()


def test_admin_path_refuses_without_the_shell_known_folder(real_locations, monkeypatch, tmp_path):
    """%ProgramData% alone is user-controlled, so enroll and leave never trust it."""
    monkeypatch.setattr(hello_mode, "supported", lambda: True)
    monkeypatch.setattr(hello_mode, "_known_program_data", lambda: None)
    monkeypatch.setenv("ProgramData", str(tmp_path / "env"))
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    with pytest.raises(hello_mode.HelloModeError, match="ProgramData"):
        hello_mode.admin_marker_path()


# --- slice 4: weakening CLI commands in the mode -------------------------------------------


def test_weaken_refusal_off_the_mode_needs_an_enrolled_factor(marker):
    method, message = drift.weaken_refusal("clearing taint")
    assert method == "no_factor_enrolled"
    assert message == (
        "clearing taint requires an enrolled possession factor - run `doberman 2fa setup` "
        "or `doberman password set` first"
    )
    password.enroll("correct horse battery staple")
    assert drift.weaken_refusal("clearing taint") is None


def test_weaken_refusal_in_the_mode_needs_hello_not_a_factor_file(mode_on, backend):
    assert drift.weaken_refusal("clearing taint") is None
    backend(available=False)
    method, message = drift.weaken_refusal("clearing taint")
    assert method == "hello_unavailable"
    assert "Windows Hello" in message and "2fa setup" not in message
    backend(available=RuntimeError("winrt blocked"))
    assert drift.weaken_refusal("clearing taint")[0] == "hello_unavailable"


def test_weaken_precheck_refuses_before_the_diff_when_hello_is_unavailable(mode_on, backend):
    from doberman.policy.drift import Classification

    backend(available=False)
    prompter = CodePrompter()
    result = asyncio.run(
        drift._run_gate_if_weaken({"a": 1}, {"a": 0}, "r", Classification.weaken, prompter)
    )
    assert result == (False, "hello_unavailable")
    assert prompter.asked == [] and backend.current().prompts == []


@pytest.fixture
def code_prompter(monkeypatch):
    from doberman.auth import provider
    from doberman.cli import main as cli_main

    monkeypatch.setattr(cli_main, "CliPrompter", CodePrompter)
    monkeypatch.setattr(provider, "CliPrompter", CodePrompter)


def _pending_policy_drop(root):
    """Pin two blocked globs, then drop one: `policy-file --accept` is a weakening."""
    from doberman.policy.sources import load_file_policy

    path = root / "doberman.policy.yaml"
    path.write_text("version: 1\nblocked:\n- a/**\n- b/**\n", encoding="utf-8")
    load_file_policy(str(root))
    path.write_text("version: 1\nblocked:\n- a/**\n", encoding="utf-8")


@pytest.mark.parametrize(
    "args",
    [
        ["taint", "clear"],
        ["tools", "approve", "some-tool"],
        ["memory", "reset"],
        ["uninstall", "--yes"],
        ["uninstall", "--global", "--yes"],
        ["policy-file", "--accept"],
    ],
    ids=" ".join,
)
def test_weakening_commands_refuse_cleanly_when_hello_is_unavailable(
    mode_on, backend, code_prompter, tmp_path, args
):
    if args == ["uninstall", "--yes"]:  # something to remove, so the gate is reached
        assert _cli(["install-hooks", "--path", str(tmp_path)])[0].exit_code == 0
    if args[0] == "policy-file":
        _pending_policy_drop(tmp_path)
    backend(available=False)
    result, out = _cli([*args, "--path", str(tmp_path)])
    assert result.exit_code == 1, out
    assert "Windows Hello" in out
    assert "2fa setup" not in out
    assert backend.current().prompts == []


def _seed_taint(root):
    from doberman.storage.taint import TAINT_SECRET_ACCESS, read_taint, record_taints

    asyncio.run(record_taints(str(root), ["sess-1"], [TAINT_SECRET_ACCESS]))
    return lambda: asyncio.run(read_taint(str(root), "sess-1"))


def test_taint_clear_works_in_the_mode_with_only_a_hello_gesture(
    mode_on, backend, code_prompter, tmp_path
):
    taint = _seed_taint(tmp_path)
    assert not totp.is_enrolled() and not password.is_enrolled()
    result, out = _cli(["taint", "clear", "--path", str(tmp_path)])
    assert result.exit_code == 0, out
    assert taint() == {}
    assert backend.current().prompts[0].startswith(b"doberman-proof-v1\naction_id=policy-weaken\n")


@pytest.mark.parametrize(
    "kwargs", [{"verdict": HelloVerdict.cancelled}, {"raises": TimeoutError()}]
)
def test_taint_clear_in_the_mode_without_a_verified_signature_changes_nothing(
    mode_on, backend, code_prompter, tmp_path, enrolled_totp, kwargs
):
    taint = _seed_taint(tmp_path)
    backend(**kwargs)
    result, out = _cli(["taint", "clear", "--path", str(tmp_path)])
    assert result.exit_code == 1, out
    assert taint() != {}


def test_policy_file_accept_works_in_the_mode_with_a_hello_gesture(
    mode_on, backend, code_prompter, tmp_path
):
    _pending_policy_drop(tmp_path)
    result, out = _cli(["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0, out
    assert "accepted" in out


def test_mode_lowering_in_the_mode_names_hello_when_it_fails(
    mode_on, backend, code_prompter, tmp_path
):
    assert _cli(["mode", "strict", "--path", str(tmp_path)])[0].exit_code == 0
    backend(verdict=HelloVerdict.cancelled)
    result, out = _cli(["mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "Windows Hello" in out and "password set" not in out
    backend(available=False)
    result, out = _cli(["mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "not available" in out
    backend()
    result, out = _cli(["mode", "light", "--path", str(tmp_path)])
    assert result.exit_code == 0, out


# --- slice 4: doctor -----------------------------------------------------------------------


@pytest.fixture
def machine_marker(tmp_path, monkeypatch):
    """A valid admin-owned machine marker and no test override."""
    path = tmp_path / "pd" / "doberman" / "proof.json"
    path.parent.mkdir(parents=True)
    _write_marker(path)
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [path])
    monkeypatch.setattr(hello_mode, "_owner_sid", lambda d: hello_mode.ADMINS_SID)
    monkeypatch.delenv(hello_mode.MARKER_ENV, raising=False)
    return path


def _sandbox(tmp_path, platform="win32"):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    return doctor._check_agent_sandbox(str(repo), home=tmp_path / "home", platform=platform)


def test_doctor_sandbox_passes_on_windows_with_the_mode_on_and_no_secret(machine_marker, tmp_path):
    check = _sandbox(tmp_path)
    assert check.status is doctor.CheckStatus.OK
    assert "Hello-required mode" in check.detail and check.detail.isascii()


def test_doctor_sandbox_warns_on_windows_when_a_secret_file_exists(machine_marker, tmp_path):
    totp.resolve_path().parent.mkdir(parents=True, exist_ok=True)
    totp.resolve_path().write_text("JBSWY3DPEHPK3PXP", encoding="utf-8")
    assert _sandbox(tmp_path).status is doctor.CheckStatus.WARN


def test_doctor_sandbox_warns_on_windows_with_a_corrupt_marker(machine_marker, tmp_path):
    machine_marker.write_text("garbage", encoding="utf-8")
    assert _sandbox(tmp_path).status is doctor.CheckStatus.WARN


def test_doctor_sandbox_warns_on_windows_with_an_unsafe_marker_folder(
    machine_marker, tmp_path, monkeypatch
):
    monkeypatch.setattr(hello_mode, "_owner_sid", lambda d: "S-1-5-21-1-2-3-1001")
    assert _sandbox(tmp_path).status is doctor.CheckStatus.WARN


def test_doctor_sandbox_warns_on_windows_when_only_the_test_override_is_on(mode_on, tmp_path):
    check = _sandbox(tmp_path)
    assert check.status is doctor.CheckStatus.WARN
    assert "native Windows" in check.detail


def test_doctor_sandbox_ignores_the_mode_off_windows(machine_marker, tmp_path):
    # non-Windows keeps the Claude Code sandbox check unchanged: no settings, so a warning
    check = _sandbox(tmp_path, platform="linux")
    assert check.status is doctor.CheckStatus.WARN
    assert "Hello" not in check.detail


def test_doctor_hello_row_names_the_pinned_key(machine_marker):
    from doberman.auth import hello_proof

    check = _hello_check()
    assert check.status is doctor.CheckStatus.OK
    assert hello_proof.key_id(_PUBKEY)[:23] in check.detail


def test_doctor_hello_row_fails_when_two_markers_pin_different_keys(
    machine_marker, tmp_path, monkeypatch
):
    other = tmp_path / "other" / "proof.json"
    other.parent.mkdir()
    _write_marker(other, public_key=base64.b64encode(keypair("b").public_key).decode())
    monkeypatch.setattr(hello_mode, "_machine_marker_paths", lambda: [machine_marker, other])
    check = _hello_check()
    assert check.status is doctor.CheckStatus.FAIL
    assert "different" in check.detail


def test_hello_availability_works_from_inside_an_event_loop(mode_on, monkeypatch):
    """The weaken pre-check runs inside asyncio.run; the WinRT check calls asyncio.run too."""

    class _LoopBackend(FakeBackend):
        def available(self):
            async def _check():
                return True

            return asyncio.run(_check())

    monkeypatch.setattr(hello_mode, "backend", lambda: _LoopBackend())

    async def _on_loop():
        return hello_mode.available()

    assert hello_mode.available() is True
    assert asyncio.run(_on_loop()) is True


def test_availability_needs_a_real_true_not_a_truthy_value(mode_on, backend):
    backend(available=1)
    assert drift.weaken_refusal("clearing taint")[0] == "hello_unavailable"


def test_lowering_advice_in_the_mode_names_hello_not_a_password(mode_on):
    from doberman.cli import main as cli_main

    assert "Windows Hello" in cli_main._lowering_factor()
    assert "password" not in cli_main._lowering_factor()
