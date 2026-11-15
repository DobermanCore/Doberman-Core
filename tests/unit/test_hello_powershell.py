"""The Windows Hello backend over Windows PowerShell 5.1 (``PowerShellHelloBackend``).

Every Hello operation runs in a short-lived ``powershell.exe`` child with a fixed script.
On Linux CI the child is faked at ``subprocess.run``; the Windows-only test at the bottom
runs the real child for non-prompting operations only. Pinned: the executable comes from
Windows (never the environment), caller data travels on stdin (never in the script), the
reply is one strict JSON line, and anything else is an error, which denies.
"""

import base64
import json
import os
import subprocess
import sys

import pytest

from doberman.auth import hello_mode, hello_proof
from doberman.auth.approval import ApprovalOutcome
from doberman.auth.methods import windows_hello
from doberman.auth.methods.windows_hello import (
    HELLO_SCRIPT,
    HelloError,
    HelloLanguageModeError,
    HelloVerdict,
    PowerShellHelloBackend,
    WindowsHelloMethod,
)
from tests.unit._hello_rsa import keypair

#: Captured at import, before the conftest fixture blocks real children for each test.
_REAL_SYSTEM_POWERSHELL = windows_hello.system_powershell

FAKE_EXE = os.path.join(
    "C:\\", "Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
)
KEY = keypair("a")
_HASH = "hmac:" + "cd" * 32


class _Done:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout, self.returncode, self.stderr = stdout, returncode, b""


def _line(obj) -> bytes:
    return (json.dumps(obj) + "\r\n").encode("ascii")


class Child:
    """A fake ``subprocess.run``: records every call, answers from ``replies`` by op."""

    def __init__(self, replies):
        self.replies, self.calls = replies, []

    def __call__(self, argv, **kwargs):
        request = json.loads(kwargs["input"])
        self.calls.append((argv, kwargs, request))
        answer = self.replies[request["op"]]
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, BaseException):
            raise answer
        return answer if isinstance(answer, _Done) else _Done(_line(answer))


@pytest.fixture
def child(monkeypatch):
    def _install(**replies):
        fake = Child(replies)
        monkeypatch.setattr(windows_hello, "system_powershell", lambda: FAKE_EXE)
        monkeypatch.setattr(windows_hello.subprocess, "run", fake)
        return fake

    return _install


def _ok(status, value=None):
    return {"status": status, "value": value}


# --- which powershell.exe ------------------------------------------------------------------


def test_off_windows_there_is_no_powershell(monkeypatch):
    monkeypatch.setattr(windows_hello.sys, "platform", "linux")
    with pytest.raises(HelloError):
        _REAL_SYSTEM_POWERSHELL()


def _fake_windows(monkeypatch, system_dir):
    monkeypatch.setattr(windows_hello.sys, "platform", "win32")
    monkeypatch.setattr(windows_hello, "_system_directory", lambda: system_dir)


def test_powershell_comes_from_the_system_directory_not_the_environment(tmp_path, monkeypatch):
    system = tmp_path / "System32"
    exe = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ")
    planted = tmp_path / "evil"
    (planted / "System32" / "WindowsPowerShell" / "v1.0").mkdir(parents=True)
    (planted / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe").write_bytes(b"MZ")
    (planted / "powershell.exe").write_bytes(b"MZ")
    monkeypatch.setenv("SystemRoot", str(planted))
    monkeypatch.setenv("windir", str(planted))
    monkeypatch.setenv("PATH", str(planted))
    _fake_windows(monkeypatch, str(system))
    assert _REAL_SYSTEM_POWERSHELL() == str(exe)


@pytest.mark.parametrize("system_dir", [None, ""])
def test_no_system_directory_means_no_hello(monkeypatch, system_dir):
    _fake_windows(monkeypatch, system_dir)
    with pytest.raises(HelloError):
        _REAL_SYSTEM_POWERSHELL()


def test_a_system_directory_without_powershell_means_no_hello(tmp_path, monkeypatch):
    _fake_windows(monkeypatch, str(tmp_path))
    with pytest.raises(HelloError):
        _REAL_SYSTEM_POWERSHELL()


class _Kernel32:
    def __init__(self, value, returned):
        self.value, self.returned = value, returned
        self.GetSystemDirectoryW = self._get

    def _get(self, buf, size):
        buf.value = self.value[: size - 1]
        return self.returned(size)


@pytest.mark.parametrize(
    ("returned", "expected"),
    [
        (lambda size: len("C:\\Windows\\System32"), "C:\\Windows\\System32"),
        (lambda size: 0, None),  # the call failed
        (lambda size: size + 10, None),  # buffer too small: the path would be truncated
    ],
)
def test_system_directory_asks_kernel32(monkeypatch, returned, expected):
    import ctypes

    kernel32 = _Kernel32("C:\\Windows\\System32", returned)
    monkeypatch.setattr(ctypes, "WinDLL", lambda name: kernel32, raising=False)
    assert windows_hello._system_directory() == expected


def test_system_directory_without_kernel32_is_none(monkeypatch):
    import ctypes

    def _no(name):
        raise OSError("no kernel32")

    monkeypatch.setattr(ctypes, "WinDLL", _no, raising=False)
    assert windows_hello._system_directory() is None


def test_a_real_child_is_never_started_when_powershell_cannot_be_resolved(monkeypatch):
    def _no_powershell():
        raise HelloError("no system directory")

    def _run(*a, **k):  # pragma: no cover - must not be reached
        raise AssertionError("no child may start")

    monkeypatch.setattr(windows_hello, "system_powershell", _no_powershell)
    monkeypatch.setattr(windows_hello.subprocess, "run", _run)
    backend = PowerShellHelloBackend()
    with pytest.raises(HelloError):
        backend.available()
    with pytest.raises(HelloError):
        backend.sign(b"msg")
    assert backend.tpm_backed() is None
    assert WindowsHelloMethod(backend=backend).is_available() is False
    assert (
        WindowsHelloMethod(backend=backend).request("p", action_id="a", timeout_s=5)
        is ApprovalOutcome.unavailable
    )


# --- the invocation: fixed argv, data on stdin ---------------------------------------------


def test_the_script_is_passed_encoded_and_never_carries_caller_data(child):
    caller_prompt = "Approve rm -rf /very/unique/path-7f3a?"
    caller_data = b"unique-message-bytes-91c2"
    fake = child(
        verify=_ok("Verified"),
        sign=_ok("Success", base64.b64encode(b"sig").decode()),
        available=_ok("Available"),
    )
    backend = PowerShellHelloBackend()
    backend.verify(caller_prompt, timeout_s=5)
    backend.sign(caller_data, timeout_s=5)
    backend.available()
    argvs = [argv for argv, _, _ in fake.calls]
    assert argvs[0] == argvs[1] == argvs[2]
    argv = argvs[0]
    assert argv[:-1] == [
        FAKE_EXE,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
    ]
    assert base64.b64decode(argv[-1]).decode("utf-16-le") == HELLO_SCRIPT
    for value in (caller_prompt, "path-7f3a", caller_data.decode(), "91c2"):
        assert value not in HELLO_SCRIPT
        assert all(value not in part for part in argv)
    (_, _, verify_req), (_, _, sign_req), (_, _, avail_req) = fake.calls
    assert base64.b64decode(verify_req["prompt"]).decode("utf-8") == caller_prompt
    assert base64.b64decode(sign_req["data"]) == caller_data
    assert {verify_req["op"], sign_req["op"], avail_req["op"]} == {"verify", "sign", "available"}
    assert sign_req["key"] == windows_hello.KEY_NAME == "doberman-proof"


def test_the_child_runs_hidden_bounded_and_away_from_user_modules(child, monkeypatch):
    monkeypatch.setenv("COR_ENABLE_PROFILING", "1")
    monkeypatch.setenv("COR_PROFILER_PATH", "C:/evil.dll")
    monkeypatch.setenv("SystemRoot", "C:/evil")
    monkeypatch.setenv("PSModulePath", "C:/evil/modules")
    monkeypatch.setenv("TEMP", "C:/temp-for-add-type")
    fake = child(available=_ok("Available"), sign=_ok("Success", base64.b64encode(b"s").decode()))
    PowerShellHelloBackend().available()
    PowerShellHelloBackend().sign(b"m", timeout_s=300)
    (_, quick, quick_req), (_, signing, sign_req) = fake.calls
    for kwargs in (quick, signing):
        assert kwargs["creationflags"] == 0x08000000  # CREATE_NO_WINDOW
        assert kwargs["capture_output"] is True
        assert kwargs["check"] is False
        env = kwargs["env"]
        assert env["PSModulePath"] == os.path.join(os.path.dirname(FAKE_EXE), "Modules")
        windows = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(FAKE_EXE))))
        assert env["SystemRoot"] == env["windir"] == windows
        assert env["TEMP"] == "C:/temp-for-add-type"
        assert not any(k.upper().startswith(("COR_", "COMPLUS_")) for k in env)
        assert kwargs["cwd"] == os.path.dirname(FAKE_EXE)
        assert isinstance(kwargs["input"], bytes) and kwargs["input"].isascii()
    assert quick["timeout"] <= 30
    assert 0 < quick_req["timeout_ms"] < quick["timeout"] * 1000
    assert sign_req["timeout_ms"] == 300_000
    assert 300 < signing["timeout"] <= 330


def test_the_command_line_fits_windows_limit():
    argv = [FAKE_EXE, *windows_hello._PS_ARGS, windows_hello._ENCODED_SCRIPT]
    assert len(subprocess.list2cmdline(argv)) < 32_767


def test_the_script_checks_its_language_mode_before_doing_anything():
    statements = [
        line.strip()
        for line in HELLO_SCRIPT.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    first_real = next(s for s in statements if not s.startswith("$") or "LanguageMode" in s)
    assert "LanguageMode" in first_real and "FullLanguage" in first_real
    assert HELLO_SCRIPT.index("LanguageMode") < HELLO_SCRIPT.index("ReadToEnd")
    assert HELLO_SCRIPT.isascii()


def test_the_script_binds_the_window_and_raises_the_dialog():
    assert "RequestSignForWindowAsync" in HELLO_SCRIPT
    assert "RequestSignAsync" in HELLO_SCRIPT  # the fallback
    assert "GetForegroundWindow" in HELLO_SCRIPT
    assert "Credential Dialog Xaml Host" in HELLO_SCRIPT
    assert "FailIfExists" in HELLO_SCRIPT  # create never replaces a pinned key


# --- strict replies -----------------------------------------------------------------------

_SIG = base64.b64encode(b"sig").decode()


@pytest.mark.parametrize(
    "outcome",
    [
        _Done(b""),
        _Done(b"garbage\r\n"),
        _Done(_line(_ok("Success", _SIG)) + _line(_ok("Success", _SIG))),
        _Done(_line(_ok("Success", _SIG)) + b"WARNING: something\r\n"),
        _Done(b"WARNING: something\r\n" + _line(_ok("Success", _SIG))),
        _Done(b"\xef\xbb\xbf" + _line(_ok("Success", _SIG))),  # a BOM
        _Done(_line(["Success", _SIG])),
        _Done(_line({"status": 1, "value": _SIG})),
        _Done(_line({"status": "Success", "value": 5})),
        _Done(_line({"status": "Success", "value": _SIG, "extra": True})),
        _Done(_line({"status": "Success"})),
        _Done(_line({"error": 5})),
        _Done(_line({"error": "failed"})),
        _Done(_line({"error": "timeout", "status": "Success"})),
        _Done(_line(_ok("Success", "!!!not base64"))),
        _Done(_line(_ok("Success", ""))),
        _Done(_line(_ok("Success"))),
        _Done(_line(_ok("UserCanceled"))),
        _Done(_line(_ok("NotFound"))),
        _Done(_line(_ok("Success", "QUFB" * 5000))),  # over the size cap
        _Done(_line(_ok("Success", _SIG)), returncode=1),
        _Done(_line(_ok("Success", _SIG)), returncode=-1073741819),
        subprocess.TimeoutExpired("powershell.exe", 1),
        OSError("cannot start"),
    ],
)
def test_any_other_reply_fails_the_signature(child, outcome):
    child(sign=outcome)
    with pytest.raises((HelloError, TimeoutError)):
        PowerShellHelloBackend().sign(b"msg", timeout_s=1)


def test_the_size_cap_is_checked_on_the_raw_output(child):
    child(available=_Done(b" " * (windows_hello._MAX_REPLY_BYTES + 1) + _line(_ok("Available"))))
    with pytest.raises(HelloError):
        PowerShellHelloBackend().available()


@pytest.mark.parametrize(
    "outcome",
    [
        _Done(b"garbage"),
        _Done(_line({"error": "failed"})),
        _Done(_line(_ok("Verified")), returncode=1),
        _Done(_line(_ok("Verified")) + _line(_ok("Verified"))),
        OSError("cannot start"),
    ],
)
def test_a_bad_verify_reply_never_approves(child, outcome):
    child(verify=outcome)
    result = WindowsHelloMethod(backend=PowerShellHelloBackend()).request(
        "p", action_id="a", timeout_s=5
    )
    assert result is ApprovalOutcome.unavailable


def test_a_good_reply_with_unix_newline_or_none_is_accepted(child):
    for raw in (
        json.dumps(_ok("Available")).encode(),
        json.dumps(_ok("Available")).encode() + b"\n",
    ):
        child(available=_Done(raw))
        assert PowerShellHelloBackend().available() is True


# --- each operation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("Available", True),
        ("DeviceNotPresent", False),
        ("NotConfiguredForUser", False),
        ("DisabledByPolicy", False),
        ("DeviceBusy", False),
    ],
)
def test_available_maps_the_availability(child, status, expected):
    child(available=_ok(status))
    assert PowerShellHelloBackend().available() is expected


def test_verify_verified(child):
    child(verify=_ok("Verified"))
    assert PowerShellHelloBackend().verify("p", timeout_s=5) is HelloVerdict.verified
    assert (
        WindowsHelloMethod(backend=PowerShellHelloBackend()).request(
            "p", action_id="a", timeout_s=5
        )
        is ApprovalOutcome.approved
    )


@pytest.mark.parametrize(
    "status",
    [
        "Canceled",
        "RetriesExhausted",
        "NotConfiguredForUser",
        "DeviceNotPresent",
        "DeviceBusy",
        "DisabledByPolicy",
        "verified-ish",
        "",
    ],
)
def test_verify_anything_else_is_a_no(child, status):
    child(verify=_ok(status))
    assert PowerShellHelloBackend().verify("p", timeout_s=5) is HelloVerdict.cancelled
    assert (
        WindowsHelloMethod(backend=PowerShellHelloBackend()).request(
            "p", action_id="a", timeout_s=5
        )
        is ApprovalOutcome.denied
    )


def test_verify_timeout_in_the_child_denies(child):
    fake = child(verify={"error": "timeout"})
    with pytest.raises(TimeoutError):
        PowerShellHelloBackend().verify("p", timeout_s=0.5)
    assert fake.calls[0][2]["timeout_ms"] == 500
    assert (
        WindowsHelloMethod(backend=PowerShellHelloBackend()).request(
            "p", action_id="a", timeout_s=0.5
        )
        is ApprovalOutcome.denied
    )


def test_sign_returns_the_decoded_signature(child):
    child(sign=_ok("Success", _SIG))
    assert PowerShellHelloBackend().sign(b"msg", timeout_s=5) == b"sig"


def test_public_key_is_the_decoded_blob(child):
    child(public_key=_ok("Success", base64.b64encode(b"spki-der").decode()))
    assert PowerShellHelloBackend().public_key() == b"spki-der"


@pytest.mark.parametrize(
    "reply", [_ok("NotFound"), _ok("Success"), _ok("Success", "%%%"), {"error": "failed"}]
)
def test_public_key_failure_raises(child, reply):
    child(public_key=reply)
    with pytest.raises(HelloError):
        PowerShellHelloBackend().public_key()


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (_ok("Success", "Success"), True),
        (_ok("Success", "NotSupported"), False),
        (_ok("Success", "UnknownError"), None),
        (_ok("Success", "TemporaryFailure"), None),
        (_ok("Success"), None),
        (_ok("NotFound", "Success"), None),  # the key did not open: never "yes"
        ({"error": "failed"}, None),
        ({"error": "timeout"}, None),
        (_Done(b"junk"), None),
    ],
)
def test_tpm_backed_is_never_yes_unless_attested(child, reply, expected):
    child(attest=reply)
    assert PowerShellHelloBackend().tpm_backed() is expected


def test_ensure_key_creates_a_missing_key(child):
    fake = child(open=_ok("NotFound"), create=_ok("Success"))
    PowerShellHelloBackend().ensure_key()
    assert [req["op"] for _, _, req in fake.calls] == ["open", "create"]


def test_ensure_key_keeps_an_existing_key(child):
    fake = child(open=_ok("Success"))
    PowerShellHelloBackend().ensure_key()
    assert [req["op"] for _, _, req in fake.calls] == ["open"]


@pytest.mark.parametrize(
    "replies",
    [
        {"open": _ok("NotFound"), "create": _ok("UserCanceled")},
        {"open": _ok("SecurityDeviceLocked")},
        {"open": {"error": "failed"}},
    ],
)
def test_ensure_key_failure_raises(child, replies):
    child(**replies)
    with pytest.raises(HelloError):
        PowerShellHelloBackend().ensure_key()


# --- Constrained Language Mode ---------------------------------------------------------------


def test_constrained_language_mode_is_its_own_error(child):
    child(ping={"error": "language_mode"}, available={"error": "language_mode"})
    with pytest.raises(HelloLanguageModeError):
        PowerShellHelloBackend().check_powershell()
    with pytest.raises(HelloLanguageModeError):
        PowerShellHelloBackend().available()


def test_check_powershell_passes_on_a_ping(child):
    fake = child(ping=_ok("ok"))
    PowerShellHelloBackend().check_powershell()
    assert fake.calls[0][2]["op"] == "ping"


@pytest.mark.parametrize("reply", [_ok("FullLanguage"), {"error": "failed"}, _Done(b"")])
def test_check_powershell_fails_on_anything_but_ok(child, reply):
    child(ping=reply)
    with pytest.raises(HelloError):
        PowerShellHelloBackend().check_powershell()


def test_mode_off_constrained_language_falls_back(child):
    # Mode off: Hello unavailable means the challenge uses TOTP, as before.
    child(available={"error": "language_mode"}, verify={"error": "language_mode"})
    method = WindowsHelloMethod(backend=PowerShellHelloBackend())
    assert method.is_available() is False
    assert method.request("p", action_id="a", timeout_s=5) is ApprovalOutcome.unavailable


@pytest.fixture
def mode_on(tmp_path, monkeypatch):
    path = tmp_path / "proof.json"
    body = {
        "version": 1,
        "public_key": base64.b64encode(KEY.public_key).decode(),
        "enrolled_at": "2026-11-14T00:00:00+00:00",
    }
    path.write_text(json.dumps(body), encoding="utf-8")
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(path))
    monkeypatch.setattr(hello_proof, "_seen", set())
    assert hello_mode.is_on()


def test_mode_on_uses_this_backend():
    assert isinstance(hello_mode.backend(), PowerShellHelloBackend)
    assert isinstance(WindowsHelloMethod()._backend, PowerShellHelloBackend)


def test_mode_on_constrained_language_denies(mode_on, child):
    child(sign={"error": "language_mode"}, available={"error": "language_mode"})
    assert hello_mode.available() is False
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH) == (
        False,
        hello_mode.HELLO_REQUIRED_METHOD,
        None,
    )


def test_mode_on_proof_through_the_child_protocol_verifies(mode_on, child):
    """The child's signature (here a software key) round-trips through stdin/stdout."""

    def _sign(request):
        data = base64.b64decode(request["data"], validate=True)
        return _ok("Success", base64.b64encode(KEY.sign(data)).decode())

    child(sign=_sign)
    approved, method, proof = hello_mode.prove(action_id="act-1", action_hash=_HASH)
    assert (approved, method) == (True, "windows_hello")
    assert hello_proof.check_stored(proof, KEY.public_key)


def test_mode_on_a_child_signature_by_another_key_is_refused(mode_on, child):
    other = keypair("b")
    child(sign=lambda r: _ok("Success", base64.b64encode(other.sign(b"x")).decode()))
    assert hello_mode.prove(action_id="act-1", action_hash=_HASH)[0] is False


# --- the real child (Windows only; never a prompting operation) ------------------------------


@pytest.mark.timeout(600)
@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows PowerShell 5.1")
def test_the_real_child_runs_non_prompting_operations(monkeypatch):
    monkeypatch.setattr(windows_hello, "system_powershell", _REAL_SYSTEM_POWERSHELL)
    # A cold Windows PowerShell 5.1 took 12-90 s to start on windows-latest (0.3 s on a desktop);
    # this test checks the real path and protocol, not the production start-up bound.
    monkeypatch.setattr(windows_hello, "_CHILD_START_S", 240.0)
    backend = PowerShellHelloBackend()
    backend.check_powershell()  # resolves, starts, FullLanguage, one strict JSON line
    assert backend.available() in (True, False)  # CheckAvailabilityAsync never prompts


# --- doctor -----------------------------------------------------------------------------


def _doctor_row(monkeypatch, outcome):
    from doberman.cli import doctor

    def _check(self):
        if outcome is not None:
            raise outcome

    monkeypatch.setattr(PowerShellHelloBackend, "check_powershell", _check)
    return doctor._check_hello_powershell()


def test_doctor_row_ok_when_powershell_runs_in_full_language(monkeypatch):
    from doberman.cli.doctor import CheckStatus

    row = _doctor_row(monkeypatch, None)
    assert (row.status, row.critical) == (CheckStatus.OK, False)
    assert "FullLanguage" in row.detail


@pytest.mark.parametrize(
    ("outcome", "words"),
    [
        (HelloLanguageModeError("clm"), "Constrained Language"),
        (HelloError("no system directory"), "HelloError"),
        (TimeoutError("slow"), "TimeoutError"),
    ],
)
def test_doctor_row_warns_off_mode_and_fails_critically_in_it(
    monkeypatch, tmp_path, outcome, words
):
    from doberman.cli.doctor import CheckStatus

    row = _doctor_row(monkeypatch, outcome)
    assert (row.status, row.critical) == (CheckStatus.WARN, False)
    assert words in row.detail and "TOTP" in row.detail
    marker = tmp_path / "proof.json"
    marker.write_text("{", encoding="utf-8")  # any marker turns the mode on
    monkeypatch.setenv(hello_mode.MARKER_ENV, str(marker))
    row = _doctor_row(monkeypatch, outcome)
    assert (row.status, row.critical) == (CheckStatus.FAIL, True)
    assert words in row.detail and "refused" in row.detail


def test_doctor_lists_the_row_only_on_windows(tmp_path):
    from doberman.cli.doctor import run_checks

    names = [r.name for r in run_checks(str(tmp_path))]
    assert ("Hello PowerShell" in names) is (sys.platform == "win32")
