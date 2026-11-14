"""WindowsHelloMethod over an injected HelloBackend.

A fake backend drives every path, so this runs on Linux CI without ``winrt``.
Pinned: only an explicit ``verified`` approves; a cancel or timeout denies; a
backend that raises or reports unavailable never approves (it defers to TOTP,
the existing fallback).
"""

import pytest

from doberman.auth.approval import ApprovalOutcome
from doberman.auth.methods import windows_hello
from doberman.auth.methods.windows_hello import (
    HelloError,
    HelloVerdict,
    WindowsHelloMethod,
    WinRTHelloBackend,
    tpm_backed_from_attestation,
)


class FakeBackend:
    def __init__(self, *, available=True, verdict=HelloVerdict.verified, raises=None):
        self._available = available
        self._verdict = verdict
        self._raises = raises
        self.calls: list[tuple[str, float]] = []

    def available(self) -> bool:
        if isinstance(self._available, BaseException):
            raise self._available
        return self._available

    def verify(self, prompt, *, timeout_s):
        self.calls.append((prompt, timeout_s))
        if self._raises is not None:
            raise self._raises
        return self._verdict

    def sign(self, data):  # pragma: no cover - not used by the method yet
        raise AssertionError("sign must not be called in slice 1")

    def public_key(self):  # pragma: no cover - not used by the method yet
        raise AssertionError("public_key must not be called in slice 1")

    def tpm_backed(self):  # pragma: no cover - not used by the method yet
        return None


def _request(backend):
    return WindowsHelloMethod(backend=backend).request(
        "Approve rm -rf build?", action_id="a1", timeout_s=7.0
    )


def test_verified_approves_and_passes_prompt_and_timeout():
    b = FakeBackend(verdict=HelloVerdict.verified)
    assert _request(b) is ApprovalOutcome.approved
    assert b.calls == [("Approve rm -rf build?", 7.0)]


def test_cancelled_denies():
    assert _request(FakeBackend(verdict=HelloVerdict.cancelled)) is ApprovalOutcome.denied


def test_unavailable_verdict_is_unavailable_not_approved():
    assert _request(FakeBackend(verdict=HelloVerdict.unavailable)) is ApprovalOutcome.unavailable


def test_timeout_denies():
    assert _request(FakeBackend(raises=TimeoutError())) is ApprovalOutcome.denied


@pytest.mark.parametrize("exc", [RuntimeError("boom"), OSError("no window"), ValueError("bad")])
def test_backend_raising_never_approves(exc):
    assert _request(FakeBackend(raises=exc)) is ApprovalOutcome.unavailable


@pytest.mark.parametrize("junk", [True, "verified", 1, None, ApprovalOutcome.approved])
def test_anything_but_the_verified_member_denies(junk):
    assert _request(FakeBackend(verdict=junk)) is ApprovalOutcome.denied


@pytest.mark.parametrize(
    "avail,expected", [(True, True), (False, False), (RuntimeError("x"), False), ("yes", False)]
)
def test_is_available_is_conservative(avail, expected):
    assert WindowsHelloMethod(backend=FakeBackend(available=avail)).is_available() is expected


def test_default_backend_is_winrt():
    assert isinstance(WindowsHelloMethod()._backend, WinRTHelloBackend)


def test_winrt_backend_without_winrt_is_unavailable_and_unknown(monkeypatch):
    monkeypatch.setattr(windows_hello, "_load_winrt", lambda: None)  # "winrt missing" anywhere
    b = WinRTHelloBackend()
    assert b.available() is False
    assert b.verify("x", timeout_s=1.0) is HelloVerdict.unavailable
    assert b.tpm_backed() is None
    with pytest.raises(HelloError):
        b.sign(b"data")
    with pytest.raises(HelloError):
        b.public_key()


@pytest.mark.parametrize(
    "status,expected",
    [
        ("SUCCESS", True),
        ("Success", True),
        ("NOT_SUPPORTED", False),
        ("NotSupported", False),
        ("UNKNOWN_ERROR", None),
        ("TEMPORARY_FAILURE", None),
        ("", None),
        (None, None),
    ],
)
def test_tpm_backed_is_never_yes_unless_attested(status, expected):
    assert tpm_backed_from_attestation(status) is expected


# --------------------------------------------------------------------------- #
# WinRTHelloBackend over stub WinRT modules (PyWinRT spells enums UPPER_SNAKE)  #
# --------------------------------------------------------------------------- #
class _Enum:
    def __init__(self, name):
        self.name = name


class _Res:
    def __init__(self, status, **kw):
        self.status = _Enum(status)
        self.__dict__.update(kw)


def _stub_winrt(
    monkeypatch,
    *,
    verify=None,
    availability="AVAILABLE",
    open_status="SUCCESS",
    sign_status="SUCCESS",
    attestation=None,
):
    """Install stub ``(ui, credentials)`` modules. ``verify``/``attestation`` are a
    status name, an exception to raise, or a coroutine function."""

    async def _answer(spec, *args):
        if isinstance(spec, BaseException):
            raise spec
        if callable(spec):
            return await spec(*args)
        return spec

    class UserConsentVerifier:
        @staticmethod
        async def check_availability_async():
            return _Enum(availability)

        @staticmethod
        async def request_verification_async(prompt):
            return await _answer(
                verify if callable(verify) or isinstance(verify, BaseException) else _Enum(verify),
                prompt,
            )

    class Key:
        async def request_sign_async(self, data):
            return _Res(sign_status, result=b"sig:" + bytes(data))

        def retrieve_public_key(self):
            return b"spki-der"

        async def get_attestation_async(self):
            return await _answer(
                attestation if isinstance(attestation, BaseException) else _Res(attestation)
            )

    class KeyCredentialManager:
        opened: list[str] = []

        @staticmethod
        async def open_async(name):
            KeyCredentialManager.opened.append(name)
            return _Res(open_status, credential=Key())

    ui = type("ui", (), {"UserConsentVerifier": UserConsentVerifier})
    cred = type("cred", (), {"KeyCredentialManager": KeyCredentialManager})
    monkeypatch.setattr(windows_hello, "_load_winrt", lambda: (ui, cred))
    return KeyCredentialManager


@pytest.mark.parametrize(
    "availability,expected",
    [("AVAILABLE", True), ("DEVICE_NOT_PRESENT", False), ("NOT_CONFIGURED_FOR_USER", False)],
)
def test_winrt_available_maps_availability(monkeypatch, availability, expected):
    _stub_winrt(monkeypatch, availability=availability)
    assert WinRTHelloBackend().available() is expected


def test_winrt_verify_verified(monkeypatch):
    _stub_winrt(monkeypatch, verify="VERIFIED")
    assert WinRTHelloBackend().verify("p", timeout_s=5) is HelloVerdict.verified


@pytest.mark.parametrize(
    "result",
    [
        "CANCELED",
        "RETRIES_EXHAUSTED",
        "NOT_CONFIGURED_FOR_USER",
        "DEVICE_NOT_PRESENT",
        "DEVICE_BUSY",
        "DISABLED_BY_POLICY",
    ],
)
def test_winrt_verify_anything_else_is_a_no(monkeypatch, result):
    # Unchanged from before the seam: every non-Verified result denies (slice 1 keeps it).
    _stub_winrt(monkeypatch, verify=result)
    assert WinRTHelloBackend().verify("p", timeout_s=5) is HelloVerdict.cancelled
    assert WindowsHelloMethod().request("p", action_id="a", timeout_s=5) is ApprovalOutcome.denied


def test_winrt_verify_raise_propagates_and_method_never_approves(monkeypatch):
    _stub_winrt(monkeypatch, verify=OSError("no window"))
    with pytest.raises(OSError):
        WinRTHelloBackend().verify("p", timeout_s=5)
    assert (
        WindowsHelloMethod().request("p", action_id="a", timeout_s=5) is ApprovalOutcome.unavailable
    )


def test_winrt_verify_timeout_denies(monkeypatch):
    import asyncio

    async def _slow(prompt):
        await asyncio.sleep(5)
        return _Enum("VERIFIED")  # pragma: no cover - the timeout fires first

    _stub_winrt(monkeypatch, verify=_slow)
    with pytest.raises(TimeoutError):
        WinRTHelloBackend().verify("p", timeout_s=0.05)
    assert (
        WindowsHelloMethod().request("p", action_id="a", timeout_s=0.05) is ApprovalOutcome.denied
    )


def test_winrt_sign_and_public_key_use_the_doberman_proof_key(monkeypatch):
    kcm = _stub_winrt(monkeypatch)
    b = WinRTHelloBackend()
    assert b.sign(b"data") == b"sig:data"
    assert b.public_key() == b"spki-der"
    assert kcm.opened == [windows_hello.KEY_NAME, windows_hello.KEY_NAME] == ["doberman-proof"] * 2


@pytest.mark.parametrize("kw", [{"open_status": "NOT_FOUND"}, {"sign_status": "USER_CANCELED"}])
def test_winrt_sign_refused_raises(monkeypatch, kw):
    _stub_winrt(monkeypatch, **kw)
    with pytest.raises(HelloError):
        WinRTHelloBackend().sign(b"data")


def test_winrt_public_key_missing_key_raises(monkeypatch):
    _stub_winrt(monkeypatch, open_status="NOT_FOUND")
    with pytest.raises(HelloError):
        WinRTHelloBackend().public_key()


@pytest.mark.parametrize(
    "kw,expected",
    [
        ({"attestation": "SUCCESS"}, True),
        ({"attestation": "NOT_SUPPORTED"}, False),
        ({"attestation": "UNKNOWN_ERROR"}, None),
        ({"attestation": "TEMPORARY_FAILURE"}, None),
        ({"attestation": RuntimeError("tpm")}, None),
        ({"open_status": "NOT_FOUND", "attestation": "SUCCESS"}, None),
    ],
)
def test_winrt_tpm_backed(monkeypatch, kw, expected):
    _stub_winrt(monkeypatch, **kw)
    assert WinRTHelloBackend().tpm_backed() is expected
