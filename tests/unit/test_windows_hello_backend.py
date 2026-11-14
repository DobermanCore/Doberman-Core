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
