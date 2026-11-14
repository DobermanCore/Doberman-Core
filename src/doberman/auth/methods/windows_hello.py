"""Windows Hello approval method — a local biometric (face / fingerprint / PIN) tap.

The method talks to Windows through an injected :class:`HelloBackend`. The real one,
:class:`WinRTHelloBackend`, uses the PyWinRT ``winrt-*`` packages
(``pip install doberman-core[winhello]``): ``UserConsentVerifier`` shows the system
Windows Hello prompt carrying the action text, and ``KeyCredentialManager`` holds the
``doberman-proof`` key for :meth:`HelloBackend.sign` / :meth:`HelloBackend.public_key`
(not used by any caller yet).

This method is **best-effort and fail-safe**:

* Not Windows, ``winrt`` not installed, or no Hello device enrolled →
  :meth:`WindowsHelloMethod.is_available` returns ``False`` (the challenge falls back
  to TOTP).
* The verifier runs but the human cancels / fails / times out → ``denied``.
* The prompt cannot be displayed at all, or the backend raises →
  ``unavailable`` (fall back to TOTP), never ``approved``.

The WinRT consent dialog historically prefers an owning window; from a bare console
process it may report itself unusable, in which case this method defers to TOTP
rather than blocking the human. Verify on a real Hello-enrolled machine
(``docs/HELLO-HARDWARE-CHECKS.md``) — CI has neither ``winrt`` nor a Hello device.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from enum import Enum
from typing import Protocol

from doberman.auth.approval import ApprovalOutcome

logger = logging.getLogger("doberman.auth.methods.windows_hello")

#: The ``KeyCredentialManager`` key name Doberman signs proofs with.
KEY_NAME = "doberman-proof"


class HelloVerdict(Enum):
    """What one Hello prompt produced. Only ``verified`` ever approves."""

    verified = "verified"
    cancelled = "cancelled"  # a real "no": cancel, failed match, retries exhausted
    unavailable = "unavailable"  # the prompt could not run at all


class HelloError(RuntimeError):
    """Hello could not do what was asked (not installed, no key, refused)."""


class HelloBackend(Protocol):
    """The Windows Hello operations Doberman needs. Injected so tests can fake it."""

    def available(self) -> bool: ...

    def verify(self, prompt: str, *, timeout_s: float) -> HelloVerdict:
        """Show the prompt. May raise ``TimeoutError`` (a deny) or anything else."""
        ...

    def sign(self, data: bytes) -> bytes: ...

    def public_key(self) -> bytes: ...

    def tpm_backed(self) -> bool | None:
        """``True`` only when Windows attests the key; ``None`` when unknown."""
        ...


def _name(value: object) -> str:
    """An enum's name, lowercased with ``_`` dropped (PyWinRT spells ``NOT_SUPPORTED``,
    older bindings ``NotSupported``)."""
    return str(getattr(value, "name", value)).lower().replace("_", "")


def tpm_backed_from_attestation(status: object) -> bool | None:
    """Map a ``KeyCredentialAttestationStatus`` to TPM-backed yes / no / unknown.

    ``Success`` means Windows produced a TPM attestation (the certificate chain is
    not verified here). ``NotSupported`` means the key has no TPM attestation.
    Anything else is unknown — never "yes".
    """
    if status is None:
        return None
    return {"success": True, "notsupported": False}.get(_name(status))


def _load_winrt():  # pragma: no cover - requires winrt on Windows
    """Return ``(ui, credentials)`` WinRT modules, or ``None`` if unavailable."""
    if sys.platform != "win32":
        return None
    try:
        from winrt.windows.security import credentials  # type: ignore
        from winrt.windows.security.credentials import ui  # type: ignore
    except Exception:  # noqa: BLE001 — any import failure means "not available"
        return None
    return ui, credentials


class WinRTHelloBackend:
    """The real backend over PyWinRT. Every method is safe to call off-Windows."""

    def available(self) -> bool:
        mods = _load_winrt()
        if mods is None:
            return False
        ui, _ = mods

        async def _check():
            return await ui.UserConsentVerifier.check_availability_async()

        return _name(asyncio.run(_check())) == "available"

    def verify(self, prompt: str, *, timeout_s: float) -> HelloVerdict:
        mods = _load_winrt()
        if mods is None:
            return HelloVerdict.unavailable
        ui, _ = mods

        async def _verify():
            return await ui.UserConsentVerifier.request_verification_async(prompt)

        result = asyncio.run(asyncio.wait_for(_verify(), timeout=timeout_s))
        return HelloVerdict.verified if _name(result) == "verified" else HelloVerdict.cancelled

    def _open_key(self):
        mods = _load_winrt()
        if mods is None:
            raise HelloError("Windows Hello (winrt) is not available")
        _, cred = mods

        async def _open():
            return await cred.KeyCredentialManager.open_async(KEY_NAME)

        res = asyncio.run(_open())
        if _name(res.status) != "success":
            raise HelloError(f"Hello key {KEY_NAME!r} not usable: {_name(res.status)}")
        return res.credential

    def sign(self, data: bytes) -> bytes:
        key = self._open_key()

        async def _sign():
            return await key.request_sign_async(data)

        res = asyncio.run(_sign())
        if _name(res.status) != "success":
            raise HelloError(f"Hello signing refused: {_name(res.status)}")
        return bytes(res.result)

    def public_key(self) -> bytes:
        # X.509 SubjectPublicKeyInfo DER (the WinRT default blob type).
        return bytes(self._open_key().retrieve_public_key())

    def tpm_backed(self) -> bool | None:
        try:
            key = self._open_key()
        except Exception:  # noqa: BLE001 — no key / no winrt: unknown, never yes
            return None

        async def _attest():
            return await key.get_attestation_async()

        try:
            return tpm_backed_from_attestation(asyncio.run(_attest()).status)
        except Exception:  # noqa: BLE001
            return None


class WindowsHelloMethod:
    """Approve an action with a Windows Hello biometric prompt."""

    name = "windows_hello"

    def __init__(self, backend: HelloBackend | None = None) -> None:
        self._backend: HelloBackend = backend if backend is not None else WinRTHelloBackend()

    def is_available(self) -> bool:
        """True only when the backend says Hello is available. Conservative and never
        raises: any failure or non-``True`` answer returns ``False``."""
        try:
            return self._backend.available() is True
        except Exception:  # noqa: BLE001 — any doubt means not available
            logger.debug("Windows Hello availability check failed; treating as unavailable")
            return False

    def request(self, prompt: str, *, action_id: str, timeout_s: float) -> ApprovalOutcome:
        """Show the Hello prompt for ``prompt`` and map the result.

        ``verified`` → approved; ``unavailable`` → unavailable (the caller falls back
        to TOTP); a timeout → denied; the backend raising → unavailable; anything
        else (cancel, failed match, an unexpected value) → denied. Never raises.
        """
        try:
            verdict = self._backend.verify(prompt, timeout_s=timeout_s)
        except TimeoutError:
            logger.info("Windows Hello verification timed out; denying")
            return ApprovalOutcome.denied
        except Exception:  # noqa: BLE001 — could not display/run the prompt → defer to TOTP
            logger.info("Windows Hello could not run the prompt; falling back", exc_info=True)
            return ApprovalOutcome.unavailable
        if verdict is HelloVerdict.verified:
            return ApprovalOutcome.approved
        if verdict is HelloVerdict.unavailable:
            return ApprovalOutcome.unavailable
        return ApprovalOutcome.denied
