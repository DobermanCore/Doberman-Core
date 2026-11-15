"""Windows Hello approval method — a local biometric (face / fingerprint / PIN) tap.

The method talks to Windows through an injected :class:`HelloBackend`. The real one,
:class:`WinRTHelloBackend`, uses the PyWinRT ``winrt-*`` packages
(``pip install doberman-core[winhello]``): ``UserConsentVerifier`` shows the system
Windows Hello prompt carrying the action text, and ``KeyCredentialManager`` holds the
``doberman-proof`` key for :meth:`HelloBackend.sign` / :meth:`HelloBackend.public_key`.
Hello-required mode (:mod:`doberman.auth.hello_mode`) signs proofs with that key through
:class:`SignerProcessBackend`, in a child process.

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
import base64
import json
import logging
import subprocess
import sys
import threading
from enum import Enum
from typing import Protocol

from doberman.auth.approval import DEFAULT_APPROVAL_TIMEOUT_S, ApprovalOutcome

logger = logging.getLogger("doberman.auth.methods.windows_hello")

#: The ``KeyCredentialManager`` key name Doberman signs proofs with.
KEY_NAME = "doberman-proof"

#: The child process Hello-required mode signs in (see :class:`SignerProcessBackend`).
SIGNER_MODULE = "doberman.auth.hello_signer"
#: Extra seconds the child gets over its own signing timeout, to start up.
_CHILD_START_S = 15.0
#: The Hello dialog's window class (Chromium foregrounds the same one for the same bug).
_HELLO_DIALOG_CLASS = "Credential Dialog Xaml Host"


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

    def ensure_key(self) -> None:
        """Create the ``doberman-proof`` key if it does not exist (may show a gesture)."""
        ...

    def sign(self, data: bytes, *, timeout_s: float | None = None) -> bytes:
        """A Hello-key signature over ``data`` after a gesture. Raises on any failure."""
        ...

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


def _foreground_window() -> int:  # pragma: no cover - Windows only
    """The foreground window's handle (0 when there is none or it cannot be read)."""
    if sys.platform != "win32":
        return 0
    try:
        import ctypes

        user32 = ctypes.WinDLL("user32")
        user32.GetForegroundWindow.restype = ctypes.c_void_p
        return int(user32.GetForegroundWindow() or 0)
    except Exception:  # noqa: BLE001 - no owner window: the plain prompt still works
        return 0


def _raise_hello_dialog(stop: threading.Event) -> None:  # pragma: no cover - Windows only
    """Best effort, signing child only: bring the Hello dialog to the front until ``stop``.

    Windows opens it under other windows for a caller without a foreground window;
    Chromium works around the same bug this way (``crypto/user_verifying_key_win.cc``).
    """
    if sys.platform != "win32":
        return
    try:
        import ctypes

        user32 = ctypes.WinDLL("user32")
        user32.FindWindowW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
        user32.FindWindowW.restype = ctypes.c_void_p
        user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
        while not stop.wait(0.25):
            hwnd = user32.FindWindowW(_HELLO_DIALOG_CLASS, None)
            if hwnd:
                user32.SetForegroundWindow(hwnd)
    except Exception:  # noqa: BLE001, S110 - cosmetic; the prompt works without it
        pass


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

    def ensure_key(self) -> None:
        mods = _load_winrt()
        if mods is None:
            raise HelloError("Windows Hello (winrt) is not available")
        _, cred = mods

        async def _open_or_create():
            res = await cred.KeyCredentialManager.open_async(KEY_NAME)
            if _name(res.status) == "notfound":
                # FAIL_IF_EXISTS: never silently replace a key someone already pinned.
                res = await cred.KeyCredentialManager.request_create_async(
                    KEY_NAME, cred.KeyCredentialCreationOption.FAIL_IF_EXISTS
                )
            return res

        res = asyncio.run(_open_or_create())
        if _name(res.status) != "success":
            raise HelloError(f"Hello key {KEY_NAME!r} could not be created: {_name(res.status)}")

    def sign(self, data: bytes, *, timeout_s: float | None = None) -> bytes:
        """One gesture, one signature. Runs inside the signing child process.

        The prompt is bound to the foreground window where Windows offers
        ``RequestSignForWindowAsync``, and the dialog is pulled to the front while it is
        open: started from a console-less process it otherwise opens behind other windows.
        """
        key = self._open_key()
        hwnd = _foreground_window()

        async def _sign():
            window_bound = getattr(key, "request_sign_for_window_async", None)
            if hwnd and window_bound is not None:
                return await window_bound((hwnd,), data)
            return await key.request_sign_async(data)

        stop = threading.Event()
        threading.Thread(target=_raise_hello_dialog, args=(stop,), daemon=True).start()
        try:
            res = asyncio.run(asyncio.wait_for(_sign(), timeout=timeout_s))
        finally:
            stop.set()
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


class SignerProcessBackend(WinRTHelloBackend):
    """Hello-required mode's backend: :meth:`sign` runs in a short-lived child process,
    ``python -P -m doberman.auth.hello_signer``.

    Signing shows a prompt from the hook process. In the child, a native crash, a hang or bad
    output becomes a :class:`HelloError` (a denial); in the hook process it would end the
    process, which the host treats as no objection. The child is not trusted: the caller
    checks the signature against the pinned key. ``-P`` keeps the working directory (the
    agent's repository) off the child's import path.
    """

    def sign(self, data: bytes, *, timeout_s: float | None = None) -> bytes:
        limit = DEFAULT_APPROVAL_TIMEOUT_S if timeout_s is None else timeout_s
        request = json.dumps({"data": base64.b64encode(data).decode("ascii"), "timeout_s": limit})
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv: this interpreter and our module
                [sys.executable, "-P", "-m", SIGNER_MODULE],
                input=request.encode("ascii"),
                capture_output=True,
                timeout=limit + _CHILD_START_S,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
            if done.returncode != 0:
                raise HelloError(f"the Hello signer exited with {done.returncode}")
            return base64.b64decode(json.loads(done.stdout)["signature"], validate=True)
        except HelloError:
            raise
        except Exception as exc:  # noqa: BLE001 - timeout, no interpreter, bad output: deny
            raise HelloError(f"the Hello signer failed ({type(exc).__name__})") from exc


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
