"""Windows Hello approval method — a local biometric (face / fingerprint / PIN) tap.

Uses the WinRT ``UserConsentVerifier`` API through the optional ``winsdk`` package
(``pip install doberman-core[winhello]``). The verifier shows the system Windows
Hello prompt carrying the action text; a successful verification is the possession
+ inherence factor that replaces the TOTP code.

This backend is **best-effort and fail-safe**:

* Not Windows, ``winsdk`` not installed, or no Hello device enrolled →
  :meth:`is_available` returns ``False`` (the challenge falls back to TOTP).
* The verifier runs but the human cancels / fails / times out → ``denied``.
* The prompt cannot be displayed at all (a console-process / windowing quirk of
  the WinRT consent UI) → ``unavailable`` (fall back to TOTP), never ``approved``.

The WinRT consent dialog historically prefers an owning window; from a bare
console process it may report itself unusable, in which case this method defers to
TOTP rather than blocking the human. Verify on a real Hello-enrolled machine — CI
has neither ``winsdk`` nor a Hello device, so there ``is_available`` is ``False``
and only the non-Windows path is exercised.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from doberman.auth.approval import ApprovalOutcome

logger = logging.getLogger("doberman.auth.methods.windows_hello")


def _load_ui():  # pragma: no cover - requires winsdk on Windows
    """Return the WinRT UserConsentVerifier UI module, or ``None`` if unavailable."""
    if sys.platform != "win32":
        return None
    try:
        from winsdk.windows.security.credentials import ui  # type: ignore
    except Exception:  # noqa: BLE001 — any import failure means "not available"
        return None
    return ui


def _availability_is_available(ui) -> bool:  # pragma: no cover - requires winsdk
    """Await ``UserConsentVerifier.check_availability_async`` and test == Available.

    Robust to winsdk enum spelling: compares the result's name case-insensitively
    to ``available`` rather than pinning a specific enum member object.
    """

    async def _check():
        return await ui.UserConsentVerifier.check_availability_async()

    result = asyncio.run(_check())
    return str(getattr(result, "name", result)).lower() == "available"


class WindowsHelloMethod:
    """Approve an action with a Windows Hello biometric prompt."""

    name = "windows_hello"

    def is_available(self) -> bool:
        """True only on Windows with ``winsdk`` installed and Hello reporting
        available. Conservative and never raises: any failure returns ``False``."""
        ui = _load_ui()
        if ui is None:
            return False
        try:  # pragma: no cover - requires winsdk on Windows
            return _availability_is_available(ui)
        except Exception:  # noqa: BLE001 — any doubt means not available
            logger.debug("Windows Hello availability check failed; treating as unavailable")
            return False

    def request(
        self, prompt: str, *, action_id: str, timeout_s: float
    ) -> ApprovalOutcome:  # pragma: no cover - requires winsdk on Windows
        """Show the Hello prompt for ``prompt`` and map the result.

        ``Verified`` → approved; any other result (cancel/fail/retries-exhausted)
        → denied; a timeout → denied; a display/interop failure → unavailable so
        the caller falls back to TOTP. Never raises (the resolver would deny it
        anyway, but returning cleanly lets the unavailable→TOTP path work).
        """
        ui = _load_ui()
        if ui is None:
            return ApprovalOutcome.unavailable

        async def _verify():
            return await ui.UserConsentVerifier.request_verification_async(prompt)

        try:
            result = asyncio.run(asyncio.wait_for(_verify(), timeout=timeout_s))
        except asyncio.TimeoutError:
            logger.info("Windows Hello verification timed out; denying")
            return ApprovalOutcome.denied
        except Exception:  # noqa: BLE001 — could not display/run the prompt → defer to TOTP
            logger.info("Windows Hello could not run the prompt; falling back", exc_info=True)
            return ApprovalOutcome.unavailable
        return (
            ApprovalOutcome.approved
            if str(getattr(result, "name", result)).lower() == "verified"
            else ApprovalOutcome.denied
        )
