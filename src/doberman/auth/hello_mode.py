"""Hello-required mode (ADR 0119, slice 2): proof tier becomes a Windows Hello gesture.

Opt-in, Windows only. An elevated ``doberman 2fa hello enroll`` writes a machine marker,
``%ProgramData%\\doberman\\proof.json``, that only administrators can change. While a
marker exists:

* the proof tiers (``two_factor``, ``role_elevation``) are satisfied ONLY by a Windows Hello
  verification through the :class:`~doberman.auth.methods.windows_hello.HelloBackend`;
* TOTP is refused on every channel (:func:`doberman.auth.totp.verify` returns ``False``), so
  a planted ``totp.secret`` approves nothing;
* Hello being unavailable, cancelled, timing out or raising is a denial, never a fallback.

Fail closed: a marker that exists but cannot be read or parsed counts as ON (``corrupt``).
Only a marker that is absent everywhere means off, which is today's behavior unchanged.

This narrows the "a script can answer its own prompt" gap (no 2FA secret exists to steal);
it does not close it. See docs/LIMITATIONS.md.

``DOBERMAN_HELLO_MARKER`` is a TEST-ONLY override. It can only ADD a marker location: it
never hides a machine marker, so setting it cannot turn the mode off. ``doctor`` warns when
it is set.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import subprocess  # noqa: S404 - icacls with a fixed argument list
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from doberman.auth.approval import (
    DEFAULT_APPROVAL_TIMEOUT_S,
    ApprovalOutcome,
    request_approval,
)
from doberman.auth.methods.windows_hello import (
    HelloBackend,
    WindowsHelloMethod,
    WinRTHelloBackend,
)

logger = logging.getLogger("doberman.auth.hello_mode")

#: Test-only override for the marker location (adds a location; never hides one).
MARKER_ENV = "DOBERMAN_HELLO_MARKER"
MARKER_VERSION = 1

#: The ``AuthResult.method`` of a proof-tier denial in this mode.
HELLO_REQUIRED_METHOD = "hello_required"

#: What to tell a person whose proof-tier approval was refused in this mode.
FIX_HINT = (
    "Doberman is in Hello-required mode: approve with the Windows Hello prompt on this "
    "machine (check the taskbar if it opened behind other windows). TOTP codes, the phone "
    "and the dashboard cannot approve this action. If Hello cannot run here, approve from "
    "an interactive desktop session, or leave the mode from an administrator terminal "
    "with `doberman 2fa hello leave`."
)

# Administrators, SYSTEM, Users: well-known SIDs, so the ACL does not depend on the locale.
_ADMINS, _SYSTEM, _USERS = "*S-1-5-32-544", "*S-1-5-18", "*S-1-5-32-545"


class Mode(str, Enum):
    off = "off"
    on = "on"
    corrupt = "corrupt"  # a marker exists but is unreadable: treated as on


def supported() -> bool:
    """Hello-required mode exists only on Windows."""
    return sys.platform == "win32"


def _known_program_data() -> Path | None:  # pragma: no cover - Windows only
    """``FOLDERID_ProgramData`` from the shell, independent of the process environment."""
    import ctypes
    import uuid
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [("bytes", ctypes.c_ubyte * 16)]

    guid = _GUID()
    guid.bytes[:] = uuid.UUID("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97").bytes_le
    out = ctypes.c_wchar_p()
    shell32 = ctypes.WinDLL("shell32")
    shell32.SHGetKnownFolderPath.argtypes = [
        ctypes.POINTER(_GUID),
        wintypes.DWORD,
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    if shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return Path(out.value) if out.value else None
    finally:
        ctypes.WinDLL("ole32").CoTaskMemFree(out)


def _machine_marker_paths() -> list[Path]:
    """Every machine location a marker may live in. Empty off Windows.

    Both the shell's ProgramData folder and ``%ProgramData%`` are checked, so a per-user
    environment override of ``ProgramData`` cannot hide the real marker.
    """
    if not supported():
        return []
    dirs: list[Path] = []
    known = _known_program_data()
    if known is not None:
        dirs.append(known)
    env = os.environ.get("ProgramData")
    if env:
        dirs.append(Path(env))
    if not dirs:
        raise OSError("cannot locate ProgramData")
    paths: list[Path] = []
    for d in dirs:
        p = d / "doberman" / "proof.json"
        if p not in paths:
            paths.append(p)
    return paths


def _override_path() -> Path | None:
    value = os.environ.get(MARKER_ENV)
    return Path(value) if value else None


def override_set() -> bool:
    return _override_path() is not None


def marker_path() -> Path | None:
    """Where enroll writes: the test override when set, else the machine location."""
    override = _override_path()
    if override is not None:
        return override
    machine = _machine_marker_paths()
    return machine[0] if machine else None


def _candidates() -> list[Path]:
    paths = list(_machine_marker_paths())
    override = _override_path()
    if override is not None and override not in paths:
        paths.append(override)
    return paths


def parse_marker(raw: bytes) -> dict:
    """Validate a marker's bytes. Raises ``ValueError`` on anything but a v1 marker."""
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or data.get("version") != MARKER_VERSION:
        raise ValueError("not a version 1 marker")
    key, when = data.get("public_key"), data.get("enrolled_at")
    if not isinstance(key, str) or not key or not isinstance(when, str) or not when:
        raise ValueError("marker is missing its public key or enrollment time")
    try:
        base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("public key is not base64") from exc
    return data


def _state_of(path: Path) -> Mode:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return Mode.off
    except OSError:  # unreadable, a directory, a broken parent: fail closed
        return Mode.corrupt
    try:
        parse_marker(raw)
    except ValueError:  # includes JSON and UTF-8 decode errors
        return Mode.corrupt
    return Mode.on


def mode() -> Mode:
    """``corrupt`` if any marker is unreadable, ``on`` if any is valid, else ``off``.

    Raises only if the marker locations cannot be determined; :func:`is_on` turns that
    into ON.
    """
    states = {_state_of(p) for p in _candidates()}
    if Mode.corrupt in states:
        return Mode.corrupt
    return Mode.on if Mode.on in states else Mode.off


def is_on() -> bool:
    """True when proof tier must be a Hello gesture. Never raises; any doubt is True."""
    try:
        return mode() is not Mode.off
    except Exception:  # noqa: BLE001 - cannot tell whether a marker exists: fail closed
        logger.warning("could not determine Hello-required mode; treating it as on")
        return True


def backend() -> HelloBackend:
    """The Hello backend this mode uses. Tests replace this function."""
    return WinRTHelloBackend()


def verify(
    prompt: str,
    *,
    action_id: str,
    timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S,
) -> tuple[bool, str]:
    """One Hello gesture for ``prompt``: ``(True, "windows_hello")`` only on ``verified``.

    Unavailable, cancelled, timed out, a raising backend, or no backend at all all return
    ``(False, HELLO_REQUIRED_METHOD)``. There is no fallback. Never raises.
    """
    try:
        method = WindowsHelloMethod(backend())
        outcome = request_approval(method, prompt, action_id=action_id, timeout_s=timeout_s)
    except Exception:  # noqa: BLE001 - no backend: deny
        outcome = ApprovalOutcome.unavailable
    if outcome is ApprovalOutcome.approved:
        return True, WindowsHelloMethod.name
    logger.warning("proof tier refused for action %s (%s). %s", action_id, outcome.value, FIX_HINT)
    return False, HELLO_REQUIRED_METHOD


def is_elevated() -> bool:
    """True only in an elevated (administrator) process. Any doubt is False."""
    if not supported():
        return False
    try:  # pragma: no cover - Windows only
        import ctypes

        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _icacls(*args: str) -> None:  # pragma: no cover - Windows only
    subprocess.run(["icacls", *args, "/C", "/Q"], check=True, capture_output=True)  # noqa: S603 S607


def _restrict_dir(directory: Path) -> None:  # pragma: no cover - Windows only
    """Administrators own the folder and alone may write it; Users may only read.

    Ownership moves to Administrators first, so a folder a user pre-created cannot keep
    its owner's implicit right to rewrite the ACL; explicit entries are then reset and
    inheritance from ProgramData (which lets Users create files) is cut.
    """
    target = str(directory)
    _icacls(target, "/setowner", _ADMINS, "/T")
    _icacls(target, "/reset", "/T")
    _icacls(
        target,
        "/inheritance:r",
        "/grant:r",
        f"{_ADMINS}:(OI)(CI)F",
        f"{_SYSTEM}:(OI)(CI)F",
        f"{_USERS}:(OI)(CI)RX",
    )


def write_marker(path: Path, public_key: bytes, *, now: datetime | None = None) -> None:
    """Write a v1 marker holding the pinned public key (slice 3 verifies against it).

    A machine location gets an admins-only ACL BEFORE the file is written; if that fails
    nothing is written. The test override location is written as a plain file.
    """
    when = (now or datetime.now(timezone.utc)).isoformat()
    body = {
        "version": MARKER_VERSION,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "enrolled_at": when,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    if path != _override_path():
        _restrict_dir(path.parent)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def remove_markers() -> list[Path]:
    """Delete every existing marker (valid or corrupt). Returns what was removed.

    Raises ``OSError`` if one exists but cannot be removed (the mode stays on).
    """
    removed: list[Path] = []
    for p in _candidates():
        if _state_of(p) is Mode.off:
            continue
        p.unlink()
        removed.append(p)
    return removed
