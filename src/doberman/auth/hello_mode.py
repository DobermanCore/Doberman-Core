"""Hello-required mode (ADR 0119, slices 2-3): proof tier becomes a signed Windows Hello gesture.

Opt-in, Windows only. An elevated ``doberman 2fa hello enroll`` writes a machine marker,
``%ProgramData%\\doberman\\proof.json``, that only administrators can change and that pins
the public key of the ``doberman-proof`` Hello key. While a marker exists:

* the proof tiers (``two_factor``, ``role_elevation``) are satisfied ONLY by a signature of
  that Hello key over a message naming the action (:mod:`doberman.auth.hello_proof`), which
  must verify against the pinned key (:func:`prove`);
* TOTP is refused on every channel (:func:`doberman.auth.totp.verify` returns ``False``), so
  a planted ``totp.secret`` approves nothing;
* Hello being unavailable, cancelled, timing out or raising is a denial, never a fallback.

Fail closed: a marker that exists but cannot be read or parsed counts as ON (``corrupt``).
Only a marker that is absent everywhere means off, which is today's behavior unchanged.

This narrows the "a script can answer its own prompt" gap (no 2FA secret exists to steal);
it does not close it. See docs/LIMITATIONS.md.

``DOBERMAN_HELLO_MARKER`` is a TEST-ONLY override. It can only ADD a marker location: it
never hides a machine marker, so setting it cannot turn the mode off, and ``enroll`` /
``leave`` refuse to run while it is set on a machine that has a machine location (a script can
``setx`` it, and an elevated terminal would inherit it). ``doctor`` warns when it is set.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import stat
import sys
import threading
from dataclasses import replace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from doberman.auth import hello_proof
from doberman.auth.approval import DEFAULT_APPROVAL_TIMEOUT_S
from doberman.auth.methods.windows_hello import (
    HelloBackend,
    PowerShellHelloBackend,
    WindowsHelloMethod,
)

logger = logging.getLogger("doberman.auth.hello_mode")

#: Test-only override for the marker location (adds a location; never hides one).
MARKER_ENV = "DOBERMAN_HELLO_MARKER"
MARKER_VERSION = 1

#: Longest wait for the Hello availability check before calling Hello unavailable.
_AVAILABLE_TIMEOUT_S = 15.0

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

ADMINS_SID, SYSTEM_SID = "S-1-5-32-544", "S-1-5-18"
#: Owner Administrators; protected DACL: Administrators and SYSTEM full, Users read+execute.
_MARKER_DIR_SDDL = "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)"


class HelloModeError(RuntimeError):
    """Enroll or leave cannot safely proceed (nothing was changed)."""


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


def admin_marker_path() -> Path:
    """Where enroll writes and what leave removes.

    Always the machine location when one exists, and then the test override is refused
    outright. The override is used only where no machine location exists (tests).
    """
    machine = _machine_marker_paths()
    if machine:
        if override_set():
            raise HelloModeError(
                f"{MARKER_ENV} is set; it is a test-only override, so unset it and run again"
            )
        # %ProgramData% alone is user-controlled; only the shell's known folder is trusted here
        if _known_program_data() is None:
            raise HelloModeError("cannot locate ProgramData through Windows; nothing changed")
        return machine[0]
    override = _override_path()
    if override is None:
        raise HelloModeError("there is no marker location on this machine")
    return override


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
    """The Hello backend this mode uses (each operation is a PowerShell child). Tests replace it."""
    return PowerShellHelloBackend()


def available() -> bool:
    """True only when the Hello backend says it can prompt here. Never raises; doubt is False.

    A pre-check for commands that need a gesture, so they refuse with a clear message before
    asking anything. It never approves: :func:`prove` still has to verify a signature.
    Runs on its own thread, so a slow PowerShell child cannot hold the caller (the policy
    weaken gate calls this from inside a running event loop) past the bound.
    """
    answer: list[object] = []

    def _check() -> None:
        try:
            answer.append(backend().available())
        except Exception:  # noqa: BLE001, S110 - no PowerShell, Constrained Language, no sensor
            pass

    worker = threading.Thread(target=_check, name="doberman-hello-available", daemon=True)
    worker.start()
    worker.join(_AVAILABLE_TIMEOUT_S)
    return not worker.is_alive() and len(answer) == 1 and answer[0] is True


def pinned_public_key() -> bytes:
    """The one public key the markers pin. Raises if none is pinned, any marker is
    unreadable or corrupt, or two markers pin different keys."""
    keys = set()
    for path in _candidates():
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            continue
        keys.add(base64.b64decode(parse_marker(raw)["public_key"], validate=True))
    if len(keys) != 1:
        raise ValueError("no single pinned Hello key")
    return keys.pop()


def prove(
    *,
    action_id: str,
    action_hash: str,
    timeout_s: float = DEFAULT_APPROVAL_TIMEOUT_S,
) -> tuple[bool, str, hello_proof.Proof | None]:
    """One Hello gesture that signs this action: ``(True, "windows_hello", proof)`` only when
    the signature verifies against the pinned key (see :func:`hello_proof.accept`).

    No pinned key, a malformed action, a cancelled or failed gesture, a timeout, a signature
    by any other key or over any other message, or any error: ``(False,
    HELLO_REQUIRED_METHOD, None)``. There is no fallback. Never raises.
    """
    try:
        public_key = pinned_public_key()
        challenge = hello_proof.new_challenge(action_id, action_hash)
        signature = backend().sign(challenge.message(), timeout_s=timeout_s)
        proof = replace(
            challenge, signature=bytes(signature), key_id=hello_proof.key_id(public_key)
        )
        if hello_proof.accept(
            proof, action_id=action_id, action_hash=action_hash, public_key=public_key
        ):
            return True, WindowsHelloMethod.name, proof
        why = "the signature did not verify against the pinned key"
    except Exception as exc:  # noqa: BLE001 - no key, no backend, no gesture: deny
        why = type(exc).__name__
    logger.warning("proof tier refused for action %r (%s). %s", action_id, why, FIX_HINT)
    return False, HELLO_REQUIRED_METHOD, None


def is_elevated() -> bool:
    """True only in an elevated (administrator) process. Any doubt is False."""
    if not supported():
        return False
    try:  # pragma: no cover - Windows only
        import ctypes

        return bool(ctypes.WinDLL("shell32").IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _is_reparse_point(path: Path) -> bool:
    """True for a junction, symlink or other reparse point (never followed)."""
    st = os.lstat(path)
    return stat.S_ISLNK(st.st_mode) or bool(
        getattr(st, "st_file_attributes", 0) & 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
    )


def _owner_sid(path: Path) -> str:  # pragma: no cover - Windows only
    """The owner SID of ``path`` as a string (``S-1-5-32-544``)."""
    import ctypes
    from ctypes import wintypes

    advapi32, kernel32 = ctypes.WinDLL("advapi32"), ctypes.WinDLL("kernel32")
    owner, sd = ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION = 1
    err = advapi32.GetNamedSecurityInfoW(
        str(path), 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(sd)
    )
    if err:
        raise ctypes.WinError(err)
    try:
        text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(owner, ctypes.byref(text)):
            raise ctypes.WinError()
        try:
            return str(text.value)
        finally:
            kernel32.LocalFree(text)
    finally:
        kernel32.LocalFree(sd)


class _SecurityDescriptor:  # pragma: no cover - Windows only
    """The marker folder's descriptor from :data:`_MARKER_DIR_SDDL`, freed on exit."""

    def __enter__(self):
        import ctypes

        self._ctypes = ctypes
        self.sd = ctypes.c_void_p()
        if not ctypes.WinDLL("advapi32").ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _MARKER_DIR_SDDL, 1, ctypes.byref(self.sd), None
        ):
            raise ctypes.WinError()
        return self.sd

    def __exit__(self, *exc):
        self._ctypes.WinDLL("kernel32").LocalFree(self.sd)


def _create_secure_dir(directory: Path) -> None:  # pragma: no cover - Windows only
    """Create the folder with its descriptor applied at creation (fails if it exists)."""
    import ctypes
    from ctypes import wintypes

    class _SA(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    with _SecurityDescriptor() as sd:
        sa = _SA(ctypes.sizeof(_SA), sd, False)
        if not ctypes.WinDLL("kernel32").CreateDirectoryW(str(directory), ctypes.byref(sa)):
            raise ctypes.WinError()


def _apply_marker_acl(directory: Path) -> None:  # pragma: no cover - Windows only
    """Replace an existing admin-owned folder's owner and DACL with the marker descriptor."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32")
    with _SecurityDescriptor() as sd:
        owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        defaulted, present = wintypes.BOOL(), wintypes.BOOL()
        if not advapi32.GetSecurityDescriptorOwner(
            sd, ctypes.byref(owner), ctypes.byref(defaulted)
        ):
            raise ctypes.WinError()
        if not advapi32.GetSecurityDescriptorDacl(
            sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise ctypes.WinError()
        # OWNER | DACL | PROTECTED_DACL security information, on SE_FILE_OBJECT.
        err = advapi32.SetNamedSecurityInfoW(
            str(directory), 1, 0x1 | 0x4 | 0x80000000, owner, None, dacl, None
        )
        if err:
            raise ctypes.WinError(err)


def _dir_problem(directory: Path) -> str | None:
    """Why an existing marker folder cannot be trusted, or ``None``."""
    if _is_reparse_point(directory):
        return f"{directory} is a reparse point (junction or link)"
    if _owner_sid(directory) not in (ADMINS_SID, SYSTEM_SID):
        return f"{directory} is not owned by Administrators"
    return None


def marker_dir_problems() -> list[str]:
    """Doctor: problems with any existing machine marker folder."""
    problems = []
    for p in _machine_marker_paths():
        if os.path.lexists(p.parent):
            problem = _dir_problem(p.parent)
            if problem:
                problems.append(problem)
    return problems


def _secure_marker_dir(directory: Path) -> None:
    """Make sure only administrators can change the marker folder, or raise.

    A folder that already exists (Users may create folders in ProgramData) is refused if it
    is a reparse point or not owned by Administrators/SYSTEM; an admin-owned one gets the
    marker descriptor reapplied. A missing one is created with the descriptor applied at
    creation, so there is no moment with a weaker ACL. Checked again afterwards.
    """
    if os.path.lexists(directory):
        problem = _dir_problem(directory)
        if problem:
            raise HelloModeError(f"{problem}; delete it from an administrator terminal first")
        _apply_marker_acl(directory)
    else:
        _create_secure_dir(directory)
    problem = _dir_problem(directory)
    if problem:
        raise HelloModeError(f"could not secure the marker folder: {problem}")


def write_marker(path: Path, public_key: bytes, *, now: datetime | None = None) -> None:
    """Write a v1 marker holding the pinned public key (slice 3 verifies against it).

    A machine location's folder is secured BEFORE anything is written; if that fails,
    nothing is written. The temp file is created exclusively, so a planted one is never
    reused. The test override location (no machine location exists) is a plain file.
    """
    when = (now or datetime.now(timezone.utc)).isoformat()
    body = {
        "version": MARKER_VERSION,
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "enrolled_at": when,
    }
    machine = path in _machine_marker_paths()
    if machine:
        _secure_marker_dir(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True))
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if machine:
        # where policy makes the creator the owner, the user could later rewrite the file's ACL
        problem = _dir_problem(path)
        if problem:
            path.unlink(missing_ok=True)
            raise HelloModeError(f"{problem}; nothing was enrolled")


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
