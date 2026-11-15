"""Windows Hello approval method — a local biometric (face / fingerprint / PIN) tap.

The method talks to Windows through an injected :class:`HelloBackend`. The real one,
:class:`PowerShellHelloBackend`, runs every operation in a short-lived child of the
Microsoft-signed Windows PowerShell 5.1 (``powershell.exe``), which drives WinRT:
``UserConsentVerifier`` shows the system Windows Hello prompt carrying the action text, and
``KeyCredentialManager`` holds the ``doberman-proof`` key for :meth:`HelloBackend.sign` /
:meth:`HelloBackend.public_key`. No extra Python package is needed, so an App Control policy
that blocks unsigned native modules (Smart App Control) does not block Hello.

The child runs a fixed script (:data:`HELLO_SCRIPT`, passed with ``-EncodedCommand``); every
caller value (operation, prompt text, message bytes, key name) goes on stdin as JSON, never
into the script. It answers with one JSON line; anything else is an error. The child is not
trusted for proofs: Hello-required mode checks each signature against the pinned key.

This method is **best-effort and fail-safe**:

* Not Windows, PowerShell missing or not in FullLanguage mode, or no Hello device enrolled →
  :meth:`WindowsHelloMethod.is_available` returns ``False`` (the challenge falls back
  to TOTP; in Hello-required mode it is a denial).
* The verifier runs but the human cancels / fails / times out → ``denied``.
* The prompt cannot be displayed at all, or the backend raises →
  ``unavailable`` (fall back to TOTP), never ``approved``.

Verify on a real Hello-enrolled machine (``docs/HELLO-HARDWARE-CHECKS.md``) — CI has no
Hello device.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import subprocess
import sys
from enum import Enum
from typing import Protocol

from doberman.auth.approval import DEFAULT_APPROVAL_TIMEOUT_S, ApprovalOutcome

logger = logging.getLogger("doberman.auth.methods.windows_hello")

#: The ``KeyCredentialManager`` key name Doberman signs proofs with.
KEY_NAME = "doberman-proof"

#: Seconds the child may wait on a non-prompting WinRT call (availability, open key).
_QUICK_TIMEOUT_S = 10.0
#: Seconds the child may wait for a TPM attestation.
_ATTEST_TIMEOUT_S = 60.0
#: Extra seconds the process gets over the child's own wait, to start up.
_CHILD_START_S = 15.0
#: Largest stdout accepted from the child; a real reply is well under 1 KiB.
_MAX_REPLY_BYTES = 16 * 1024
_CREATE_NO_WINDOW = 0x08000000
#: The only variables the child keeps from this process (temp folder and profile paths).
_PASS_ENV = (
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "USERNAME",
    "USERDOMAIN",
    "COMPUTERNAME",
    "HOMEDRIVE",
    "HOMEPATH",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
)
_MAX_PATH = 260

#: The one script the child runs. Constant: caller data arrives on stdin, never in here.
#: Replies: ``{"status": <WinRT status name>, "value": <string or null>}`` or
#: ``{"error": "language_mode" | "timeout" | "failed"}``, as one line.
HELLO_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { '{"error":"language_mode"}'; exit 0 }

# Started from a process with no foreground window, the Hello dialog opens behind other
# windows, and Windows will not let this process raise it. So each prompt is bound to the
# window in front (the one the person is using), and an unfocused dialog is flashed.
$windowSource = @'
using System;
using System.Runtime.InteropServices;
public static class DobermanHelloWindow {
    // userconsentverifierinterop.h (Windows build 22000+)
    [ComImport, Guid("39E050C3-4E74-441A-8DC0-B81104DF949C"), InterfaceType(ComInterfaceType.InterfaceIsIInspectable)]
    interface IUserConsentVerifierInterop {
        [return: MarshalAs(UnmanagedType.IInspectable)]
        object RequestVerificationForWindowAsync(IntPtr appWindow, [MarshalAs(UnmanagedType.HString)] string message, [In] ref Guid riid);
    }
    [StructLayout(LayoutKind.Sequential)]
    struct FlashInfo { public uint Size; public IntPtr Window; public uint Flags; public uint Count; public uint Timeout; }
    [DllImport("user32.dll")]
    static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")]
    static extern bool FlashWindowEx(ref FlashInfo info);
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    public static object VerifyForWindow(object factory, IntPtr window, string message, Guid riid) {
        return ((IUserConsentVerifierInterop)factory).RequestVerificationForWindowAsync(window, message, ref riid);
    }
    public static bool CanVerifyForWindow(object factory) { return factory is IUserConsentVerifierInterop; }
    public static void Raise(IntPtr dialog) {
        if (dialog == IntPtr.Zero || dialog == GetForegroundWindow()) { return; }
        SetForegroundWindow(dialog);
        // shortcut: FlashWindowEx returned FALSE (error 87) on this dialog in the 2026-11-14 probe; revisit after the hardware rerun
        FlashInfo info = new FlashInfo();
        info.Size = (uint)Marshal.SizeOf(typeof(FlashInfo));
        info.Window = dialog;
        info.Flags = 15; // FLASHW_ALL | FLASHW_TIMERNOFG: flash the taskbar button until focused
        FlashWindowEx(ref info);
    }
}
'@
$script:canRaise = $false

function Enable-Raise {
    $script:started = [DateTime]::Now
    try { Add-Type -TypeDefinition $windowSource; $script:canRaise = $true } catch { $script:canRaise = $false }
}

function Get-Front {
    if ($script:canRaise) { return [DobermanHelloWindow]::GetForegroundWindow() }
    [IntPtr]::Zero
}

# The front window as a WinRT WindowId, or $null (no window, or no WindowId on this Windows).
# Without the helper there is no foreground window handle at all, so no call can be bound.
function Get-FrontWindowId {
    $hwnd = Get-Front
    if ($hwnd -eq [IntPtr]::Zero) { return $null }
    try {
        $window = [Activator]::CreateInstance([Windows.UI.WindowId,Windows.UI,ContentType=WindowsRuntime])
        $window.Value = [uint64]$hwnd.ToInt64()
        return $window
    } catch { return $null }
}

# A class-name window search does not see the Hello dialog; its CredentialUIBroker process lists it.
function Find-Dialog {
    $found = [IntPtr]::Zero
    $newest = $script:started
    foreach ($broker in @(Get-Process CredentialUIBroker -ErrorAction SilentlyContinue)) {
        try {
            if ($broker.StartTime -ge $newest -and $broker.MainWindowHandle -ne [IntPtr]::Zero) {
                $newest = $broker.StartTime
                $found = $broker.MainWindowHandle
            }
        } catch { }
    }
    $found
}

# PowerShell 5.1 cannot pass a WinRT IBuffer (it holds it as __ComObject) to a typed parameter;
# MethodInfo.Invoke lets the runtime marshal it. Every IBuffer argument goes through here.
function Invoke-Typed([Type]$type, [string]$name, $target, [object[]]$arguments) {
    $method = $type.GetMethods() | Where-Object {
        $_.Name -eq $name -and $_.GetParameters().Count -eq $arguments.Count
    } | Select-Object -First 1
    if ($null -eq $method) { throw "no method $name" }
    $method.Invoke($target, $arguments)
}

function Wait-Op($operation, [Type]$resultType, [int]$ms) {
    $task = $script:asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $raised = [IntPtr]::Zero
    while (-not $task.Wait(250)) {
        if ($clock.ElapsedMilliseconds -ge $ms) {
            # close the prompt so it does not linger after the deny; the deny stands either way
            try { $null = [Windows.Foundation.IAsyncInfo,Windows.Foundation,ContentType=WindowsRuntime].GetMethod('Cancel').Invoke($operation, $null) } catch { }
            throw [TimeoutException]::new('timeout')
        }
        if ($script:canRaise) {
            try {
                $dialog = Find-Dialog
                if ($dialog -ne $raised) { [DobermanHelloWindow]::Raise($dialog); $raised = $dialog }
            } catch { }
        }
    }
    $task.Result
}

function Invoke-HelloOp($request) {
    $op = [string]$request.op
    $ms = [int]$request.timeout_ms
    if ($op -notin 'ping', 'available', 'selftest', 'verify', 'open', 'create', 'public_key', 'attest', 'sign') { throw 'unknown op' }
    if ($ms -le 0) { throw 'bad timeout' }
    if ($op -eq 'ping') { return @{ status = 'ok'; value = $null } }

    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $script:asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    $manager = [Windows.Security.Credentials.KeyCredentialManager,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $verifier = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]
    $buffers = [Windows.Security.Cryptography.CryptographicBuffer,Windows.Security.Cryptography,ContentType=WindowsRuntime]
    $retrieval = [Windows.Security.Credentials.KeyCredentialRetrievalResult]
    $keyCredential = [Windows.Security.Credentials.KeyCredential,Windows.Security.Credentials,ContentType=WindowsRuntime]

    if ($op -eq 'available') {
        $availability = Wait-Op ($verifier::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]) $ms
        return @{ status = [string]$availability; value = $null }
    }
    if ($op -eq 'selftest') {
        # what binding a prompt needs, resolved without calling anything that prompts
        $probe = $buffers::CreateFromByteArray([byte[]](1, 2, 3))
        if ((Invoke-Typed $buffers 'EncodeToBase64String' $null @($probe)) -ne 'AQID') {
            return @{ status = 'buffers'; value = $null }
        }
        Enable-Raise
        if (-not $script:canRaise) { return @{ status = 'helper'; value = $null } }
        $factory = [Runtime.InteropServices.WindowsRuntime.WindowsRuntimeMarshal]::GetActivationFactory($verifier)
        if (-not [DobermanHelloWindow]::CanVerifyForWindow($factory)) { return @{ status = 'interop'; value = $null } }
        $null = [Activator]::CreateInstance([Windows.UI.WindowId,Windows.UI,ContentType=WindowsRuntime])
        $create = $manager.GetMethod('RequestCreateForWindowAsync')
        $sign = [Windows.Security.Credentials.KeyCredential].GetMethod('RequestSignForWindowAsync')
        if (-not $create -or -not $sign) { return @{ status = 'window_calls'; value = $null } }
        return @{ status = 'ok'; value = $null }
    }
    if ($op -eq 'verify') {
        Enable-Raise
        $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$request.prompt))
        $verdictType = [Windows.Security.Credentials.UI.UserConsentVerificationResult]
        $pending = $null
        $hwnd = Get-Front
        if ($hwnd -ne [IntPtr]::Zero) {
            try {
                $riid = [Windows.Foundation.IAsyncOperation`1,Windows.Foundation,ContentType=WindowsRuntime].MakeGenericType($verdictType).GUID
                $factory = [Runtime.InteropServices.WindowsRuntime.WindowsRuntimeMarshal]::GetActivationFactory($verifier)
                $pending = [DobermanHelloWindow]::VerifyForWindow($factory, $hwnd, $text, $riid)
            } catch { $pending = $null }
        }
        if ($null -eq $pending) { $pending = $verifier::RequestVerificationAsync($text) }
        $verdict = Wait-Op $pending $verdictType $ms
        return @{ status = [string]$verdict; value = $null }
    }
    $key = [string]$request.key
    if ($op -eq 'create') {
        Enable-Raise
        $option = [Windows.Security.Credentials.KeyCredentialCreationOption]::FailIfExists
        $pending = $null
        $window = Get-FrontWindowId
        if ($null -ne $window) {
            try { $pending = $manager::RequestCreateForWindowAsync($window, $key, $option) } catch { $pending = $null }
        }
        if ($null -eq $pending) { $pending = $manager::RequestCreateAsync($key, $option) }
        $created = Wait-Op $pending $retrieval $ms
        return @{ status = [string]$created.Status; value = $null }
    }
    $opened = Wait-Op ($manager::OpenAsync($key)) $retrieval $ms
    if ($op -eq 'open' -or [string]$opened.Status -ne 'Success') { return @{ status = [string]$opened.Status; value = $null } }
    $credential = $opened.Credential
    if ($op -eq 'public_key') {
        return @{ status = 'Success'; value = (Invoke-Typed $buffers 'EncodeToBase64String' $null @($credential.RetrievePublicKey())) }
    }
    if ($op -eq 'attest') {
        $attestation = Wait-Op ($credential.GetAttestationAsync()) ([Windows.Security.Credentials.KeyCredentialAttestationResult]) $ms
        return @{ status = 'Success'; value = [string]$attestation.Status }
    }

    # sign: bound to the foreground window where Windows offers it, else the plain call
    Enable-Raise
    $data = $buffers::CreateFromByteArray([Convert]::FromBase64String([string]$request.data))
    $pending = $null
    $window = Get-FrontWindowId
    if ($null -ne $window) {
        try { $pending = Invoke-Typed $keyCredential 'RequestSignForWindowAsync' $credential @($window, $data) } catch { $pending = $null }
    }
    if ($null -eq $pending) { $pending = Invoke-Typed $keyCredential 'RequestSignAsync' $credential @($data) }
    $signed = Wait-Op $pending ([Windows.Security.Credentials.KeyCredentialOperationResult]) $ms
    if ([string]$signed.Status -ne 'Success') { return @{ status = [string]$signed.Status; value = $null } }
    return @{ status = 'Success'; value = (Invoke-Typed $buffers 'EncodeToBase64String' $null @($signed.Result)) }
}

try {
    $reply = Invoke-HelloOp ([Console]::In.ReadToEnd() | ConvertFrom-Json)
} catch [TimeoutException] {
    $reply = @{ error = 'timeout' }
} catch {
    $reply = @{ error = 'failed' }
}
[Console]::Out.Write(($reply | ConvertTo-Json -Compress) + "`n")
exit 0
"""

_PS_ARGS = (
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
)
_ENCODED_SCRIPT = base64.b64encode(HELLO_SCRIPT.encode("utf-16-le")).decode("ascii")


class HelloVerdict(Enum):
    """What one Hello prompt produced. Only ``verified`` ever approves."""

    verified = "verified"
    cancelled = "cancelled"  # a real "no": cancel, failed match, retries exhausted
    unavailable = "unavailable"  # the prompt could not run at all


class HelloError(RuntimeError):
    """Hello could not do what was asked (no PowerShell, no key, refused, bad reply)."""


class HelloLanguageModeError(HelloError):
    """PowerShell is not in FullLanguage mode (Constrained Language under App Control)."""


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
    """A status name, lowercased with ``_`` dropped (``NotSupported`` → ``notsupported``)."""
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


def _system_directory() -> str | None:
    """System32 as Windows reports it (``GetSystemDirectoryW``), or ``None``."""
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32")
        buf = ctypes.create_unicode_buffer(_MAX_PATH)
        n = kernel32.GetSystemDirectoryW(buf, len(buf))
    except Exception:  # noqa: BLE001 - not Windows, no kernel32: no system directory
        return None
    return buf.value if 0 < n < len(buf) else None


def system_powershell() -> str:
    """Windows PowerShell 5.1 under the real System32. Raises :class:`HelloError` if absent.

    Never from ``%SystemRoot%`` or ``PATH``: the user (and so the agent) controls those, and
    outside Hello-required mode the consent prompt's answer is trusted.
    """
    if sys.platform != "win32":
        raise HelloError("Windows Hello needs Windows")
    system = _system_directory()
    if not system:
        raise HelloError("cannot locate the Windows system directory")
    exe = os.path.join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.isfile(exe):
        raise HelloError("Windows PowerShell 5.1 is not installed")
    return exe


def _parse_reply(stdout: bytes) -> tuple[str, str | None]:
    """The child's one JSON line as ``(status, value)``. Anything else raises."""
    if len(stdout) > _MAX_REPLY_BYTES:
        raise HelloError("the Hello child wrote too much")
    try:
        line = stdout.decode("ascii").removesuffix("\n").removesuffix("\r")
        if not line or "\n" in line or "\r" in line:
            raise ValueError("not exactly one line")
        reply = json.loads(line)
    except ValueError as exc:  # also UnicodeDecodeError and JSONDecodeError
        raise HelloError("the Hello child did not answer with one JSON line") from exc
    if isinstance(reply, dict) and set(reply) == {"error"}:
        if reply["error"] == "language_mode":
            raise HelloLanguageModeError(
                "PowerShell runs in Constrained Language Mode here, so Windows Hello cannot run"
            )
        if reply["error"] == "timeout":
            raise TimeoutError("Windows Hello timed out")
        raise HelloError("the Hello child reported a failure")
    if (
        not isinstance(reply, dict)
        or set(reply) != {"status", "value"}
        or not isinstance(reply["status"], str)
        or not (reply["value"] is None or isinstance(reply["value"], str))
    ):
        raise HelloError("the Hello child's answer has the wrong shape")
    return reply["status"], reply["value"]


def _child_env(exe: str) -> dict[str, str]:
    """A minimal environment for the child, its Windows paths derived from ``exe``.

    Nothing else passes through: ``COR_PROFILER*``, ``COMPlus_*`` or a user ``PSModulePath``
    could load someone else's code into the child, whose consent answer is trusted outside
    Hello-required mode.
    """
    ps_home = os.path.dirname(exe)
    system = os.path.dirname(os.path.dirname(ps_home))
    windows = os.path.dirname(system)
    env = {k: os.environ[k] for k in _PASS_ENV if k in os.environ}
    env.update(
        SystemRoot=windows,
        windir=windows,
        SystemDrive=os.path.splitdrive(windows)[0],
        PATH=os.pathsep.join((system, windows)),
        PSModulePath=os.path.join(ps_home, "Modules"),
    )
    return env


def _call(op: str, *, timeout_s: float, **fields: str) -> tuple[str, str | None]:
    """Run one operation in a fresh ``powershell.exe`` child; see :data:`HELLO_SCRIPT`."""
    exe = system_powershell()
    request = {"op": op, "key": KEY_NAME, "timeout_ms": int(timeout_s * 1000), **fields}
    env = _child_env(exe)
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv: System32 PowerShell and our script
            [exe, *_PS_ARGS, _ENCODED_SCRIPT],
            input=json.dumps(request).encode("ascii"),
            capture_output=True,
            timeout=timeout_s + _CHILD_START_S,
            creationflags=_CREATE_NO_WINDOW,
            cwd=os.path.dirname(exe),
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HelloError(f"Windows PowerShell did not run ({type(exc).__name__})") from exc
    if done.returncode != 0:
        raise HelloError(f"Windows PowerShell exited with {done.returncode}")
    return _parse_reply(done.stdout)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decoded(value: str | None) -> bytes:
    try:
        raw = base64.b64decode(value or "", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HelloError("the Hello child's value is not base64") from exc
    if not raw:
        raise HelloError("the Hello child returned nothing")
    return raw


class PowerShellHelloBackend:
    """The real backend: each operation is one ``powershell.exe`` child (see module docs)."""

    def available(self) -> bool:
        status, _ = _call("available", timeout_s=_QUICK_TIMEOUT_S)
        return _name(status) == "available"

    def verify(self, prompt: str, *, timeout_s: float) -> HelloVerdict:
        status, _ = _call("verify", timeout_s=timeout_s, prompt=_b64(prompt.encode("utf-8")))
        return HelloVerdict.verified if _name(status) == "verified" else HelloVerdict.cancelled

    def ensure_key(self) -> None:
        status, _ = _call("open", timeout_s=_QUICK_TIMEOUT_S)
        if _name(status) == "notfound":
            # FailIfExists: never silently replace a key someone already pinned.
            status, _ = _call("create", timeout_s=DEFAULT_APPROVAL_TIMEOUT_S)
        if _name(status) != "success":
            raise HelloError(f"Hello key {KEY_NAME!r} is not usable: {_name(status)}")

    def sign(self, data: bytes, *, timeout_s: float | None = None) -> bytes:
        """One gesture, one signature, bound to the foreground window where Windows can."""
        limit = DEFAULT_APPROVAL_TIMEOUT_S if timeout_s is None else timeout_s
        status, value = _call("sign", timeout_s=limit, data=_b64(data))
        if _name(status) != "success":
            raise HelloError(f"Hello signing refused: {_name(status)}")
        return _decoded(value)

    def public_key(self) -> bytes:
        # X.509 SubjectPublicKeyInfo DER (the WinRT default blob type).
        status, value = _call("public_key", timeout_s=_QUICK_TIMEOUT_S)
        if _name(status) != "success":
            raise HelloError(f"Hello key {KEY_NAME!r} not usable: {_name(status)}")
        return _decoded(value)

    def tpm_backed(self) -> bool | None:
        try:
            status, value = _call("attest", timeout_s=_ATTEST_TIMEOUT_S)
        except Exception:  # noqa: BLE001 - no key / no PowerShell: unknown, never yes
            return None
        return tpm_backed_from_attestation(value) if _name(status) == "success" else None

    def check_powershell(self) -> None:
        """Doctor: raise unless PowerShell resolves and runs the script in FullLanguage."""
        status, _ = _call("ping", timeout_s=_QUICK_TIMEOUT_S)
        if status != "ok":
            raise HelloError("Windows PowerShell gave an unexpected answer")

    def window_binding(self) -> str:
        """Doctor: ``"ok"`` when prompts can be bound to the window in front, else what is
        missing (``buffers``, ``helper``, ``interop`` or ``window_calls``). Never prompts."""
        status, _ = _call("selftest", timeout_s=_QUICK_TIMEOUT_S)
        return status


class WindowsHelloMethod:
    """Approve an action with a Windows Hello biometric prompt."""

    name = "windows_hello"

    def __init__(self, backend: HelloBackend | None = None) -> None:
        self._backend: HelloBackend = backend if backend is not None else PowerShellHelloBackend()

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
