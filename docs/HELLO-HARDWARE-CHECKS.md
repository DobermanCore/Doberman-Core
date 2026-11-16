# Windows Hello hardware checks

Doberman's opt-in Windows Hello approval (`doberman 2fa methods enable windows_hello`; it runs
through the built-in Windows PowerShell 5.1, so no extra package is needed) cannot be tested in CI: CI has no Hello device. Before any
release claims more about Hello than "it shows a prompt", someone runs these checks on a real Windows
11 machine and writes down what they saw. An unchecked box means unknown, not "fine".

Record for each run: Windows build, sign-in method (face, fingerprint, PIN), whether the machine has a
TPM 2.0, and the date.

## Checks

1. **Can another program press the button?** Start a Hello prompt, then from a second process running
   as the same user send synthetic keyboard or mouse input (for example a PIN typed with `SendInput`).
   Does the prompt accept it? If yes, a script running as the user can approve its own prompt, and
   Hello only removes the stealable secret.
2. **Is the prompt on the secure desktop?** While it shows, does the rest of the screen dim, and can
   a normal screenshot tool capture the prompt? A prompt on the secure desktop is out of reach of
   ordinary same-user programs.
3. **Does face recognition approve without a deliberate act?** With face sign-in on, sit in front of
   the camera and trigger a prompt. Does it approve before you do anything on purpose? If so, a face
   approval shows you were there, not that you meant "yes".
4. **Does deleting the Hello key need a gesture?** Create the `doberman-proof` key, then delete it
   from a script (`KeyCredentialManager.DeleteAsync`). Does Windows ask for a gesture first? If not, a
   script can delete the key and force re-enrollment.
5. **Does the prompt show from a hook process?** Trigger a 2FA-tier action from a coding agent so the
   prompt comes from Doberman's hook, which has no console window. Does the prompt appear in front,
   behind other windows, or not at all? Doberman falls back to TOTP when the prompt cannot run,
   except in Hello-required mode, where it denies. Every prompt runs in a `powershell.exe` child
   that binds it to the window in front where Windows allows (verify through
   `IUserConsentVerifierInterop::RequestVerificationForWindowAsync`, key creation through
   `RequestCreateForWindowAsync`, signing through `RequestSignForWindowAsync`), and, while the
   dialog is open and not in front, asks Windows to raise it and flash its taskbar button. On a
   timeout it cancels the request, which should close the dialog; does it? `doberman doctor`
   warns on the "Hello PowerShell" row when prompts cannot be bound. Run this check again in
   the mode.
6. **Is the key TPM-backed or software-only?** After creating the key, does
   `KeyCredential.GetAttestationAsync` return `Success` (TPM attestation) or `NotSupported`
   (no TPM attestation)? Doberman treats anything else as unknown, never as TPM-backed.
7. **Does PowerShell's Hello path run under App Control?** With Smart App Control or another App
   Control policy on, does `doberman doctor` show the "Hello PowerShell" row as OK (Windows
   PowerShell 5.1 resolved from System32 and running in FullLanguage mode)? Under an enterprise
   policy that puts PowerShell in Constrained Language Mode, Hello cannot run: Doberman uses TOTP
   outside Hello-required mode and refuses proof tier in it.
8. **Does the Hello key's signature verify?** `doberman 2fa hello enroll` signs a test message and
   checks it with Doberman's own verifier (RSA PKCS#1 v1.5 with SHA-256 over the key's
   SubjectPublicKeyInfo) before pinning the key. Does enrollment pass that step? If it refuses with
   "did not verify", the key type or signature format differs from what Doberman expects.
9. **Does the availability check work off the main thread?** In Hello-required mode, run
   `doberman mode` to lower the mode. Doberman checks Hello on a worker thread first; if it says
   Hello is unavailable while Windows Hello works, every loosening command is refused in the mode.

## Results

| Date | Build | Check | Observed | By |
| --- | --- | --- | --- | --- |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 7 | `pip install` of the `winrt-*` packages on CPython 3.13 succeeded; the import failed with "An Application Control policy has blocked this file" for `_winrt`. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 7 (PowerShell path) | Smart App Control on. `powershell.exe` from System32 is Microsoft-signed (Authenticode valid) and ran Doberman's Hello script in FullLanguage mode: ping OK, `UserConsentVerifier` availability `Available`, opening `doberman-proof` returned `NotFound`, each in about 0.3 s. No key was created and no prompt was shown. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | Availability only | From Windows PowerShell 5.1 (not Doberman's Python path): `UserConsentVerifier` reports `Available`, `KeyCredentialManager.IsSupportedAsync` is `True`, no `doberman-proof` key exists. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 1 | From a second process at the same user's normal (medium) integrity, posting Escape or close to the prompt window failed with access denied, and ending the prompt's process failed too. A global synthetic keypress went to the window in front, not the prompt, because the prompt was behind other windows. Typing into the prompt while it is in front was not tried. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 2 | The prompt was an ordinary window on the normal desktop, listed by other programs as "Windows Security". The screen did not switch to the secure desktop. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 5 | A prompt started from a process with no console window opened behind other windows and was never answered. The request timed out after 40 seconds, and Doberman denies on a timeout. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 6 | TPM 2.0 present and ready for attestation. No `doberman-proof` key was created, because creating one needs a gesture. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 3, 4 | Not run: each needs a person. The machine has an IR camera with Hello face sign-in and a fingerprint reader. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 5 (PowerShell path) | At 22:10 PST, through the PowerShell backend with no window binding for verify or create: each opened a visible "Windows Security" dialog (a `CredentialUIBroker` process), but the browser stayed the foreground window for the whole 60 s (verify) and 90 s (create). Both timed out and were denied. The raise step never found the dialog: `FindWindowW` does not see it, though its process's main window handle does. Both dialogs were still open long after their requests timed out. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 3, 4, 6, 8 | Same run. Check 3 inconclusive: the verify prompt never came to the front, so nobody could see whether the face sign-in approves without a deliberate act. Checks 4, 6 and 8 not reached: the key was never created. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 5 (raise and flash) | Against those two open dialogs, from a program at the same user's normal integrity: `SetForegroundWindow` returned false and the foreground window did not change. `FlashWindowEx` (flash caption and taskbar button until focused) and `FlashWindow` returned false with error 87 (invalid parameter), while the same `FlashWindowEx` call on the probe's own window worked. So raising and flashing may do nothing for this dialog; binding the prompt to the window in front is the fix, and it has not been tried with a real prompt yet. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 5 (timeout cancel) | At 00:23 PST a verify prompt through the window-bound path timed out after 60 seconds and Doberman denied, but the person at the machine reported the "Windows Security" prompt stayed open; cancelling the request does not close it. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 8 (key format) | A `doberman-proof` key already existed (the 22:11 create prompt from the day before was answered later). Reading its public key through PowerShell failed: PowerShell 5.1 holds a WinRT buffer as a plain COM object and will not pass it to a typed parameter. With buffers passed through reflection, the key reads as a 294-byte RSA 2048 SubjectPublicKeyInfo (e = 65537) and Doberman's verifier parses it. Signing has the same buffer problem, fixed the same way; a real signature is still unchecked. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 3 | At 00:23 PST a verify prompt was left alone with the person at the machine; it timed out after 60 seconds, so face sign-in did not approve it without a deliberate act, assuming the camera could see the person (whether the prompt was in front is not confirmed). | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 6 | `GetAttestationAsync` on the `doberman-proof` key reports it TPM-backed. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 8 | With the buffer fix, a real Hello signature (256 bytes, approved by the person in 17 seconds) verifies with Doberman's own verifier against the key's public key, and the same signature over a changed message is rejected. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 4 | `KeyCredentialManager.DeleteAsync("doberman-proof")` completed in 0.3 seconds with no prompt, and the key was gone. Any program running as the user can delete the key without a gesture. In Hello-required mode that only denies: the marker pins the old public key, so a new key never matches, and re-enrolling needs an administrator. | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 5 (window-bound sign) | The sign prompt for check 8, started from a process with no console window through `RequestSignForWindowAsync`, appeared in front of the person's other windows (their report). | Claude |
| 2026-11-15 | Windows 11 Home 10.0.26200 | 5 (timeout cancel) | Two prompts were left alone and cancelled after 15 seconds: once with `IAsyncInfo.Cancel` (what Doberman does) and once through a .NET cancellation token. Both prompts stayed open 10 seconds later and after the program exited, and the token-cancelled request never finished. Windows does not close this prompt when an app cancels it; the person has to close it. | Claude |

Checks 3, 4, 6 and 8 were answered on 2026-11-15 (rows above). Check 5 is mostly answered: a window-bound sign prompt came to the front, but a timed-out prompt stays open until the person closes it (Windows ignores the cancel), and the window-bound verify prompt was not confirmed in front. Check 1 is only partly answered: a same-user program could not message or end the prompt, but nobody tried typing into it while it was in front.
