# Windows Hello hardware checks

Doberman's opt-in Windows Hello approval (`pip install "doberman-core[winhello]"`, then
`doberman 2fa methods enable windows_hello`) cannot be tested in CI: CI has no Hello device. Before any
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
   behind other windows, or not at all? Doberman falls back to TOTP when the prompt cannot run.
6. **Is the key TPM-backed or software-only?** After creating the key, does
   `KeyCredential.GetAttestationAsync` return `Success` (TPM attestation) or `NotSupported`
   (no TPM attestation)? Doberman treats anything else as unknown, never as TPM-backed.
7. **Does the `winhello` extra load at all?** With Smart App Control or another App Control policy
   on, does `import winrt.windows.security.credentials` work, or does Windows block the `_winrt` DLL?
   If it is blocked, Hello is reported unavailable and Doberman uses TOTP.

## Results

| Date | Build | Check | Observed | By |
| --- | --- | --- | --- | --- |
| 2026-11-14 | Windows 11 Home 10.0.26200 | 7 | `pip install` of the `winrt-*` packages on CPython 3.13 succeeded; the import failed with "An Application Control policy has blocked this file" for `_winrt`. | Claude |
| 2026-11-14 | Windows 11 Home 10.0.26200 | Availability only | From Windows PowerShell 5.1 (not Doberman's Python path): `UserConsentVerifier` reports `Available`, `KeyCredentialManager.IsSupportedAsync` is `True`, no `doberman-proof` key exists. | Claude |

Checks 1 to 6 have not been run yet. They each need a person to make or withhold a Hello gesture.
