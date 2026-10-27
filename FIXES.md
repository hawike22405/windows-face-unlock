# Startup and credential pipe fixes

Addresses upstream reports [#1](https://github.com/caochitam/windows-face-unlock/issues/1), [#2](https://github.com/caochitam/windows-face-unlock/issues/2), [#3](https://github.com/caochitam/windows-face-unlock/issues/3), and [#4](https://github.com/caochitam/windows-face-unlock/issues/4).

## Changes

- Both frozen entry scripts use absolute package imports and call multiprocessing.freeze_support before importing application code. The screenshots in #1 and #2 show the same missing package context as #4.
- Both executables collect into a shared directory without cross-executable MERGE references. The installer build runs each frozen executable with `--self-test` to check imports without starting the camera or UI. A Credential Provider compilation failure now stops the build instead of silently shipping without it; SKIP_CP=1 remains an explicit opt-out.
- The pipe has an explicit DACL granting the service user and SYSTEM access, rejects remote clients, and refuses to join another server's pipe instance.
- Ordinary user connections may use tray operations but cannot request `unlock`. Before face verification or password decryption, unlock requires the OS-provided client token to identify SYSTEM in the service's interactive session and the OS-provided client PID to identify the real System32\\LogonUI.exe. Lookup failures deny access. JSON fields cannot supply this identity.
- The Credential Provider connects at identification impersonation level. Before sending a request it verifies the server PID, same session, installed executable path, and token SID against Windows' interactive user token. It fails closed if Windows cannot provide that identity. Client access excludes FILE_CREATE_PIPE_INSTANCE.
- Installation uses the fixed Program Files\\WindowsFaceUnlock directory expected by server verification. An old custom install must be removed and reinstalled in that directory. Removed the installer grant giving all users modification rights on its precreated data directory.

- The fork updater and installer links point to hawike22405/windows-face-unlock, so future updates do not replace these changes with upstream binaries.

## Validation

Run `python -m unittest discover -s tests -v`. Portable tests check both entry scripts with no package context, the command authorization matrix, failed identity lookup, and SYSTEM process path/session checks. Windows tests additionally exercise a real pipe and verify that unauthorized requests and failed face checks never load credentials. CI compiles the C++ Credential Provider on Windows. The full installer build checks actual frozen imports.

The tests do not establish that live face unlocking works on a specific PC. Before relying on this build, test on Windows with a working password/PIN fallback:

1. Build using `python installer/build.py` with the dependencies from INSTALL.md. Do not reuse the original v0.1.0 release executables.
2. Install the newly built installer, enroll, and save credentials through the app.
3. Check that the tray and both scheduled tasks start without import popups.
4. With the enrolled face visible, an ordinary user pipe request `{"cmd":"unlock"}` must return `unauthorized`, without activating the camera or loading credentials.
5. A different non-admin local account and remote pipe connection must be denied. A fake server executable, wrong session, or failed identity lookup must not be accepted by the Credential Provider.
6. Lock the existing signed-in session and confirm the real Credential Provider succeeds only after a matching face/liveness check. Failed checks must not return credentials. Test each supported Windows version.

## Scope and limits

The background service runs as the signed-in user, so this design supports unlocking an existing session. It does not start before the first sign-in after reboot. SYSTEM identity checks deliberately exclude arbitrary user tools from password retrieval. Developer installations outside the fixed protected directory cannot use the Credential Provider.

This mitigates the named-pipe credential disclosure reported in #3. It does not protect against administrator/SYSTEM compromise or malware already running as the enrolled user, which can access that user's DPAPI data and modify their enrollment/configuration. It is not Windows Hello or hardware-backed authentication.
