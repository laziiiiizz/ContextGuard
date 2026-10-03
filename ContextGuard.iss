; Inno Setup script for ContextGuard.
; Installs to %LocalAppData%\ContextGuard (not Program Files) and requires
; no administrator rights at all -- consistent with every other piece of
; this project (CA-cert install targets the CurrentUser store, auto-launch
; uses the Startup folder instead of Task Scheduler): Program Files is
; read-only for a standard user, and this tool needs to write its own CA
; store, telemetry, and config at runtime.
;
; Build dist\ContextGuard\ first (PyInstaller: `python -m PyInstaller
; ContextGuard.spec --noconfirm`), then compile this with Inno Setup's ISCC.
;
; Testing this installer's /VERYSILENT or /SILENT switches from a Git Bash
; shell (MSYS/MinGW) DOES NOT WORK -- confirmed live, cost real time to
; root-cause: Git Bash auto-converts a leading "/" argument into a POSIX-to-
; Windows path before exec'ing the child process, so "/VERYSILENT" never
; actually reaches ContextGuard-Setup.exe at all -- it silently runs as a
; normal interactive wizard instead, which looks exactly like a hang if
; nothing is watching to click it (0% CPU, sitting on a real wizard page).
; Invoke silent-mode switches from PowerShell (`& ".\ContextGuard-Setup.exe"
; /VERYSILENT ...`) or cmd.exe instead, never a POSIX shell.

#define MyAppName "ContextGuard"
#define MyAppVersion "1.2.0"
#define MyAppExeName "ContextGuard.exe"

[Setup]
AppId={{B6D6C9C7-6A0B-4E8B-9C1A-6C6C6C6C6C6C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={localappdata}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputBaseFilename=ContextGuard-Setup
OutputDir=installer_output
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "dist\{#MyAppName}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
; This DOES need waituntilterminated, unlike the uninstall-side CA removal
; below -- trusting a brand-new root CA for the first time always shows a
; native Windows "Security Warning" confirmation (confirmed live; -f on
; certutil -addstore only forces overwriting an EXISTING same-thumbprint
; entry, it does not bypass this prompt for a genuinely new cert), and the
; app needs that trust in place BEFORE "Launch ContextGuard now" below
; actually starts intercepting traffic -- launching first and trusting async
; would let the proxy start breaking HTTPS browsing before anyone's had a
; chance to answer the prompt. This means a fully unattended/silent install
; (no one available to click the prompt) will hang here -- an accepted,
; documented limitation of the interactive-only supported install path, not
; something to route around by skipping the wait.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--install-ca-cert"; Flags: runhidden waituntilterminated; StatusMsg: "Trusting the local proxy certificate (no admin rights needed)..."
Filename: "{app}\{#MyAppExeName}"; Parameters: "--register-autostart"; Flags: runhidden waituntilterminated; StatusMsg: "Setting up auto-start at login..."
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName} now"; Flags: postinstall nowait skipifsilent

[UninstallRun]
; Graceful shutdown (restores the system proxy setting, stops the proxy
; cleanly) BEFORE file removal -- a plain process kill would leave the
; system proxy pointed at a dead port with nothing listening, breaking all
; browsing, exactly the bug this project's own system_proxy.py exists to
; prevent. Also silently no-ops if nothing is running.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--quit-if-running"; Flags: runhidden waituntilterminated; RunOnceId: "QuitBeforeUninstall"
Filename: "{app}\{#MyAppExeName}"; Parameters: "--unregister-autostart"; Flags: runhidden waituntilterminated; RunOnceId: "UnregisterAutostart"
; Removes git's global core.hooksPath, but only if it still points at this
; app's hooks folder; the hook scripts would otherwise call a deleted exe.
Filename: "{app}\{#MyAppExeName}"; Parameters: "--git-guard-off"; Flags: runhidden waituntilterminated; RunOnceId: "GitGuardOff"
; Removes the trusted CA cert this install added -- the private key is
; deleted along with {app} right after, so leaving the cert trusted with no
; corresponding key would be a pointless, if harmless, leftover.
;
; Deliberately NOT waituntilterminated -- confirmed live: removing a
; CurrentUser Root store entry always triggers a native Windows security
; confirmation dialog ("Root Certificate Store" -- distinct from the
; install-time "Do you want to install this certificate?" prompt, and not
; suppressed by runhidden, which only hides the cmd.exe console window, not
; a child GUI dialog it spawns). This is Windows' own "Protected Roots"
; security boundary (PowerShell's Cert: provider hits the exact same wall:
; "The operation is on user root store and UI is not allowed") -- not a bug
; to work around, and not something to silently defeat via lower-level
; registry access either, which would make this app behave like the exact
; class of thing that boundary exists to catch. Concretely, waiting on this
; step means an unattended/silent uninstall (or an interactive one where the
; user doesn't understand what the dialog is or ignores it) hangs
; INDEFINITELY with no way to proceed -- confirmed live, the whole uninstall
; sat blocked until the dialog was manually dismissed. Firing it without
; waiting makes CA-cert cleanup best-effort: it still prompts and succeeds
; for anyone paying attention, but the rest of the uninstall (file removal,
; autostart, proxy restore) always completes regardless of whether anyone
; answers it. A user who never answers is left with one harmless orphaned
; trusted cert (no private key survives to make it exploitable) -- an
; accepted, documented tradeoff, not a silent failure.
Filename: "{cmd}"; Parameters: "/C certutil -user -delstore Root mitmproxy"; Flags: runhidden nowait; RunOnceId: "RemoveCaCert"

[UninstallDelete]
; Inno Setup only tracks files it originally installed -- these are the
; specific files/folders the app creates AT RUNTIME, not part of [Files].
; DO NOT use "Name: {app}" with filesandordirs here again: {app} is
; whatever directory the user picked in the wizard, not necessarily
; %LocalAppData%\ContextGuard -- a user can point it at an existing,
; unrelated directory (this has happened), and a recursive delete of
; "{app}" itself will destroy whatever else lives there. Only ever delete
; the app's own known runtime-generated files by exact name, scoped inside
; {app}, never {app} itself.
Type: filesandordirs; Name: "{app}\ca_store"
Type: files; Name: "{app}\telemetry.db"
Type: files; Name: "{app}\alias_vault.db"
Type: files; Name: "{app}\.system_proxy_state.json"
Type: files; Name: "{app}\settings.json"
Type: filesandordirs; Name: "{app}\git-hooks"
; The CONTEXTGUARD_DEBUG_LOG_RAW=1 diagnostics (proxy/addon.py, notify/confirm_dialog.py) -- only ever
; created when that env var is explicitly set for local debugging, never in a normal end-user run, but
; still real runtime-generated files this app creates and should clean up like the ones above. Found
; missing from this list during a real uninstall-cycle test (confirmed live: they survived a full
; uninstall that correctly removed everything else).
Type: files; Name: "{app}\last_addon_error.log"
Type: files; Name: "{app}\unrecognized_shapes.log"
Type: files; Name: "{app}\all_matched_requests.log"
Type: files; Name: "{app}\dialog_debug.log"
