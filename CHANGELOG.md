# Changelog

All notable changes to ContextGuard are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [1.2.0] - 2026-09-27

### Security
- HuggingChat's web UI (multipart/form-data with the message in a JSON `data` field) is now parsed:
  secrets are blocked and other flagged content raises a warning. Previously an email address there passed
  silently. `router.huggingface.co` (Hugging Face's current OpenAI-compatible API) is now watched.
- Closed a spoofable-Host-header bypass, scoped TLS decryption to only watchlisted hosts (previously
  decrypted ALL HTTPS on the machine, verified live via cert-issuer inspection), made the addon fail
  CLOSED instead of mitmproxy's default fail-open on init failure, pinned the policy-signing public key
  as a compiled-in source constant instead of a tamperable sibling file, and fixed a LAN-open-proxy bind
  bug (mitmproxy's default `listen_host` binds `0.0.0.0`, not loopback-only).
- Fixed a structural "unrecognized shape = silent bypass" class of bug across 5+ provider wire formats,
  including two variants where an empty-but-present known field could shield a real secret elsewhere in
  the same request body from the fallback scanner.
- Redesigned dashboard authentication to cookie-based sessions with two separate secrets (dashboard vs.
  control-plane token, previously shared) instead of a token embedded in every URL/browser-history entry.
  Added a tray menu option to rotate both.
- Closed a port-squatting race: a same-machine (or same-network multi-user) process binding the
  dashboard/control-plane ports first, before ContextGuard does, could previously receive a real token
  instead of the connection simply failing.

### Fixed
- The app now refuses to launch a second instance instead of silently corrupting the system proxy
  setting — a real, live-diagnosed bug where a second launch's own failed startup could flip protection
  off while the first, healthy instance's tray icon kept showing "Active."
- A background watchdog now detects and recovers automatically if the proxy process dies mid-session
  (a crash, being killed by antivirus/EDR, anything) — previously this left the system proxy setting
  pointed at a dead port indefinitely, breaking ALL browsing (not just watched hosts) until the user
  manually disabled it in Windows Settings.
- The CA certificate is now checked and (re-)trusted automatically on every launch rather than only via
  a separate installer step or manual script — closes a real `ERR_CERT_AUTHORITY_INVALID` gap for anyone
  running the app without going through the full installer.
- A mid-session proxy crash no longer requires two clicks of Resume to actually recover.
- Various accounting/telemetry gaps closed: pause/resume/quit and crash-recovery events are now all
  logged distinctly rather than being unrecorded or conflated.
- Site background traffic (analytics and telemetry requests full of random-looking tokens) no longer
  floods the app with warnings: a body in an unrecognized format is now checked for blockable secrets
  only, and "Heads up" notifications are limited to one per category and site per minute. A live test
  logged about 2,700 such warnings in 20 minutes.
- The window's "Caught so far" count no longer includes pause/resume/quit events.
- The window's "Open web dashboard" now verifies the app's own dashboard is the one listening before
  sending it the token, as the tray-only entry point already did.
- If the app exits while protection is on, the Windows proxy setting is restored on the way out.

### Changed
- Each release now includes a SHA-256 checksum file, and the README shows how to check the download
  with PowerShell.
- README and SECURITY.md rewritten in plain language, with a step-by-step install guide.
- Code comments shortened and rewritten in plain language (no code changes; checked automatically).
- Removed unused code: the old command-line launcher (`proxy/launch.py`) and a second, developer-only
  copy of the tray menu that had drifted from the real app.
- The window's Pause/Resume button and status now check whether the proxy is really running, so after
  a crash it no longer shows Active, and one click restarts protection.
- GitHub Actions updated to versions that run on Node 24.
- Test and audit tools moved from `requirements.txt` to `requirements-dev.txt`, so they're no longer
  installed as app dependencies.

### Added
- PDF upload checking: the text of a PDF uploaded to a watched AI site (up to 50 pages) is checked with
  the same detectors, read with pypdfium2 in a separate, time-limited process. A key that the page
  layout wrapped over two lines is still caught. PDFs that can't be checked ask before sending. On by
  default; switch "PDF uploads" in Settings.
- Gemini's upload servers are watched as upload-only hosts: its web app uploads an attached file
  (raw PDF body) before the message is sent, and switches between `contribution-rt.usercontent.google.com`
  and `push.clients6.google.com` (both seen in live network captures); `content-push.googleapis.com` is
  also watched. These hosts are shared with other Google apps, so only PDF uploads
  on them are checked. ChatGPT's file storage (`*.oaiusercontent.com`) is watched the same way:
  ChatGPT uploads an attached file there with a PUT, with a different subdomain per region. Live-tested sites for PDFs: ChatGPT, Claude and Gemini;
  HuggingChat does not accept PDFs; Perplexity uploads need a paid plan and are untested.
- Git protection (Settings, off by default): stops a commit or push that adds a `.env` file, a private
  key file or a known secret format, in any tool that runs git (VS Code, IntelliJ, GitHub Desktop,
  terminal), with a Don't Commit / Commit Anyway popup and a terminal explanation. Runs the
  repository's own hook afterwards; never prints the secret itself.
- Activity tab filters (All / Blocked / Sent anyway / Masked or warned). One message counts once, even
  when it contained several kinds of information or the site sent it in several requests.
- Tray menu action "Reset CA certificate (fixes cert errors)": generates a fresh CA, re-trusts it, and
  restarts the proxy, as an escape hatch for certificate/trust-store drift.
- After a CA (re-)install the app now tells you to fully restart your browser; Chromium caches TLS trust
  per session, so a reload alone may keep showing certificate errors.
- `scripts/run_pip_audit.py` + `.github/pip-audit-ignore.txt`: one shared vulnerability ignore list for CI
  and release builds (was copied into three workflow steps).
- The main window is reorganized into three tabs: Home (status, Pause/Resume, counts of blocked,
  sent-anyway and masked-or-warned, latest five events), Activity (the full list) and Settings. Events
  and the Don't Send popup use plain names and local times ("Blocked · AWS access token · chatgpt.com ·
  9:44 PM") instead of internal ids.
- Settings tab: one switch per kind of detection — API keys
  and access tokens, unknown-format secrets, credit card numbers, Social Security numbers, email
  addresses, internal IPs and hostnames. Everything is on by default; a change applies to the next
  message sent. Stored in `settings.json` next to the app, separate from the signed policy file.
- The Don't Send / Send Anyway popup now shows the ContextGuard icon.
- "Reset CA certificate" and "Rotate dashboard/control tokens" are now in the installed app's tray menu
  (they had only been added to the developer entry point's menu).
- App logo: used for the tray icon (green when active, gray when paused), the window, the exe and the
  installer.
- `scripts/rotate_tokens.py` — rotates the dashboard and control-plane tokens from the command line.

## [1.1.0] - 2026-09-11

### Added
- Native desktop GUI (`gui/app.py`) with Pause/Resume, a running "caught so far" count, and a recent-activity
  log — no terminal required to use the app day to day.
- One-click Windows installer (`ContextGuard.iss`, built with Inno Setup) — installs to
  `%LocalAppData%\ContextGuard`, no admin rights needed, sets up CA trust and login autostart automatically.
- Interactive "Don't Send" / "Send Anyway" confirmation when a block decision fires, instead of an
  unconditional hard block. Detectors aren't perfect; this gives the user the final call on likely false
  positives instead of guessing wrong in either direction. Every choice is logged (never a silent
  override).
- `infra.internal_ip` / `infra.internal_hostname` detectors — flags private IP addresses or internal-only
  hostnames near an infrastructure keyword (server/database/deploy/etc.), gated on proximity to avoid
  false positives on ordinary text.
- `pii.credit_card` — detects credit card numbers via real BIN-range matching (Visa, Mastercard, Amex,
  Discover, Diners Club, JCB) plus a Luhn checksum, not just "16 digits in a row"; a same-length,
  wrong-prefix number (e.g. an order/reference number) is never flagged. `pii.ssn` — detects dash/space
  separated Social Security Numbers, excluding the SSA's own never-issued area/group/serial ranges.
  `pii.ssn_context` — a weaker, keyword-gated fallback for a bare (no separators) 9-digit SSN, only
  fired when an actual "ssn"/"social security" keyword sits nearby. All three are `action: block,
  mandatory: true` in policy.yaml except the context-gated fallback (`warn`), same tier as a leaked API
  key given the real identity-theft/fraud risk.
- A background GitHub-Releases update check (`notify/update_check.py`) — runs once at GUI startup,
  surfaces a "new version available" label if the latest published release is newer, never
  auto-downloads or auto-installs anything. Fails silently on any error, including "no release published
  yet" (this project's real current state).
- GitHub Actions release workflow (`.github/workflows/release.yml`) — builds and attaches the installer to
  a GitHub Release on a version tag push. Not yet exercised against a real tag.
- `CHANGELOG.md` and a single-source `version.py` (this file's own existence).

### Fixed
- Gemini's web UI (`gemini.google.com`) was watched but never actually scanned — its real send endpoint
  uses Google's internal `batchexecute` RPC format (form-encoded, not JSON), which silently fell through
  detection entirely. Real secrets went out unblocked and unlogged until this was found and fixed.
- Perplexity's web UI had two separate bugs stacked on top of each other: the real site serves from
  `www.perplexity.ai`, not the bare `perplexity.ai` domains.yaml listed (fixed generically via
  subdomain-aware host matching, not a one-off domain addition); and its actual request body uses a
  `query_str` field that wasn't a recognized shape at all.
- A runtime-path bug (`get_writable_data_dir()`) had `telemetry.db`, `alias_vault.db`, `ca_store/`, and the
  proxy-restore state file all writing into PyInstaller's bundled `_internal/` resources folder instead of
  the actual install directory.
- The installer's uninstaller could delete far more than intended: `[UninstallDelete]` recursively removed
  the entire install directory by path, which is user-chosen and not guaranteed to be
  `%LocalAppData%\ContextGuard` — now scoped to only the app's own known runtime files, never the install
  root itself.
- The uninstaller could also hang indefinitely on a native Windows confirmation dialog when removing the
  trusted CA certificate, with no way to proceed on an unattended uninstall. That step is now
  fire-and-forget: cleanup of everything else always completes regardless of whether anyone answers it.
- A fresh install could silently end up with no CA certificate trusted at all, if an unrelated leftover
  certificate happened to share the name "mitmproxy" — the trust check now matches by exact certificate
  serial number instead of a name substring.
- The confirm-dialog popup could be resolved by a stray input event with no real user click. Hardened with
  a short grace period before its buttons become clickable, and keyboard focus/Enter pinned to the safe
  "Don't Send" choice.
- A chain of a force-killed process followed by a later graceful relaunch-and-quit could leave the
  Windows system proxy setting permanently stuck pointed at a dead port, breaking normal browsing.

### Security
Following an external, code-grounded security audit and OSI-layer threat model review:
- The proxy silently bound `0.0.0.0` instead of `127.0.0.1` (mitmproxy's own default) — on any shared
  network, anyone else could use this machine as an open forward proxy and reach every other
  localhost-only service on it, including this tool's own dashboard/control server. Now binds loopback
  only, with `block_private=true` as defense-in-depth.
- The watchlist check used the spoofable `pretty_host` (prefers the Host header) instead of the real
  CONNECT/dial target — any non-browser client (a CLI tool, an SDK) could spoof the inner Host header and
  go completely uninspected. Both are now checked.
- ContextGuard decrypted **every** HTTPS connection on the machine, not just watchlisted hosts — a
  `tls_clienthello` hook now passes an unwatched connection through as an opaque tunnel, never
  terminating it with the local CA at all. Verified live by inspecting the actual leaf certificate
  presented for both a watched and an unwatched host.
- If module-level initialization ever failed (a corrupted signature, a lost keyring entry), mitmproxy's
  own default behavior is to run fully open with no addon loaded at all — silently protecting nothing
  while the tray/dashboard kept showing Active. A minimal fail-closed mode now blocks all traffic to
  known AI hosts instead. Verified live with a real forced signature corruption.
- The pinned policy-signing public key lived in the same user-writable directory as the files it
  authenticates, so a local attacker could overwrite it, generate their own keypair, and re-sign a
  weakened policy. The key is now compiled into the application's own source rather than read from a
  sibling file at runtime. Verified live by corrupting the sibling `.pem` file and confirming
  verification was unaffected.
- A request to a watched host in a shape no known provider format recognized used to pass through with
  zero inspection and zero log trace — five separate real gaps of this exact kind have been found and
  fixed one at a time so far. Unrecognized bodies are now scanned as raw text and routed through the
  same block/warn path already used for shapes with no safe in-place rewrite, so a future provider
  change degrades to reduced coverage instead of silent total bypass.
- `hmac.compare_digest()` raised an unhandled exception on a non-ASCII token instead of a clean 401 in
  both the dashboard's and the tray control server's auth checks.
- `localhost` shipped enabled in the real signed `domains.yaml` (a test-only fixture), meaning a real
  install could intercept and mask-rewrite a developer's own local traffic. Now disabled by default.
- No accounting trail existed for pausing/resuming/quitting protection, revealing a vault secret via the
  dashboard, or a failed authentication attempt against either local HTTP server. All four are now logged
  (content-free, as with every other telemetry event here).
- `telemetry.db` writes had no busy-timeout and could raise past code not expecting a telemetry failure,
  risking a wedged connection instead of the block already decided. Added WAL mode, a busy timeout, and
  made `log_event()` itself never raise.
- `release.yml` built and shipped the actual installer without ever running `pip-audit` (only `ci.yml`
  did); added the same gate. Also pinned the third-party `action-gh-release` step to a commit SHA rather
  than a mutable tag, since that job runs with repo write access.
- A pre-existing Windows `ProxyOverride` bypass-list entry (left by a VPN, a corporate tool, or the user)
  could silently exempt a watched host from routing through this proxy at all, with nothing surfacing it.
  Now warned about (not auto-cleared) on a blanket `*` or an entry matching a known AI host.
- `state['proxy']` could reference an already-dead process (e.g. mitmdump exiting instantly because the
  port was taken) while every "is protection active" surface — the tray icon, `/status`, the dashboard —
  kept reporting Active indefinitely. Startup now verifies the process is still alive before declaring
  success, and every liveness check uses real process state, not just non-None.
- `SECURITY.md` expanded with an honest architecture/threat-model section: what policy signing does and
  doesn't defend against, the CA-compromise story (silent, total, permanent for the affected account, no
  rotation today), and the system-proxy mechanism's real nature as a cooperative control rather than
  kernel-level enforcement.

### Changed
- README, SECURITY.md, and BENCHMARK.md rewritten to match the actual current project — the GUI, the
  installer, the Send-Anyway dialog, and corrected detector/watchlist counts that had drifted stale.

## [1.0.0] - 2026-09-10

Initial tagged state: local HTTPS proxy (mitmproxy-based) inspecting outgoing requests to OpenAI, Anthropic,
Gemini, Perplexity, and HuggingFace hostnames; regex/context/entropy detector pipeline with mask/tokenize/
generalize/remove/block policy actions; encrypted CA private key and alias vault; signed policy file;
tray app with a browser-based dashboard.
