<p align="center"><img src="assets/logo.png" alt="ContextGuard logo" width="120"></p>

# ContextGuard

ContextGuard is a Windows app that stops you from accidentally pasting secrets into AI chats. It
checks what you send to ChatGPT, Claude, Gemini, Perplexity and HuggingFace **before it leaves your
computer**. If it finds something like an API key, a credit card number or an SSN, it stops and asks
you first.

It runs only on your own computer. Nothing is sent anywhere else, and it never stores what you
typed.

This is a portfolio project. It is not a commercial security product and is not connected to any AI
company.

## What it does

- **Checks your messages.** Anything you type or paste into a supported AI site is checked before it
  is sent.
- **Asks before sending a secret.** When it finds an API key, a credit card number or a Social
  Security number, a popup asks: **Don't Send** or **Send Anyway**. If you don't answer within 60
  seconds, it does not send.
- **Masks or warns about smaller things.** Email addresses are replaced with a mask where the site
  allows it. Internal IP addresses, internal server names and random-looking strings get a warning
  notification.
- **Checks PDFs you upload,** up to 50 pages. A PDF it can't check (too big, locked, only images)
  shows a "This PDF was not checked" popup instead of passing silently.
- **Can guard git (optional).** Stops a `git commit` or `git push` that would add a `.env` file, a
  private key file or a known secret format to your repository, from VS Code, IntelliJ, GitHub
  Desktop or the terminal.
- **You choose what to check.** The Settings tab has a switch for each kind: API keys, unknown-format
  secrets, credit cards, SSNs, emails, internal network details and PDF uploads.
- **Keeps a private log.** The Activity tab lists what was caught: the kind of information, the
  site and the time. Never the text itself.

It knows more than 200 API key formats (AWS, GitHub, OpenAI, Stripe, Slack, Google and many more).

## Demo



https://github.com/user-attachments/assets/808c4ef9-19ad-4e68-af26-640bbb8a95ea



## Install

Windows 10 or 11. No admin rights needed. It installs only for your own Windows account.

### Option 1: download from the website

1. Go to the [latest release](https://github.com/laziiiiizz/ContextGuard/releases/latest).
2. Under **Assets**, click `ContextGuard-Setup.exe` to download it.
3. Open the file and continue with **Step 3** below.

### Option 2: download with PowerShell (also checks the file)

**Step 1. Open PowerShell.** Press the Windows key, type `PowerShell` and press Enter.

**Step 2. Download the installer and check it.** Copy these lines, paste them into PowerShell and
press Enter:

```powershell
$ProgressPreference = 'SilentlyContinue'
$dl = "$env:USERPROFILE\Downloads"
$url = "https://github.com/laziiiiizz/ContextGuard/releases/latest/download"
Invoke-WebRequest "$url/ContextGuard-Setup.exe" -OutFile "$dl\ContextGuard-Setup.exe"
Invoke-WebRequest "$url/ContextGuard-Setup.exe.sha256" -OutFile "$dl\ContextGuard-Setup.exe.sha256"
(Get-FileHash "$dl\ContextGuard-Setup.exe" -Algorithm SHA256).Hash.ToLower() -eq (Get-Content "$dl\ContextGuard-Setup.exe.sha256").Split(' ')[0]
```

The last line must print **True**. That means the file is exactly the one GitHub built from this
code. If it prints **False**, delete the file and don't run it.

Then start the installer:

```powershell
Start-Process "$dl\ContextGuard-Setup.exe"
```

### Step 3. Run the installer

1. Windows may show **"Windows protected your PC"**. That's because the installer isn't code-signed
   yet. Click **More info**, then **Run anyway**.
2. Click through the installer. It installs to your own `AppData\Local\ContextGuard` folder.
3. Windows asks whether to install a certificate. Click **Yes**. ContextGuard needs this to read
   what you send to AI sites. The certificate is created on your own computer during install, not
   downloaded.
4. ContextGuard opens, and its green **C** icon appears in the system tray (near the clock).

### Step 4. Restart your browser

Close **every** browser window, then open the browser again. A page reload is not enough.

### Step 5. Turn off QUIC (Chrome, Edge, Brave, Opera)

These browsers have a faster connection type called QUIC that skips ContextGuard. Turn it off once:

1. In the address bar, go to `chrome://flags/#enable-quic` (for Edge: `edge://flags/#enable-quic`).
2. Set **Experimental QUIC protocol** to **Disabled**.
3. Click **Relaunch**.

Firefox doesn't need this step, but it uses its own certificate list. See
[Firefox](#firefox) below.

### Step 6. Check that it works

Open ChatGPT (or Claude, Gemini, ...) and send this fake key. It is not a real key:

```
here is my key AKIAABCDEFGHIJKLMNOP
```

The ContextGuard popup should appear. Click **Don't Send**. Then open ContextGuard and look at the
**Activity** tab: you'll see "Blocked · AWS access token".

### Firefox

Firefox doesn't use the Windows certificate list. Import the certificate yourself once:
**Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import**, then
pick `ca_store\mitmproxy-ca-cert.cer` from `%LocalAppData%\ContextGuard` and tick "Trust this CA to
identify websites".

## Using it

ContextGuard starts by itself when you sign in to Windows. Click the tray icon to open the window:

- **Home:** shows whether protection is on, a **Pause / Resume** button, and how many messages were
  blocked, sent anyway, or masked and warned.
- **Activity:** everything that was caught, with filters. One message counts once, even if it held
  several secrets.
- **Settings:** a switch for each kind of check, and the optional git protection.

Closing the window with X keeps protection running in the tray. To stop it completely, right-click
the tray icon and choose **Quit**.

Right-click menu on the tray icon:
- **Reset CA certificate**: use this if AI sites show certificate errors. Restart the browser after.
- **Rotate dashboard/control tokens**: makes new access tokens for the web dashboard.
- **Open web dashboard (advanced)**: the same information in your browser.

### Git protection

Turn it on in **Settings > Check commits and pushes**. After that, a commit or push that adds a
`.env` file, a private key file (`id_rsa`, `.pem`, ...) or a known secret is stopped with a popup and
a message saying what to do. Template files such as `.env.example` are allowed.

To skip the check once (for example, for a test file), use `git commit --no-verify` or
`git push --no-verify`.

## Uninstall

Windows **Settings > Apps > Installed apps > ContextGuard > Uninstall**. It closes the app, puts your
Windows proxy setting back, removes the startup entry, the certificate and the git setting, and
deletes its own files. Nothing outside its install folder is touched.

## How it works

```mermaid
flowchart LR
    C["Browser or AI app"] -->|Windows proxy setting| P["ContextGuard<br/>(local proxy, 127.0.0.1 only)"]
    P -->|any other website| T["Passed through,<br/>never decrypted"] --> W["Internet"]
    P -->|watched AI site| X["Read the message<br/>or the uploaded PDF"]
    X --> D["Detectors<br/>200+ key formats · credit card · SSN<br/>email · internal network"]
    D --> R["Signed policy"]
    R -->|nothing found| A["AI site"]
    R -->|email| M["Masked"] --> A
    R -->|secret| Q{"Popup:<br/>Don't Send / Send Anyway"}
    Q -->|Send Anyway| A
    Q -->|Don't Send or 60 s| B["Stopped"]
    R -. kind of info only, never the text .-> L[("Activity log")]
```

- ContextGuard is a small proxy ([mitmproxy](https://mitmproxy.org/)) on your own computer. Windows
  sends web traffic through it while protection is on.
- **Only the watched AI sites are decrypted.** Every other website (your bank, email, everything
  else) passes straight through without being opened. The list is in `proxy/domains.yaml`.
- The list of sites and the rules are **signed**. If a file was changed without a new signature,
  ContextGuard refuses to run normally and blocks all AI sites until it's fixed. It never quietly
  runs without checking.
- PDFs are read in a separate process with a time limit, so a broken PDF can't crash the proxy.

## Limitations

Please read these before relying on it.

- **You can always choose Send Anyway.** It's a safety net, not a wall.
- **Only text and PDFs are checked.** Text inside images or screenshots is not read (no OCR), and
  Word files and other attachments are not opened. PDFs over 50 pages are not checked; you get a
  popup saying so.
- **Only the supported sites and their known upload servers.** A site that changes how it sends
  messages or files may need an update.
- **Not every format is known.** A secret in a format none of the rules know is only caught as a
  "random-looking string", which warns but doesn't block. Addresses, phone numbers and passport
  numbers are not checked yet.
- **Some sites can be blocked or warned, but not masked:** Gemini, Claude Design and HuggingChat. On
  those, an email address raises a warning instead of being masked.
- **Apps must use the Windows proxy setting and trust the certificate.** Most browsers and many apps
  do. Apps with built-in certificate pinning (many phone and some desktop apps) won't work through it.
- **WebSocket messages are not checked.** The supported sites send messages over normal HTTP today.
- **Git protection can be skipped** with `--no-verify`. It is not available if another tool already
  manages git hooks for your account, and it doesn't cover a repository that sets its own hooks
  folder (Husky does this).
- **The installer is not code-signed yet,** so Windows shows a warning the first time. It is built by
  GitHub Actions directly from this code (`.github/workflows/release.yml`), and each release has a
  SHA-256 checksum you can check (see Install, Option 2).

## Security

- **The certificate's private key is encrypted** with a key kept in Windows Credential Manager. It is
  made on your computer at install time and never leaves it. While protection runs, mitmproxy needs a
  decrypted copy in a temporary folder, which is deleted when protection stops.
- **Settings files are signed** (Ed25519). The public key is built into the app, so replacing a file
  next to the rules isn't enough to weaken them.
- **Fails closed.** If anything fails at startup, ContextGuard blocks the AI sites instead of letting
  everything through unchecked.
- **The log holds no content.** Only the kind of information, the site and the time.
- **Local only.** The proxy and the dashboard listen on 127.0.0.1 only, not on your network. The
  dashboard needs a token, which is swapped for a browser cookie as soon as you open it.
- **Dependencies are checked** with `pip-audit` on every build, and a software bill of materials
  (SBOM) is saved with each CI run.

Installing ContextGuard's certificate on a computer you don't own, or without the owner knowing, is
not a supported use. It is meant to protect the person running it.

See [SECURITY.md](SECURITY.md) for the full security model and how to report a problem privately.

## For developers

Run from source:

```
git clone https://github.com/laziiiiizz/ContextGuard.git
cd ContextGuard
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python gui/app.py
python scripts/install_ca_cert.py
```

Run the tests:

```
pytest tests/
```

Build the installer yourself:

```
pip install -r requirements-build.txt
python -m PyInstaller ContextGuard.spec --noconfirm
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" ContextGuard.iss
```

This makes `installer_output\ContextGuard-Setup.exe` (needs [Inno Setup](https://jrsoftware.org/isinfo.php),
free).

After changing `policy/policy.yaml`, `policy/allowlist.yaml` or `proxy/domains.yaml`, sign them again
with `python scripts/sign_policy.py`, or ContextGuard won't load them.

Detection speed and test cases: [BENCHMARK.md](BENCHMARK.md). Changes per version:
[CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
