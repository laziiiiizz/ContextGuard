# Security Policy

ContextGuard is a portfolio project maintained by one person, not a commercial product. There is no
security team and no guaranteed response time; reports are handled on a best-effort basis.

## Reporting a vulnerability

Please **don't** open a public GitHub issue for a security problem. Use GitHub's private reporting
instead: this repository > **Security** tab > **Report a vulnerability**. Only the maintainer can see
the report until it is fixed.

## In scope

The proxy addon (`proxy/`), the detectors and policy (`engine/`), the PDF reader, the git protection
(`gitguard/`), the alias vault, the web dashboard, the app window and tray, and the installer.

Problems in third-party packages (mitmproxy, Flask, pypdfium2, ...) should go to those projects,
unless the way ContextGuard uses them causes the problem.

## Known limits (not vulnerabilities)

These are documented choices; see README > Limitations:

- The user can always choose **Send Anyway**, and `--no-verify` skips the git check. ContextGuard is a
  safety net, not something that can't be overridden.
- Text in images is not read. Only PDFs are opened, up to 50 pages; others show a "not checked"
  popup. Word files and other attachments are not read.
- Apps with certificate pinning don't work through the proxy.
- Chrome-based browsers skip the proxy over QUIC unless it is turned off.
- WebSocket messages are not checked.
- The detectors don't know every secret format. A missing format is a coverage gap: add a case to
  `tests/adversarial/corpus.json` rather than filing a security report.

## Use on other people's computers

Installing ContextGuard's certificate on a computer you don't own, or without the owner knowing, is
not a supported use. ContextGuard is meant to protect the person running it, not to read someone
else's traffic.

## Security model and its honest limits

**The real boundary is your Windows account.** Every secret ContextGuard uses (the certificate's
private key, the vault key, the dashboard and control tokens) is stored in your account's Windows
Credential Manager, and the install folder is writable by your account; that's what lets it work
without admin rights. So **any program running as you can read those secrets and change the
installed files.** That's true of almost any program you install, not something special here.

**Signed settings protect against tampered downloads, not against someone already in your account.**
The rules, the site list and the allow list are signed (Ed25519), and the public key is built into the
app. That stops a corrupted or edited file from being used. Someone with access to your account could
still rebuild the app itself; that's much harder than editing a file, but not impossible. An older,
properly signed rules file could also be put back, since there is no minimum version check yet.

**If your account is ever taken over, the certificate is a risk.** The certificate's private key is
encrypted and only decrypted into a temporary folder while protection runs. But if someone gets into
your account, they get a certificate your browser trusts, valid for 10 years. There is no automatic
revocation. **Uninstalling removes the certificate**, but if you think your account was compromised,
also check `certmgr.msc` > Trusted Root Certification Authorities for any leftover "mitmproxy" entry
and delete it.

**Only watched sites are decrypted.** Connections to every other site pass through untouched; their
certificates are not replaced.

**Browsers follow the proxy setting voluntarily.** ContextGuard works by setting the Windows proxy
setting. Browsers follow that setting voluntarily: an extension, a company policy or an
already-open connection can go around it without any error. The QUIC issue is one example. A stronger
method (WinDivert, which redirects traffic at the driver level) was considered and not used, because
it needs admin rights at every start, and ContextGuard is built to never need admin rights.

**Local ports can be taken first.** The dashboard (5050) and control server (5052) use fixed ports. If
another program grabs a port first, ContextGuard notices, shows a message, and never sends its token
to that program. It can't stop the other program from taking the port.

**Git protection runs with your rights.** It works by setting git's global `core.hooksPath` to
ContextGuard's hooks folder. It never prints or stores the secret it finds. Uninstalling removes the
setting, and only if it still points at ContextGuard's folder.

**PDFs are read in a separate process** with a time limit and a page limit, so a malformed PDF can
only fail its own check (shown as "not checked"), never crash the proxy.
