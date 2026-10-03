# PyInstaller spec: builds the ContextGuard GUI (gui/app.py) as a --onedir
# bundle -- deliberately NOT --onefile. --onefile extracts its entire payload
# to a temp folder on every launch, which is exactly the runtime behavior
# heuristic antivirus/SmartScreen engines flag as suspicious (malware does
# the same thing to hide its real payload); --onedir needs no extraction at
# all, so it's both faster to start and far less likely to be flagged.
#
# No separate mitmdump.exe is bundled: a venv-built mitmdump.exe is a thin
# launcher hard-wired to that specific venv's python.exe (confirmed live --
# copying it elsewhere, or even hiding the venv on the SAME machine, makes it
# fail outright) and is not portable to a machine that only downloaded the
# finished app. mitmproxy's own Python code is already fully bundled here
# (its PyInstaller hooks pull it in automatically), so gui/app.py's early
# dispatch block re-invokes this SAME exe with `--run-mitmdump` instead --
# see tray/app.py's MITMDUMP_CMD for the launch side of this.
#
# proxy/addon.py is loaded by mitmproxy at runtime via its own `-s <path>`
# addon-loading mechanism, NOT a normal Python `import` statement anywhere in
# gui/app.py's call graph -- PyInstaller's static analysis has no way to
# discover it or its engine/notify dependencies on its own, so both are
# listed explicitly below (hiddenimports for the actual import machinery,
# datas so proxy/addon.py exists as a real loose file mitmproxy's loader can
# open).
#
# scripts/ (install_ca_cert.py, autostart.py) is reached the same
# self-invocation way, via --install-ca-cert/--register-autostart/
# --unregister-autostart -- the installer's post-install steps (see
# ContextGuard.iss) call these instead of needing a separate Python/venv.
#
# UPX compression is deliberately left off (upx=False) -- another common
# antivirus false-positive trigger on PyInstaller builds.
from PyInstaller.utils.hooks import collect_all, collect_submodules

# pypdfium2 ships pdfium.dll as package data that PyInstaller's import
# analysis does not pick up on its own; without this the frozen app cannot
# read PDFs (a known pypdfium2 + PyInstaller issue).
pdfium_datas, pdfium_binaries, pdfium_hiddenimports = [], [], []
for package in ('pypdfium2', 'pypdfium2_raw'):
    datas_, binaries_, hidden_ = collect_all(package)
    pdfium_datas += datas_
    pdfium_binaries += binaries_
    pdfium_hiddenimports += hidden_

block_cipher = None

a = Analysis(
    ['gui/app.py'],
    pathex=[],
    binaries=pdfium_binaries,
    datas=[
        ('policy/policy.yaml', 'policy'),
        ('policy/policy.yaml.sig', 'policy'),
        ('policy/allowlist.yaml', 'policy'),
        ('policy/allowlist.yaml.sig', 'policy'),
        ('policy/policy_signing_pubkey.pem', 'policy'),
        ('proxy/domains.yaml', 'proxy'),
        ('proxy/domains.yaml.sig', 'proxy'),
        ('proxy/addon.py', 'proxy'),
        ('assets/icon.ico', 'assets'),
        ('engine', 'engine'),
        ('notify', 'notify'),
    ] + pdfium_datas,
    hiddenimports=(
        collect_submodules('engine') + collect_submodules('notify') + collect_submodules('scripts')
        + collect_submodules('gitguard') + pdfium_hiddenimports
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ContextGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon='assets/icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name='ContextGuard',
)
