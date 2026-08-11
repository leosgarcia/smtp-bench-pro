# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

block_cipher = None

project_root = Path(SPECPATH).parent
src_dir = project_root / "src"

py_side6_datas, py_side6_binaries, py_side6_hiddenimports = collect_all("PySide6")
dns_datas, dns_binaries, dns_hiddenimports = collect_all("dns")
tld_datas, tld_binaries, tld_hiddenimports = collect_all("tldextract")

datas = []
datas += py_side6_datas
datas += dns_datas
datas += tld_datas
datas += [
    (str(project_root / "README.md"), "."),
    (str(project_root / "LICENSE"), "."),
]

binaries = []
binaries += py_side6_binaries
binaries += dns_binaries
binaries += tld_binaries

hiddenimports = []
hiddenimports += py_side6_hiddenimports
hiddenimports += dns_hiddenimports
hiddenimports += tld_hiddenimports
hiddenimports += [
    "smtp_bench_pro.__main__",
    "smtp_bench_pro.application",
    "smtp_bench_pro.comparison",
    "smtp_bench_pro.domain",
    "smtp_bench_pro.engine",
    "smtp_bench_pro.export",
    "smtp_bench_pro.integration",
    "smtp_bench_pro.persistence",
    "smtp_bench_pro.security",
    "smtp_bench_pro.ui",
]

a = Analysis(
    [str(src_dir / "smtp_bench_pro" / "__main__.py")],
    pathex=[str(src_dir)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "pytest", "bandit"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SMTP Bench Pro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version=None,
)
