# PyInstaller spec for Sec-Benchmarks (cross-platform).
#
# Usage:
#   # One-folder build (default; faster startup):
#   pyinstaller packaging/pyinstaller-secbench.spec --noconfirm --clean
#
#   # One-file build (single self-extracting binary):
#   #   PowerShell:  $env:SECBENCH_ONEFILE = "1"; pyinstaller ...
#   #   bash:        SECBENCH_ONEFILE=1 pyinstaller ...

# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# SPECPATH is provided by PyInstaller and points at the directory
# containing this .spec file. All paths below are resolved relative to
# the project root (one level above /packaging) so the build works no
# matter what cwd `pyinstaller` is run from.
SPEC_DIR = Path(SPECPATH).resolve()
PROJECT_ROOT = SPEC_DIR.parent
ICON_DIR = SPEC_DIR / "icons"
ENTRY_SCRIPT = PROJECT_ROOT / "src" / "secbench" / "__main__.py"

ONEFILE = os.environ.get("SECBENCH_ONEFILE", "0").lower() in ("1", "true", "yes", "on")

if not ENTRY_SCRIPT.is_file():
    raise SystemExit(
        f"PyInstaller spec error: entry script not found at {ENTRY_SCRIPT}. "
        "Make sure you are running pyinstaller from a checkout that contains "
        "src/secbench/__main__.py."
    )


def _icon_path() -> str | None:
    name = "icon.icns" if sys.platform == "darwin" else "icon.ico"
    p = ICON_DIR / name
    return str(p) if p.is_file() else None


datas = collect_data_files(
    "secbench",
    includes=["**/*.yaml", "**/*.j2", "**/*.qss", "**/*.css", "**/*.svg"],
)

hiddenimports: list[str] = []
hiddenimports += collect_submodules("secbench.benchmarks")
hiddenimports += collect_submodules("azure")
hiddenimports += [
    "azure.mgmt.resource",
    "azure.mgmt.subscription",
    "azure.mgmt.compute",
    "azure.mgmt.storage",
    "azure.mgmt.sql",
    "azure.mgmt.network",
    "azure.mgmt.keyvault",
    "azure.mgmt.monitor",
    "azure.mgmt.security",
    "azure.mgmt.policyinsights",
    "azure.mgmt.authorization",
    "azure.mgmt.web",
    "azure.mgmt.containerservice",
    "azure.mgmt.containerregistry",
    "azure.mgmt.cosmosdb",
    "azure.mgmt.rdbms.postgresql_flexibleservers",
    "azure.mgmt.rdbms.mysql_flexibleservers",
    "azure.identity",
    "msal",
    "msgraph",
    "reportlab",
]
# weasyprint needs C libs that often aren't present on Windows.
if sys.platform != "win32":
    hiddenimports.append("weasyprint")

a = Analysis(
    [str(ENTRY_SCRIPT)],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if ONEFILE:
    # Single self-extracting executable. Slightly slower first launch
    # because the bundle is unpacked to a temp dir on each run.
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="SecBench",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        icon=_icon_path(),
    )
else:
    # One-folder bundle: ./dist/SecBench/SecBench(.exe) plus dependencies.
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="SecBench",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        icon=_icon_path(),
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="SecBench",
    )

if sys.platform == "darwin" and not ONEFILE:
    app = BUNDLE(
        coll,
        name="SecBench.app",
        icon=_icon_path(),
        bundle_identifier="ai.factory.secbench",
        info_plist={"NSHighResolutionCapable": "True"},
    )
