#Requires -Version 5.1
# Build a standalone Windows binary with PyInstaller.
#
# Usage:
#   .\packaging\build_windows.ps1                  # one-folder mode (default)
#   .\packaging\build_windows.ps1 -OneFile         # single .exe (slower first launch)
#   .\packaging\build_windows.ps1 -SkipInstall     # skip pip install -e .[dev]
#
# Output (one-folder):  .\dist\SecBench\SecBench.exe
# Output (one-file):    .\dist\SecBench.exe

[CmdletBinding()]
param(
    [switch]$OneFile,
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $ProjectRoot

if (-not $SkipInstall) {
    Write-Host "==> Installing project + dev extras (PyInstaller, etc.)" -ForegroundColor Cyan
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
    if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)" }
}

# Make sure PyInstaller is invoked through the same interpreter that
# pip just used. `pyinstaller` on PATH may resolve to a different venv.
if ($OneFile) {
    Write-Host "==> Running PyInstaller (one-file mode)" -ForegroundColor Cyan
    $env:SECBENCH_ONEFILE = "1"
} else {
    Write-Host "==> Running PyInstaller (one-folder mode)" -ForegroundColor Cyan
    $env:SECBENCH_ONEFILE = "0"
}

python -m PyInstaller (Join-Path $ProjectRoot "packaging\pyinstaller-secbench.spec") `
    --noconfirm --clean --distpath (Join-Path $ProjectRoot "dist") `
                       --workpath (Join-Path $ProjectRoot "build")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }

if ($OneFile) {
    $artifact = Join-Path $ProjectRoot "dist\SecBench.exe"
} else {
    $artifact = Join-Path $ProjectRoot "dist\SecBench\SecBench.exe"
}

if (Test-Path $artifact) {
    $size = (Get-Item $artifact).Length / 1MB
    Write-Host ("==> Built {0}  ({1:N1} MB)" -f $artifact, $size) -ForegroundColor Green
} else {
    throw "Expected artifact not found at $artifact"
}
