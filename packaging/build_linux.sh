#!/usr/bin/env bash
# Build a standalone Linux binary with PyInstaller.
#
# Usage:
#   ./packaging/build_linux.sh                       # one-folder mode
#   SECBENCH_ONEFILE=1 ./packaging/build_linux.sh    # single ELF binary
#   SECBENCH_SKIP_INSTALL=1 ./packaging/build_linux.sh
#
# Output (one-folder):  ./dist/SecBench/SecBench
# Output (one-file):    ./dist/SecBench

set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"

if [[ "${SECBENCH_SKIP_INSTALL:-0}" != "1" ]]; then
    echo "==> Installing project + dev extras (PyInstaller, etc.)"
    python -m pip install --upgrade pip
    python -m pip install -e ".[dev]"
fi

export SECBENCH_ONEFILE="${SECBENCH_ONEFILE:-0}"
if [[ "$SECBENCH_ONEFILE" == "1" ]]; then
    echo "==> Running PyInstaller (one-file mode)"
else
    echo "==> Running PyInstaller (one-folder mode)"
fi

python -m PyInstaller "${PROJECT_ROOT}/packaging/pyinstaller-secbench.spec" \
    --noconfirm --clean \
    --distpath "${PROJECT_ROOT}/dist" \
    --workpath "${PROJECT_ROOT}/build"

if [[ "$SECBENCH_ONEFILE" == "1" ]]; then
    artifact="${PROJECT_ROOT}/dist/SecBench"
else
    artifact="${PROJECT_ROOT}/dist/SecBench/SecBench"
fi

if [[ -f "$artifact" ]]; then
    size=$(du -h "$artifact" | awk '{print $1}')
    echo "==> Built $artifact ($size)"
else
    echo "ERROR: Expected artifact not found at $artifact" >&2
    exit 1
fi
