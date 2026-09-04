#!/usr/bin/env bash
# Install CyberMentor (security-audit-tool) on Kali / Debian / Ubuntu or any
# Linux box with Python 3.8+. Pure stdlib — no third-party dependencies.
#
#   sudo ./install.sh    installs for all users (venv in /opt, scripts in
#                        /usr/local/bin, bash completion system-wide)
#   ./install.sh         installs for the current user only (~/.local)
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "error: $PY not found." >&2
  echo "hint:  apt install python3 python3-venv" >&2
  exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
  VENV_DIR="/opt/cybermentor-venv"
  BIN_DIR="/usr/local/bin"
else
  VENV_DIR="${HOME}/.local/share/cybermentor/venv"
  BIN_DIR="${HOME}/.local/bin"
fi

echo "==> Creating virtualenv in ${VENV_DIR}"
"$PY" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet "$SRC_DIR"

echo "==> Linking console scripts into ${BIN_DIR}"
mkdir -p "$BIN_DIR"
for s in audit-tool audit-web audit-baseline; do
  ln -sf "$VENV_DIR/bin/$s" "$BIN_DIR/$s"
done

# Best-effort bash completion (system-wide when writable).
if [ -d /usr/share/bash-completion/completions ] && [ -w /usr/share/bash-completion/completions ]; then
  install -m 0644 "$SRC_DIR/completions/audit-tool" /usr/share/bash-completion/completions/audit-tool
  echo "==> Installed bash completion"
fi

echo
echo "Installed:"
ls -l "$BIN_DIR"/audit-tool "$BIN_DIR"/audit-web "$BIN_DIR"/audit-baseline
echo
echo "Quick start:"
echo "  audit-tool --skip-scan --out ~/reports          # audit this machine"
echo "  audit-tool --host <target> --ports top --out ~/reports"
echo "  audit-web --reports ~/reports --port 8931       # then open http://localhost:8931/"
echo
echo "Note: add ~/.local/bin to PATH if you installed as a normal user."
