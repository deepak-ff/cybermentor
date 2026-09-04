#!/usr/bin/env bash
# Remove CyberMentor installed by install.sh.
# Removes the symlinks, the virtualenv, and the bash completion.
set -euo pipefail

for BIN_DIR in /usr/local/bin "${HOME}/.local/bin"; do
  [ -d "$BIN_DIR" ] || continue
  for s in audit-tool audit-web audit-baseline; do
    if [ -L "${BIN_DIR}/$s" ]; then
      target="$(readlink "${BIN_DIR}/$s")"
      case "$target" in
        *cybermentor*) rm -v "${BIN_DIR}/$s" ;;
      esac
    fi
  done
done

for VENV_DIR in /opt/cybermentor-venv "${HOME}/.local/share/cybermentor/venv"; do
  if [ -d "$VENV_DIR" ]; then
    rm -rf -v "$VENV_DIR"
  fi
done

if [ -w /usr/share/bash-completion/completions ]; then
  rm -f -v /usr/share/bash-completion/completions/audit-tool
fi

echo "Done."
