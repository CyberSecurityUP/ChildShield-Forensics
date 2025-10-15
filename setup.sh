#!/usr/bin/env bash
# ChildShield Forensics – setup & build (Linux/macOS)
# Usage: ./setup.sh [PYTHON_VERSION]
# Example: ./setup.sh 3.11.9

set -euo pipefail

PY_VER="${1:-3.11.9}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
PYBIN=""

echo "==> Requested Python version: ${PY_VER}"

have_py() {
  command -v python3 >/dev/null 2>&1 || return 1
  local v; v="$(python3 -c 'import sys;print(".".join(map(str,sys.version_info[:2])))' 2>/dev/null || true)"
  [[ "$v" == "$(echo "$PY_VER" | cut -d. -f1-2)" ]]
}

install_python_mac() {
  if ! command -v brew >/dev/null 2>&1; then
    echo "[!] Homebrew not found; install from https://brew.sh/"; exit 1
  fi
  local minor="$(echo "$PY_VER" | cut -d. -f1-2 | tr -d '.')"
  echo "==> brew install python@$(echo "$PY_VER" | cut -d. -f1-2)"
  brew install "python@$(echo "$PY_VER" | cut -d. -f1-2)"
  PYBIN="$(brew --prefix)/opt/python@$(echo "$PY_VER" | cut -d. -f1-2)/bin/python3"
}

install_python_linux() {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    case "$(echo "$PY_VER" | cut -d. -f1-2)" in
      3.11) sudo apt-get install -y python3.11 python3.11-venv python3.11-dev ;;
      3.12) sudo apt-get install -y python3.12 python3.12-venv python3.12-dev ;;
      *) echo "[!] Distro packages may not have $PY_VER; consider pyenv.";;
    esac
    PYBIN="$(command -v python3 || true)"
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y "python$(echo "$PY_VER" | cut -d. -f1-2)" "python$(echo "$PY_VER" | cut -d. -f1-2)-devel" || true
    PYBIN="$(command -v python3 || true)"
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm python
    PYBIN="$(command -v python3 || true)"
  else
    echo "[!] Unsupported package manager. Install Python ${PY_VER} manually or via pyenv."
  fi
}

# Pick or install Python
if have_py; then
  PYBIN="$(command -v python3)"
else
  if [[ "$OSTYPE" == "darwin"* ]]; then
    install_python_mac
  else
    install_python_linux
  fi
fi

if [[ -z "${PYBIN}" ]]; then
  echo "[!] Could not determine python3 binary. Aborting."
  exit 1
fi

echo "==> Using Python: $("$PYBIN" -V)"

# Create venv
"$PYBIN" -m venv "$VENV"
source "$VENV/bin/activate"

# Upgrade pip & install deps
pip install --upgrade pip wheel
pip install -r "$ROOT/requirements.txt" pyinstaller

# Optional system tool: ffmpeg (best-effort)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y ffmpeg || true
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y ffmpeg || true
elif command -v brew >/dev/null 2>&1; then
  brew install ffmpeg || true
fi

# Build with PyInstaller (Linux/macOS uses ':' in --add-data)
echo "==> Building executables…"
pyinstaller --noconfirm --clean \
  --name childshield_cli \
  --add-data "policy:policy" \
  --add-data "plugins:plugins" \
  cli/main.py

pyinstaller --noconfirm --clean --windowed \
  --name childshield_gui \
  --add-data "policy:policy" \
  --add-data "plugins:plugins" \
  gui/main_gui.py

echo "==> Done. Binaries are in dist/ (childshield_cli, childshield_gui)."
