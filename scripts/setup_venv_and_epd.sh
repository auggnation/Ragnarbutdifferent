#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/setup_venv_and_epd.sh [venv-dir]
# Default venv-dir: ragnar-venv

VENV_DIR="${1:-ragnar-venv}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "Creating virtual environment at: $VENV_DIR"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "Upgrading pip, setuptools, wheel"
python -m pip install --upgrade pip setuptools wheel

if [ -f requirements.txt ]; then
  echo "Installing Python requirements from requirements.txt"
  pip install -r requirements.txt
else
  echo "No requirements.txt found at $REPO_ROOT; skipping pip install -r requirements.txt"
fi

# Install Waveshare e-Paper library (RaspberryPi/JetsonNano branch)
EPD_DIR="vendor/e-Paper"
if [ ! -d "$EPD_DIR" ]; then
  echo "Cloning Waveshare e-Paper repo into $EPD_DIR"
  mkdir -p vendor
  git clone https://github.com/waveshare/e-Paper.git "$EPD_DIR"
fi

if [ -d "$EPD_DIR/RaspberryPi_JetsonNano/python" ]; then
  echo "Installing Waveshare Python bindings into virtualenv"
  pushd "$EPD_DIR/RaspberryPi_JetsonNano/python" > /dev/null
  # Use pip to install from local source inside venv
  pip install .
  popd > /dev/null
else
  echo "Warning: expected $EPD_DIR/RaspberryPi_JetsonNano/python not found; skipping Waveshare EPD installation"
fi

cat <<EOF
Setup complete.
To activate the virtual environment:

  source $VENV_DIR/bin/activate

If you need to run the project's installer inside the venv, activate it first and then run:

  sudo -E bash install_ragnar.sh

Note: running the installer with sudo may still run parts as root; prefer running needed Python installs inside the venv.
EOF
