#!/usr/bin/env bash
# Bootstrap a local Python virtual environment for the steganography tool.

set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ ! -d "${VENV_DIR}" ]]; then
    echo "Creating SpectraLock virtual environment in ${VENV_DIR} using ${PYTHON_BIN}..."
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
else
    echo "SpectraLock virtual environment ${VENV_DIR} already exists."
fi

source "${VENV_DIR}/bin/activate"

echo "Upgrading pip..."
python -m pip install --upgrade pip

echo "Installing SpectraLock dependencies..."
python -m pip install cryptography Pillow

echo "SpectraLock environment ready. Activate it with:"
echo "  source ${VENV_DIR}/bin/activate"
