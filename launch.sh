#!/usr/bin/env bash
# Launch SpectraLock with the virtual environment activated.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${VENV_DIR:-${SCRIPT_DIR}/.venv}"

if [[ ! -d "${VENV_DIR}" ]]; then
    echo "SpectraLock virtual environment missing. Bootstrapping..."
    bash "${SCRIPT_DIR}/set-environment.sh"
fi

# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"

exec python3 "${SCRIPT_DIR}/spectralock.py"
