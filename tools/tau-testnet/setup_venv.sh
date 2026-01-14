#!/usr/bin/env bash
set -euo pipefail

# Setup a local Python venv for Tau Testnet and install runtime dependencies.
#
# This script is intentionally kept in-repo (outside external/) so MPRD developers
# can reproduce the Tau node harness used by `mprd-core` integration tests.
#
# Usage:
#   ./tools/tau-testnet/setup_venv.sh
#
# Then:
#   export TAU_TESTNET_PYTHON="$PWD/external/tau-testnet/venv/bin/python"
#   cargo test -p mprd-core tau_testnet_node_boots_and_answers_commands

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAU_DIR="$ROOT/external/tau-testnet"
VENV_DIR="$TAU_DIR/venv"

if [[ ! -d "$TAU_DIR" ]]; then
  echo "ERROR: tau-testnet not found at $TAU_DIR"
  echo "       (it should live under external/ and is git-ignored)"
  exit 2
fi

python3 -m venv "$VENV_DIR"

"$VENV_DIR/bin/pip" install --upgrade pip

# Base dependencies (as pinned by Tau Testnet).
"$VENV_DIR/bin/pip" install -r "$TAU_DIR/requirements.txt"

# NOTE: Tau Testnet imports `trio_websocket` but requirements.txt may not include it.
"$VENV_DIR/bin/pip" install "trio-websocket"

echo
echo "OK."
echo "Set:"
echo "  export TAU_TESTNET_PYTHON=\"$VENV_DIR/bin/python\""

