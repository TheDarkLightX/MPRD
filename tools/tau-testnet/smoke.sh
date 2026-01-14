#!/usr/bin/env bash
set -euo pipefail

# One-command Tau Testnet smoke runner for MPRD.
#
# What it does:
# - Ensures Tau Testnet Python deps are installed (via setup_venv.sh)
# - Runs the mprd-core tau_testnet smoke test using that venv Python
#
# Usage:
#   ./tools/tau-testnet/smoke.sh
#
# Notes:
# - This uses TAU_FORCE_TEST=1 in the harness, i.e. no Docker / no real Tau network.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

"$ROOT/tools/tau-testnet/setup_venv.sh"

export TAU_TESTNET_PYTHON="$ROOT/external/tau-testnet/venv/bin/python"

cd "$ROOT"

cargo test -p mprd-core tau_testnet_node_boots_and_answers_commands -- --nocapture

