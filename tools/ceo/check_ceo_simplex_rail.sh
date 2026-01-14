#!/usr/bin/env bash
set -euo pipefail

# CEO Simplex rail gate (research-to-runtime):
# - ensures simplex POR oracle + symmetry key compile and basic tests pass
# - runs a bounded perf sweep to confirm determinism and avoid regressions
#
# This is intentionally bounded and deterministic enough for CI-style usage.

ROOT="${ROOT:-/home/trevormoc/Downloads/MPRD}"
cd "$ROOT"

echo "[ceo-simplex-rail] cargo test: simplex POR oracle"
cargo test -q -p mprd-core tokenomics_v6::simplex_por_oracle

echo "[ceo-simplex-rail] cargo test: simplex symmetry key"
cargo test -q -p mprd-core tokenomics_v6::simplex_symmetry_key

echo "[ceo-simplex-rail] cargo test: ample-set POR decision-quality (bounded falsifier sweep)"
cargo test -q -p mprd-core dfs_c2_decision_falsifier_sweep_small

echo "[ceo-simplex-rail] cargo test: ample-set POR matches brute-force (tiny instance)"
cargo test -q -p mprd-core plan_best_linear_dfs_c2_matches_bruteforce_small

echo "[ceo-simplex-rail] cargo build: perf harness"
cargo build -q -p mprd-perf

TMP_JSON="${TMP_JSON:-/tmp/mprd_ceo_simplex_sweep.json}"
echo "[ceo-simplex-rail] mprd-perf simplex sweep -> ${TMP_JSON}"

# Small bounded grid (keep runtime low but still exercise crossover behavior).
cargo run -q -p mprd-perf -- \
  --bench simplex \
  --sweep \
  --k-list 4,6 \
  --t-list 10,12 \
  --h-list 6,8 \
  --eval-list 0,50,200 \
  --time-ms 20000 \
  --budget-expanded 50000 \
  --json > "${TMP_JSON}"

echo "[ceo-simplex-rail] strict crossover gate (SYM must win for eval_iters>=200)"
python3 tools/ceo/check_ceo_simplex_sweep_strict.py "${TMP_JSON}" --gate sym --min-eval-iters 200 --min-win-rate 0.75 --max-median-ratio 1.0

echo "[ceo-simplex-rail] summarize sweep (structural, deterministic)"
python3 tools/ceo/summarize_ceo_simplex_sweep.py "${TMP_JSON}" | head -80

echo "[ceo-simplex-rail] summarize sweep (time-based, informational)"
python3 tools/tokenomics/summarize_simplex_sweep.py "${TMP_JSON}" | head -80

echo "[ceo-simplex-rail] OK (wrote ${TMP_JSON})"

