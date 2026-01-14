#!/usr/bin/env bash
set -euo pipefail

# Policy rail gate (fail-closed):
# - property tests that tie semantics (evaluate) to compiler/canonicalization invariants
# - decision-quality policy benchmark sweep + summarizer (fails on any mismatch row)
#
# This is intentionally bounded and deterministic enough for CI-style usage.

ROOT="${ROOT:-/home/trevormoc/Downloads/MPRD}"
cd "$ROOT"

echo "[policy-rail] cargo test: eval vs ROBDD soundness (with missing)"
cargo test -q -p mprd-core policy_algebra::bdd::tests::robdd_matches_policy_evaluate_for_random_policies_with_missing

echo "[policy-rail] cargo test: canonicalize preserves evaluate semantics (exhaustive small)"
cargo test -q -p mprd-core policy_algebra::bdd::tests::canonicalize_preserves_evaluate_semantics_exhaustive_small

echo "[policy-rail] cargo test: canonicalize preserves semantics via ROBDD (proptest)"
cargo test -q -p mprd-core policy_algebra::bdd::tests::canonicalize_is_semantics_preserving_via_robdd

TMP_JSON="${TMP_JSON:-/tmp/mprd_policy_sweep.json}"
echo "[policy-rail] mprd-perf sweep -> ${TMP_JSON}"
cargo run -q -p mprd-perf -- \
  --bench policy \
  --policy-atoms-list 6,8,10,12 \
  --policy-depth-list 2,3,4,5 \
  --policy-env-iters 5000 \
  --json > "${TMP_JSON}"

echo "[policy-rail] summarize sweep (fails non-zero on mismatch)"
python3 tools/policy/summarize_policy_sweep.py "${TMP_JSON}"

echo "[policy-rail] OK"

