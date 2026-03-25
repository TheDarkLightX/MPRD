#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

TIME_PER_TARGET=10
INCLUDE_ASDE=0
SUMMARY_PATH="${ROOT}/fuzz/artifacts/rc1_fuzz_smoke_summary.json"

usage() {
  cat <<'EOF'
Usage: tools/fuzz_smoke_rc1.sh [--time-per-target SECONDS] [--include-asde] [--summary PATH]

Runs the tracked RC1 fuzz smoke campaign and writes a JSON summary.

Options:
  --time-per-target SECONDS  Max fuzz time per target (default: 10)
  --include-asde             Include ASDE economic fuzz targets (slower; off by default)
  --summary PATH             Output summary JSON path
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --time-per-target)
      TIME_PER_TARGET="$2"
      shift 2
      ;;
    --include-asde)
      INCLUDE_ASDE=1
      shift
      ;;
    --summary)
      SUMMARY_PATH="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "${SUMMARY_PATH}")"

TARGET_ROWS=(
  "limits_bytes_v1|--no-default-features|limits_bytes_parser"
  "candidate_preimage_v1|--no-default-features|candidate_preimage_decode"
  "anti_replay_state_machine|--no-default-features|anti_replay_state_machine"
  "tau_output_attestation_envelope_v1|--no-default-features|tau_output_attestation_envelope"
  "governance_admission_witness_v1|--features zk|governance_admission_witness"
  "receipt_deser|--features zk|receipt_deserialization"
  "mpb_artifact_deser|--features zk|mpb_artifact_deserialization"
  "decoded_journal_metamorphic_v3|--features zk|decoded_journal_metamorphic"
)

if [[ "${INCLUDE_ASDE}" == "1" ]]; then
  TARGET_ROWS+=(
    "asde_voucher_trace_v1|--features asde|asde_voucher_trace"
    "asde_allocation_v1|--features asde|asde_allocation"
  )
fi

RESULTS_TSV="$(mktemp)"
trap 'rm -f "${RESULTS_TSV}"' EXIT

overall_status="passed"

run_one() {
  local target="$1"
  local feature_flags="$2"
  local surface="$3"
  local started finished duration status
  local -a cmd extra_flags

  started="$(date +%s)"
  cmd=("${ROOT}/tools/fuzz.sh" run "${target}")
  if [[ -n "${feature_flags}" ]]; then
    read -r -a extra_flags <<<"${feature_flags}"
    cmd+=("${extra_flags[@]}")
  fi
  cmd+=(-- "-max_total_time=${TIME_PER_TARGET}")

  if "${cmd[@]}"; then
    status="passed"
  else
    status="failed"
    overall_status="failed"
  fi

  finished="$(date +%s)"
  duration="$((finished - started))"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "${target}" "${surface}" "${feature_flags}" "${status}" "${duration}" >>"${RESULTS_TSV}"
}

for row in "${TARGET_ROWS[@]}"; do
  IFS='|' read -r target feature_flags surface <<<"${row}"
  run_one "${target}" "${feature_flags}" "${surface}"
done

python3 - "${RESULTS_TSV}" "${SUMMARY_PATH}" "${TIME_PER_TARGET}" "${overall_status}" "${INCLUDE_ASDE}" "${ROOT}" <<'PY'
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

rows_path, summary_path, time_per_target, overall_status, include_asde, root = sys.argv[1:]
targets = []
with open(rows_path, "r", encoding="utf-8") as handle:
    for line in handle:
        target, surface, feature_flags, status, duration = line.rstrip("\n").split("\t")
        targets.append(
            {
                "target": target,
                "surface": surface,
                "feature_flags": feature_flags.split() if feature_flags else [],
                "status": status,
                "duration_s": int(duration),
            }
        )

head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
payload = {
    "schema": "mprd/rc1-fuzz-smoke-summary/v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_head": head,
    "time_per_target_s": int(time_per_target),
    "include_asde": include_asde == "1",
    "overall_status": overall_status,
    "targets": targets,
}

with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

cat "${SUMMARY_PATH}"

if [[ "${overall_status}" != "passed" ]]; then
  exit 1
fi
