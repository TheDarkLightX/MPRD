#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/release/check_deployment_wiring_fixture.sh --out-dir DIR

Generates a deterministic trustless deployment fixture and verifies it with
`mprd deploy verify-release`. This is a release-gate smoke check for
registry-bound deployment wiring; it is not a substitute for validating a real
deployment's signed registry checkpoint, signed manifest, and policy artifacts.
USAGE
}

out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="${2:-}"
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

if [[ -z "$out_dir" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mkdir -p "$out_dir"
fixture_dir="$out_dir/trustless-fixture"
rm -rf "$fixture_dir"

cargo run --locked --quiet -p mprd-cli --bin mprd-trustless-fixture -- \
  --output "$fixture_dir" > "$out_dir/fixture-summary.json"

registry_key_hex="$(
  python3 - "$fixture_dir/.mprd/config.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    config = json.load(fh)
print(config["registry_verifying_key_hex"])
PY
)"

cargo run --locked --quiet -p mprd-cli --bin mprd -- deploy verify-release \
  --registry-state "$fixture_dir/.mprd/registry_state.json" \
  --registry-key-hex "$registry_key_hex" \
  --policy-artifacts-dir "$fixture_dir/.mprd/policy-artifacts" \
  --format json > "$out_dir/deployment-release-report.json"

cargo run --locked --quiet -p mprd-cli --bin mprd -- deploy verify-release \
  --registry-state "$fixture_dir/.mprd/registry_state.json" \
  --registry-key-hex "$registry_key_hex" \
  --policy-artifacts-dir "$fixture_dir/.mprd/policy-artifacts" \
  --format digest > "$out_dir/deployment-release-report.digest"

python3 - "$out_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])
report = json.loads((out_dir / "deployment-release-report.json").read_text(encoding="utf-8"))
digest = (out_dir / "deployment-release-report.digest").read_text(encoding="utf-8").strip()

expected_digest = hashlib.sha256(
    json.dumps(report, indent=2, sort_keys=False).encode("utf-8")
).hexdigest()

if digest != expected_digest:
    raise SystemExit(f"digest mismatch: cli={digest} recomputed={expected_digest}")

if report.get("report_schema") != "mprd/deploy-verify-release/v1":
    raise SystemExit("unexpected deployment release report schema")

if int(report.get("production_policy_count", -1)) < 1:
    raise SystemExit("deployment release fixture has no production policies")

for policy in report.get("policies", []):
    if policy.get("policy_exec_kind") not in {"mpb_v1", "tau_compiled_v1"}:
        raise SystemExit(f"non-production exec kind in release report: {policy}")
    image_id = str(policy.get("image_id_hex", ""))
    if len(image_id) != 64 or set(image_id) == {"0"}:
        raise SystemExit(f"invalid production image id in release report: {policy}")
    if policy.get("artifact_validation") != "validated":
        raise SystemExit(f"policy artifact was not validated: {policy}")

gate = {
    "schema": "mprd/deployment-wiring-fixture-gate/v1",
    "ok": True,
    "release_report_path": str(out_dir / "deployment-release-report.json"),
    "release_report_digest": digest,
    "production_policy_count": report["production_policy_count"],
    "policy_exec_kinds": sorted({p["policy_exec_kind"] for p in report["policies"]}),
}
(out_dir / "deployment-wiring-gate-report.json").write_text(
    json.dumps(gate, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(gate, sort_keys=True))
PY
