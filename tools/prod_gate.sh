#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/prod_gate.sh [options]

Runs the local MPRD production gate. By default this performs the fast,
release-blocking checks that do not require a full Risc0 release rebuild:

  - focused source tests with placeholder Risc0 builds enabled for speed
  - executor adapter tests
  - decentralized executor completion audit
  - registry-bound deployment wiring fixture through `mprd deploy verify-release`
    with local production method placeholders rejected
  - materialized deployment bundle check for `deployment/production/deployment-bundle.json`

Options:
  --out-dir DIR              Gate artifact directory (default: dist/prod-gate/<utc timestamp>)
  --skip-fast-tests          Skip `tools/test.sh fast-lowdisk`
  --skip-executor-audit      Skip decentralized executor current-state audit
  --skip-deployment-fixture  Skip registry-bound deployment wiring fixture
  --skip-deployment-bundle   Skip materialized deployment bundle verification
  --full-release             Also build an attested release artifact with RISC0_FORCE_BUILD=1
  --version VERSION          Version for --full-release (default: v0.1.0-local-prod-gate)
  --target TARGET            Rust target for --full-release (default: rustc host target)
  -h, --help                 Show this help

This gate is intentionally deployment-data agnostic. Real production deployments
must additionally run:

  tools/release/check_deployment_bundle.sh --manifest PATH --out-dir DIR
USAGE
}

out_dir=""
skip_fast_tests=0
skip_executor_audit=0
skip_deployment_fixture=0
skip_deployment_bundle=0
full_release=0
version="v0.1.0-local-prod-gate"
target=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --skip-fast-tests)
      skip_fast_tests=1
      shift
      ;;
    --skip-executor-audit)
      skip_executor_audit=1
      shift
      ;;
    --skip-deployment-fixture)
      skip_deployment_fixture=1
      shift
      ;;
    --skip-deployment-bundle)
      skip_deployment_bundle=1
      shift
      ;;
    --full-release)
      full_release=1
      shift
      ;;
    --version)
      version="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -z "$out_dir" ]]; then
  out_dir="dist/prod-gate/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "$out_dir"

if [[ "$full_release" == "1" && -z "$target" ]]; then
  target="$(rustc -vV | awk '/^host:/ { print $2 }')"
fi

step_files=()

write_step_json() {
  local step_json="$1"
  local name="$2"
  local start="$3"
  local end="$4"
  local exit_code="$5"
  local log_path="$6"
  python3 - "$step_json" "$name" "$start" "$end" "$exit_code" "$log_path" <<'PY'
import json
import pathlib
import sys

out_path, name, start, end, exit_code, log_path = sys.argv[1:7]
payload = {
    "schema": "mprd/local-production-gate-step/v1",
    "name": name,
    "started_at": start,
    "finished_at": end,
    "exit_code": int(exit_code),
    "ok": int(exit_code) == 0,
    "log_path": str(pathlib.Path(log_path)),
}
pathlib.Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

run_step() {
  local name="$1"
  shift
  local log_path="$out_dir/${name}.log"
  local step_json="$out_dir/${name}.json"
  local start
  local end
  local exit_code

  echo "==> $name"
  start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  "$@" >"$log_path" 2>&1
  exit_code=$?
  set -e
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  write_step_json "$step_json" "$name" "$start" "$end" "$exit_code" "$log_path"
  step_files+=("$step_json")
  if [[ "$exit_code" != "0" ]]; then
    echo "step failed: $name (log: $log_path)" >&2
    write_report "false"
    exit "$exit_code"
  fi
}

write_report() {
  local ok="$1"
  python3 - "$out_dir/local-production-gate-report.json" "$out_dir" "$ok" "$full_release" "$version" "${target:-}" "${step_files[@]}" <<'PY'
import json
import pathlib
import subprocess
import sys

report_path = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
ok = sys.argv[3] == "true"
full_release = sys.argv[4] == "1"
version = sys.argv[5]
target = sys.argv[6] or None
step_paths = [pathlib.Path(p) for p in sys.argv[7:]]

def git_output(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None

steps = [json.loads(p.read_text(encoding="utf-8")) for p in step_paths]
dirty_status = git_output(["git", "status", "--porcelain"])
payload = {
    "schema": "mprd/local-production-gate/v1",
    "ok": ok and all(step.get("ok") for step in steps),
    "generated_at": git_output(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]),
    "repo": str(pathlib.Path.cwd()),
    "git_head": git_output(["git", "rev-parse", "HEAD"]),
    "git_dirty": bool(dirty_status),
    "out_dir": str(out_dir),
    "steps": steps,
    "full_release": {
        "enabled": full_release,
        "version": version if full_release else None,
        "target": target if full_release else None,
    },
    "deployment_bundle_gate_required_for_real_deployments": True,
}
report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps({"ok": payload["ok"], "report": str(report_path)}, sort_keys=True))
PY
}

if [[ "$skip_fast_tests" == "0" ]]; then
  run_step fast_lowdisk_tests env RISC0_SKIP_BUILD="${RISC0_SKIP_BUILD:-1}" bash tools/test.sh fast-lowdisk
  run_step executor_adapter_tests env RISC0_SKIP_BUILD="${RISC0_SKIP_BUILD:-1}" cargo test --locked -p mprd-adapters
fi

if [[ "$skip_executor_audit" == "0" ]]; then
  run_step executor_completion_audit python3 internal/experiments/decentralized_executor_20260218/executor_completion_audit_v1.py
fi

if [[ "$skip_deployment_fixture" == "0" ]]; then
  run_step deployment_wiring_fixture env -u RISC0_SKIP_BUILD tools/release/check_deployment_wiring_fixture.sh --out-dir "$out_dir/deployment-wiring-fixture"
fi

if [[ "$skip_deployment_bundle" == "0" ]]; then
  run_step deployment_bundle_gate env -u RISC0_SKIP_BUILD tools/release/check_deployment_bundle.sh --manifest deployment/production/deployment-bundle.json --out-dir "$out_dir/deployment-bundle-gate"
fi

if [[ "$full_release" == "1" ]]; then
  run_step attested_release_build tools/release/build_attested_release.sh \
    --version "$version" \
    --target "$target" \
    --out-dir "$out_dir/release"
fi

write_report "true"
