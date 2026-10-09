#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/release/check_deployment_bundle.sh --manifest PATH --out-dir DIR

Verifies an actual deployment bundle manifest with `mprd deploy verify-release`.

Manifest schema: mprd/deployment-bundle/v1

Example:
{
  "schema": "mprd/deployment-bundle/v1",
  "environment": "production",
  "registry_state": "registry_state.json",
  "registry_key_hex": "<32-byte public verifying key hex>",
  "manifest_key_hex": "<optional 32-byte public verifying key hex>",
  "policy_artifacts_dir": "policy-artifacts",
  "production_config": "config.json",
  "registry_authority": "registry-authority.json"
}

All paths are resolved relative to the manifest directory. The manifest contains
public verifying keys only; do not put private signing keys in deployment bundles.
USAGE
}

manifest_path=""
out_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      manifest_path="${2:-}"
      shift 2
      ;;
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

if [[ -z "$manifest_path" || -z "$out_dir" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

mkdir -p "$out_dir"

python3 - "$manifest_path" "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json
import pathlib
import re
import sys

manifest_path = pathlib.Path(sys.argv[1]).resolve()
out_path = pathlib.Path(sys.argv[2]).resolve()

with manifest_path.open("r", encoding="utf-8") as fh:
    manifest = json.load(fh)

if manifest.get("schema") != "mprd/deployment-bundle/v1":
    raise SystemExit("deployment bundle manifest schema must be mprd/deployment-bundle/v1")

base = manifest_path.parent

def required_str(key: str) -> str:
    value = manifest.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"deployment bundle manifest missing non-empty string field: {key}")
    return value.strip()

def optional_str(key: str) -> str | None:
    value = manifest.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"deployment bundle manifest field must be null or non-empty string: {key}")
    return value.strip()

def resolve_path(key: str, *, required: bool = True) -> str | None:
    raw = required_str(key) if required else optional_str(key)
    if raw is None:
        return None
    path = (base / raw).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise SystemExit(f"{key} must stay within deployment bundle directory") from exc
    if not path.exists():
        raise SystemExit(f"{key} path does not exist: {path}")
    return str(path)

def validate_key_hex(key: str, *, required: bool) -> str | None:
    raw = required_str(key) if required else optional_str(key)
    if raw is None:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise SystemExit(f"{key} must be 32-byte hex")
    if set(raw.lower()) == {"0"}:
        raise SystemExit(f"{key} must not be all-zero")
    return raw.lower()

resolved = {
    "schema": "mprd/deployment-bundle-resolved/v1",
    "environment": required_str("environment"),
    "manifest_path": str(manifest_path),
    "registry_state": resolve_path("registry_state"),
    "registry_key_hex": validate_key_hex("registry_key_hex", required=True),
    "manifest_key_hex": validate_key_hex("manifest_key_hex", required=False),
    "policy_artifacts_dir": resolve_path("policy_artifacts_dir"),
    "production_config": resolve_path("production_config", required=False),
    "registry_authority": resolve_path("registry_authority"),
}

out_path.write_text(json.dumps(resolved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(resolved, sort_keys=True))
PY

registry_state="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["registry_state"])
PY
)"
registry_key_hex="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["registry_key_hex"])
PY
)"
manifest_key_hex="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], "r", encoding="utf-8")).get("manifest_key_hex")
print(value or "")
PY
)"
policy_artifacts_dir="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["policy_artifacts_dir"])
PY
)"
production_config="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], "r", encoding="utf-8")).get("production_config")
print(value or "")
PY
)"
registry_authority="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["registry_authority"])
PY
)"
environment="$(
  python3 - "$out_dir/resolved-deployment-bundle.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], "r", encoding="utf-8"))["environment"])
PY
)"

verify_args=(
  "run" "--locked" "--quiet" "-p" "mprd-cli" "--bin" "mprd" "--"
  "deploy" "verify-release"
  "--registry-state" "$registry_state"
  "--registry-key-hex" "$registry_key_hex"
  "--policy-artifacts-dir" "$policy_artifacts_dir"
)
if [[ -n "$manifest_key_hex" ]]; then
  verify_args+=("--manifest-key-hex" "$manifest_key_hex")
fi
if [[ -n "$production_config" ]]; then
  verify_args+=("--config" "$production_config")
fi

cargo "${verify_args[@]}" --format json > "$out_dir/deployment-release-report.json"

python3 tools/release/check_registry_authority_packet.py \
  --registry-authority "$registry_authority" \
  --release-report "$out_dir/deployment-release-report.json" \
  --environment "$environment" \
  --out "$out_dir/registry-authority-report.json" > "$out_dir/registry-authority-report.stdout"

cargo "${verify_args[@]}" --format digest > "$out_dir/deployment-release-report.digest"

python3 - "$out_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

out_dir = pathlib.Path(sys.argv[1])
resolved = json.loads((out_dir / "resolved-deployment-bundle.json").read_text(encoding="utf-8"))
report = json.loads((out_dir / "deployment-release-report.json").read_text(encoding="utf-8"))
authority_report = json.loads((out_dir / "registry-authority-report.json").read_text(encoding="utf-8"))
digest = (out_dir / "deployment-release-report.digest").read_text(encoding="utf-8").strip()
expected_digest = hashlib.sha256(json.dumps(report, indent=2).encode("utf-8")).hexdigest()
if digest != expected_digest:
    raise SystemExit(f"digest mismatch: cli={digest} recomputed={expected_digest}")
if report.get("report_schema") != "mprd/deploy-verify-release/v1":
    raise SystemExit("unexpected deployment release report schema")
if int(report.get("production_policy_count", -1)) < 1:
    raise SystemExit("deployment bundle has no production policies")
if authority_report.get("schema") != "mprd/registry-authority-admission-report/v1" or not authority_report.get("ok"):
    raise SystemExit("registry authority admission report failed")

gate = {
    "schema": "mprd/deployment-bundle-gate/v1",
    "ok": True,
    "environment": resolved["environment"],
    "bundle_manifest_path": resolved["manifest_path"],
    "release_report_path": str(out_dir / "deployment-release-report.json"),
    "release_report_digest": digest,
    "registry_authority_report_path": str(out_dir / "registry-authority-report.json"),
    "registry_authority_namespace_count": authority_report["namespace_count"],
    "registry_authority_policy_admission_count": authority_report["policy_admission_count"],
    "production_policy_count": report["production_policy_count"],
    "policy_exec_kinds": sorted({p["policy_exec_kind"] for p in report["policies"]}),
}
(out_dir / "deployment-bundle-gate-report.json").write_text(
    json.dumps(gate, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(gate, sort_keys=True))
PY
