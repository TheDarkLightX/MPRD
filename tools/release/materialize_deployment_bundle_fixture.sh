#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/release/materialize_deployment_bundle_fixture.sh --out-dir DIR

Materializes a deterministic registry-bound deployment bundle from the trustless
fixture generator. The output is suitable for `tools/release/check_deployment_bundle.sh`.

The generated bundle contains public release inputs only:
  - signed registry checkpoint
  - signed guest image manifest embedded in the registry checkpoint
  - policy artifact bytes
  - production config with no private token signing key
  - deployment-bundle manifest with public verifying key material

It intentionally does not copy token signing key env files, signed state requests,
candidate request bodies, or operator-private material.
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

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fixture_root="$tmp_dir/trustless-fixture"
env -u RISC0_SKIP_BUILD cargo run --locked --quiet -p mprd-cli --bin mprd-trustless-fixture -- \
  --output "$fixture_root" > "$tmp_dir/fixture-summary.json"

rm -rf "$out_dir"
mkdir -p "$out_dir/policy-artifacts"

cp "$fixture_root/.mprd/registry_state.json" "$out_dir/registry_state.json"
cp "$fixture_root/.mprd/policy-artifacts/"* "$out_dir/policy-artifacts/"

python3 - "$fixture_root/.mprd/config.json" "$out_dir/config.json" "$out_dir/deployment-bundle.json" "$out_dir/README.md" "$out_dir/registry-authority.json" "$out_dir/registry_state.json" <<'PY'
import json
import pathlib
import sys

config_path = pathlib.Path(sys.argv[1])
out_config_path = pathlib.Path(sys.argv[2])
manifest_path = pathlib.Path(sys.argv[3])
readme_path = pathlib.Path(sys.argv[4])
authority_path = pathlib.Path(sys.argv[5])
registry_state_path = pathlib.Path(sys.argv[6])

config = json.loads(config_path.read_text(encoding="utf-8"))
registry_state = json.loads(registry_state_path.read_text(encoding="utf-8"))
registry_key_hex = config["registry_verifying_key_hex"]
state = registry_state["state"]
policy_epoch = state["policy_epoch"]
registry_root_hex = "".join(f"{b:02x}" for b in state["registry_root"])
policy_rows = []
for policy in state["authorized_policies"]:
    policy_rows.append({
        "policy_hash_hex": "".join(f"{b:02x}" for b in policy["policy_hash"]),
        "namespace_id": "tau-owner-default",
        "certification_tier": "certified",
        "activation_epoch": policy_epoch,
        "admitted_node_ids": ["prod-node-1"],
        "policy_exec_kind": "mpb_v1",
        "source_governance": "TauGovernedMapped",
    })

config["registry_state_path"] = "registry_state.json"
config["policy_artifacts_dir"] = "policy-artifacts"
config.setdefault("policy_storage", {})["local_dir"] = "policies"
config.setdefault("anti_replay", {})["nonce_store_dir"] = "anti_replay"
config.setdefault("execution", {})["audit_file"] = "audit.jsonl"
out_config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")

manifest = {
    "schema": "mprd/deployment-bundle/v1",
    "environment": "production",
    "registry_state": "registry_state.json",
    "registry_key_hex": registry_key_hex,
    "manifest_key_hex": None,
    "policy_artifacts_dir": "policy-artifacts",
    "production_config": "config.json",
    "registry_authority": "registry-authority.json",
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

authority = {
    "schema": "mprd/registry-authority-admission/v1",
    "environment": "production",
    "registry_binding": {
        "policy_epoch": policy_epoch,
        "registry_root_hex": registry_root_hex,
    },
    "local_node_id": "prod-node-1",
    "namespaces": [
        {
            "namespace_id": "tau-owner-default",
            "owner_set_id": "tau-owner-set-production",
            "allowed_node_ids": ["prod-node-1"],
            "min_certification_tier": "certified",
            "activation_epoch": policy_epoch,
        }
    ],
    "policy_admissions": policy_rows,
}
authority_path.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n", encoding="utf-8")

readme_path.write_text(
    """# MPRD Production Deployment Bundle

This directory is a deterministic registry-bound deployment bundle used by the
production-readiness gate. It is materialized by
`tools/release/materialize_deployment_bundle_fixture.sh` and verified by
`tools/release/check_deployment_bundle.sh`.

The bundle contains public deployment inputs only. Do not add private signing
keys, token signing key env files, operator request payloads, or private registry
seeds to this directory.

`registry-authority.json` is a release-bound authority packet bound to the
verified registry epoch/root. It names the production namespace, owner set,
node assignment, activation epoch, and certification tier for each admitted
policy.

Verification:

```sh
tools/release/check_deployment_bundle.sh \\
  --manifest deployment/production/deployment-bundle.json \\
  --out-dir dist/deployment-bundle-gate
```
""",
    encoding="utf-8",
)
PY

echo "materialized deployment bundle: $out_dir/deployment-bundle.json"
