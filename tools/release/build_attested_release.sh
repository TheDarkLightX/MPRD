#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/release/build_attested_release.sh --version vX.Y.Z --target TARGET [options]

Options:
  --out-dir DIR       Output directory (default: dist/release)
  --allow-dirty      Permit packaging from a dirty worktree for local dry runs only

This script builds production-grade binary release artifacts. It requires
RISC0_FORCE_BUILD=1 and refuses RISC0_SKIP_BUILD=1 during packaging.
USAGE
}

version=""
target=""
out_dir="dist/release"
allow_dirty=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty=1
      shift
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

if [[ -z "$version" || -z "$target" ]]; then
  usage >&2
  exit 2
fi

case "$version" in
  v*) ;;
  *)
    echo "release version must start with v: $version" >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

target_out="$out_dir/$version/$target"
mkdir -p "$target_out"

export RISC0_FORCE_BUILD=1
unset RISC0_SKIP_BUILD
export CARGO_RISCZERO_VERSION="${CARGO_RISCZERO_VERSION:-cargo-risczero 1.2.6}"

cargo build --locked -p mprd-risc0-methods
cargo test --locked -p mprd-risc0-methods --lib

cargo run --locked -p mprd-risc0-methods --bin print_image_ids -- --json > "$target_out/image_ids.json"
cargo run --locked -p mprd-risc0-methods --bin print_image_ids -- --text > "$target_out/image_ids.txt"
python3 tools/release/check_image_ids.py "$target_out/image_ids.json"
tools/release/check_deployment_wiring_fixture.sh --out-dir "$target_out/deployment-wiring-gate"

rustup target add "$target"
cargo build --locked -p mprd-cli --release --target "$target"

target_root="${CARGO_TARGET_DIR:-target}"
binary_path="$target_root/$target/release/mprd"
if [[ ! -x "$binary_path" ]]; then
  echo "missing release binary: $binary_path" >&2
  exit 1
fi

python3 tools/release/generate_cargo_sbom.py \
  --version "$version" \
  --target "$target" \
  --output "$target_out/mprd-$version-$target-sbom.spdx.json"

package_args=(
  --version "$version"
  --target "$target"
  --binary "$binary_path"
  --image-ids-json "$target_out/image_ids.json"
  --image-ids-text "$target_out/image_ids.txt"
  --sbom "$target_out/mprd-$version-$target-sbom.spdx.json"
  --output-dir "$target_out"
)

if [[ "$allow_dirty" == "1" ]]; then
  package_args+=(--allow-dirty)
fi

python3 tools/release/package_attested_binary.py "${package_args[@]}"
