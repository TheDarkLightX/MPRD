#!/usr/bin/env bash
set -euo pipefail

subcmd="${1:-help}"
shift || true

usage() {
  cat <<'EOF'
Usage: tools/test.sh <command> [cargo_test_args...]

Commands:
  fast       Run the most common local test set (no long zk suite)
  core       Run mprd-core tests
  proof      Run mprd-proof tests
  cli        Run mprd-cli tests
  zk         Run mprd-zk tests (can be slow)
  all        Run full workspace tests (can be slow)
  pbt-core   Run mprd-core with higher PROPTEST_CASES (default 256)

Examples:
  tools/test.sh fast
  tools/test.sh core -- --nocapture
  PROPTEST_CASES=512 tools/test.sh pbt-core
EOF
}

case "$subcmd" in
  help|-h|--help)
    usage
    ;;
  fast)
    cargo test -p mprd-core -p mprd-proof -p mprd-cli "$@"
    ;;
  core)
    cargo test -p mprd-core "$@"
    ;;
  proof)
    cargo test -p mprd-proof "$@"
    ;;
  cli)
    cargo test -p mprd-cli "$@"
    ;;
  zk)
    cargo test -p mprd-zk "$@"
    ;;
  all)
    cargo test --workspace "$@"
    ;;
  pbt-core)
    : "${PROPTEST_CASES:=256}"
    export PROPTEST_CASES
    cargo test -p mprd-core "$@"
    ;;
  *)
    echo "Unknown command: $subcmd" >&2
    usage >&2
    exit 2
    ;;
esac
