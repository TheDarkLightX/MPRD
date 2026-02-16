#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT"

SRC="internal/whitepapers/MPRD_Security_Whitepaper.tex"
OUTDIR="docs/whitepapers"
OUTPDF="${OUTDIR}/MPRD_Security_Whitepaper.pdf"

mkdir -p "$OUTDIR"

# Build in a temp dir to avoid leaving LaTeX artifacts in-repo.
TMPD="$(mktemp -d)"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

cp "$SRC" "$TMPD/main.tex"
latexmk -pdf -interaction=nonstopmode -halt-on-error -quiet -outdir="$TMPD" "$TMPD/main.tex"

cp "$TMPD/main.pdf" "$OUTPDF"
echo "[whitepaper] wrote ${OUTPDF}"

