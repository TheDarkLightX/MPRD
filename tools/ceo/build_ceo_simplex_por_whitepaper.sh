#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/home/trevormoc/Downloads/MPRD}"
cd "$ROOT"

SRC="docs/whitepapers/CEO_Simplex_POR_Whitepaper.tex"
OUTDIR="public/whitepapers"
OUTPDF="${OUTDIR}/CEO_Simplex_POR_Whitepaper.pdf"

mkdir -p "$OUTDIR"

# Build in a temp dir to avoid leaving LaTeX artifacts in-repo.
TMPD="$(mktemp -d)"
cleanup() { rm -rf "$TMPD"; }
trap cleanup EXIT

cp "$SRC" "$TMPD/main.tex"

latexmk -pdf -interaction=nonstopmode -halt-on-error -quiet -outdir="$TMPD" "$TMPD/main.tex"

cp "$TMPD/main.pdf" "$OUTPDF"
echo "[whitepaper] wrote ${OUTPDF}"

