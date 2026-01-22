# MPRD Lean Proofs (Public)

This directory contains a **small, self-contained Lean 4** proof bundle for the
core MPRD safety invariant and its abstract composition with an economic forcing
assumption.

## What is included

- `MPRD_Theorem.lean`: the core safety invariant (contract-based).
- `MPRD_Alignment_Combined.lean`: composition lemma (explicitly states assumptions).

## How to typecheck

From the repo root:

```bash
cd proofs/lean
lake build
```

Or typecheck individual files:

```bash
cd proofs/lean
lake env lean MPRD_Theorem.lean
lake env lean MPRD_Alignment_Combined.lean
```

## Notes

- These proofs are **Lean core only** (no Mathlib dependency) to keep builds fast.
- The economics → “ethical policy selection” step is intentionally modeled as an
  **explicit axiom** in `MPRD_Alignment_Combined.lean`; this file is a *bridge*
  lemma, not a full economic development.
