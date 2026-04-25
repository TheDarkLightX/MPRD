# Proof artifacts

This repo keeps proof artifacts under `proofs/`:

- `proofs/lean/`: a small, self-contained Lean 4 bundle (run `cd proofs/lean && lake build`)
- `proofs/policy_algebra/`: Lean specs + auxiliary proofs for policy-algebra “veto-first”
  semantics and fail-closed hardening obligations.
- `proofs/tau-mprd-compiler/`: verification artifacts for `tools/tau-mprd-compiler/`

Focused policy-algebra checks:

```bash
cd proofs/lean
lake env lean ../policy_algebra/PolicyAlgebraVeto.lean
lake env lean ../policy_algebra/FailClosedHardening.lean
```
