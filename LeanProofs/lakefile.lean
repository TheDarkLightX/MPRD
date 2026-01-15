import Lake
open Lake DSL

package «MPRDLeanProofs» where
  -- Keep it lightweight: Lean core only (no Mathlib dependency)
  moreLeanArgs := #["-DautoImplicit=false", "-Dlinter.missingDocs=false"]

@[default_target]
lean_lib MPRDLeanProofs where
  roots := #[
    `MPRDLeanProofs,
    `MPRD_Theorem,
    `MPRD_Alignment_Combined,
    `TauTables_SelectSet
  ]

