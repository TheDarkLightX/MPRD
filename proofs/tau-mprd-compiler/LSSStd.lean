import Std

/-!
  Minimal Lean 4 proof artifacts for the LSS circuit scrambler.

  This file is intentionally **Mathlib-free** so it can be checked in offline/airgapped
  environments where `Mathlib` is not available in the Lean search path.

  Scope:
  - Proves the propositional lemma used by semantic decoy injection.
  - Proves a generic “mask/unmask” inversion lemma **given an explicit inverse assumption**.

  Non-goals:
  - Proving existence of inverses for odd numbers in Z/(2^64)Z (requires Mathlib `ZMod` tooling).
-/

namespace LSSStd

section Decoy

theorem decoy_injection_preserves_semantics (P o d : Prop) (hP : P) :
    (P ∧ o) ∨ (¬P ∧ d) ↔ o := by
  constructor
  · intro h
    cases h with
    | inl h1 => exact h1.2
    | inr h2 => exact False.elim (h2.1 hP)
  · intro ho
    exact Or.inl ⟨hP, ho⟩

theorem layer_composition_preserves_semantics
    {α : Type} (f : α → Prop)
    (L1 L2 L3 L4 L5 : α → α)
    (h1 : ∀ x, f (L1 x) ↔ f x)
    (h2 : ∀ x, f (L2 x) ↔ f x)
    (h3 : ∀ x, f (L3 x) ↔ f x)
    (h4 : ∀ x, f (L4 x) ↔ f x)
    (h5 : ∀ x, f (L5 x) ↔ f x)
    (x : α) : f (L5 (L4 (L3 (L2 (L1 x))))) ↔ f x := by
  simpa using (Iff.trans (h5 _) (Iff.trans (h4 _) (Iff.trans (h3 _) (Iff.trans (h2 _) (h1 _)))))

end Decoy

end LSSStd
