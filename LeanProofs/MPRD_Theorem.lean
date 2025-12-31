/-
  MPRD_Theorem.lean (public bundle)

  Formalization of the core safety invariant of the MPRD architecture:

    "Model proposes, rules decide. Every executed action is allowed."

  This file is intentionally lightweight (no Mathlib dependency).
-/

namespace MPRD

universe u

/-!
Proof bundle version tag (for reviewers and long-term reproducibility).
-/
def proof_bundle_version : String := "mprd-leanproofs-v1"

/-!
## Safety invariant (abstract, contract-based)

We work with abstract types:

* `S` – environment states
* `A` – actions
* `P` – policies (rule systems)

and abstract components:

* `Allowed : P → S → A → Prop` — the rules predicate
* `M : S → List A` — the model/proposer (candidates only)
* `Sel : P → S → List A → A` — the selector
* `ExecCalled : P → S → A → Prop` — “a side-effect actually occurred”

We assume two contracts:

1) Selector contract: `Sel` returns an allowed element of the candidate list.
2) Execution guard: execution can only happen for the selector’s output on the model’s list.

Then the safety invariant is immediate:

  `ExecCalled p s a → Allowed p s a`.
-/

theorem safety_invariant
    {S A P : Type u}
    (Allowed : P → S → A → Prop)
    (M : S → List A)
    (Sel : P → S → List A → A)
    (ExecCalled : P → S → A → Prop)
    (Sel_respects_Allowed :
      ∀ (p : P) (s : S) (C : List A),
        List.Mem (Sel p s C) C ∧ Allowed p s (Sel p s C))
    (Exec_only_for_Sel :
      ∀ (p : P) (s : S) (a : A),
        ExecCalled p s a → ∃ C, C = M s ∧ a = Sel p s C) :
    ∀ (p : P) (s : S) (a : A),
      ExecCalled p s a → Allowed p s a := by
  intro p s a hExec
  rcases Exec_only_for_Sel p s a hExec with ⟨C, hC, ha⟩
  subst hC
  have h := Sel_respects_Allowed p s (M s)
  simpa [ha] using h.2

end MPRD

/-!
Versioned alias (same statement, stable name).
-/
abbrev safety_invariant_v1 {S A P : Type} := (MPRD.safety_invariant (S := S) (A := A) (P := P))

