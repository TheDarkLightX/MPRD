/-
  MPRD_Alignment_Combined.lean (public bundle)

  A small, generic bridge between:
    * MPRD's architectural safety invariant, and
    * an (external) economic forcing claim that rational maintainers choose ethical policies.

  This file is intentionally lightweight. It does *not* re-encode
  the full economics; instead it treats the economics→ethical-policy statement
  as an axiom/hypothesis and composes it with the MPRD safety lemma.
-/

namespace MPRDAlignment

universe u

/-!
Proof bundle version tag (for reviewers and long-term reproducibility).
-/
def proof_bundle_version : String := "mprd-leanproofs-v1"

def EthicalPolicy
    {S A P : Type u}
    (Allowed : P → S → A → Prop)
    (EthicalAction : P → S → A → Prop)
    (p : P) : Prop :=
  ∀ (s : S) (a : A), Allowed p s a → EthicalAction p s a

/-!
Abstract consequence of the Alignment Theorem at the policy level.

This bridge file declares it as an axiom so that the composition theorem is
fully explicit about assumptions.
-/
axiom alignment_drives_policies_ethical
    {S A P : Type u}
    (Allowed : P → S → A → Prop)
    (EthicalAction : P → S → A → Prop)
    (RationalPolicyMaintainer : P → Prop) :
    ∀ (p : P),
      RationalPolicyMaintainer p →
      EthicalPolicy (Allowed := Allowed) (EthicalAction := EthicalAction) p

/-!
Main combined theorem:

If:
- executed actions are always `Allowed` (MPRD safety), and
- rational maintainers pick policies such that `Allowed → EthicalAction`,

then executed actions are ethically acceptable.
-/
theorem executed_actions_are_ethical
    {S A P : Type u}
    (Allowed : P → S → A → Prop)
    (ExecCalled : P → S → A → Prop)
    (EthicalAction : P → S → A → Prop)
    (RationalPolicyMaintainer : P → Prop)
    (mprd_safety_invariant :
      ∀ (p : P) (s : S) (a : A), ExecCalled p s a → Allowed p s a)
    :
    ∀ (p : P) (s : S) (a : A),
      RationalPolicyMaintainer p →
      ExecCalled p s a →
      EthicalAction p s a := by
  intro p s a h_rational h_exec
  have h_allowed : Allowed p s a := mprd_safety_invariant p s a h_exec
  have h_eth_pol :
      EthicalPolicy (Allowed := Allowed) (EthicalAction := EthicalAction) p :=
    alignment_drives_policies_ethical
      (Allowed := Allowed)
      (EthicalAction := EthicalAction)
      (RationalPolicyMaintainer := RationalPolicyMaintainer)
      p h_rational
  unfold EthicalPolicy at h_eth_pol
  exact h_eth_pol s a h_allowed

end MPRDAlignment

/-!
Versioned alias (same statement, stable name).
-/
abbrev executed_actions_are_ethical_v1 {S A P : Type} :=
  (MPRDAlignment.executed_actions_are_ethical (S := S) (A := A) (P := P))


