/-
  MPRD_ExecutionLifecycle.lean

  A lightweight Lean model of the decision lifecycle used in the ShapeForge
  execution-gate slice.  This mirrors the checked-in TLA+ lifecycle at the
  level of reachable states and proves the two core invariants:

    * denied verdicts imply execution is skipped
    * executed states imply the proof status is verified
-/

namespace MPRDExecutionLifecycle

/-!
Proof bundle version tag (for reviewers and reproducibility).
-/
def proof_bundle_version : String := "mprd-leanproofs-v2"

inductive Verdict where
  | allowed
  | denied
  deriving Repr, DecidableEq

inductive ProofStatus where
  | pending
  | verified
  | failed
  deriving Repr, DecidableEq

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  proof : ProofStatus
  exec : ExecStatus
  verdict : Verdict
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.proof = .pending ∧ s.exec = .skipped

def DeniedImpliesSkipped (s : State) : Prop :=
  s.verdict = .denied -> s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ExecutedImpliesVerified (s : State) : Prop :=
  Executed s -> s.proof = .verified

inductive Step : State -> State -> Prop
  | proof_pending_stay (e : ExecStatus) (v : Verdict) :
      Step
        { proof := .pending, exec := e, verdict := v }
        { proof := .pending, exec := e, verdict := v }
  | proof_pending_verify (e : ExecStatus) (v : Verdict) :
      Step
        { proof := .pending, exec := e, verdict := v }
        { proof := .verified, exec := e, verdict := v }
  | proof_pending_fail (e : ExecStatus) (v : Verdict) :
      Step
        { proof := .pending, exec := e, verdict := v }
        { proof := .failed, exec := e, verdict := v }
  | proof_verified_stay (e : ExecStatus) (v : Verdict) :
      Step
        { proof := .verified, exec := e, verdict := v }
        { proof := .verified, exec := e, verdict := v }
  | proof_failed_stay (e : ExecStatus) (v : Verdict) :
      Step
        { proof := .failed, exec := e, verdict := v }
        { proof := .failed, exec := e, verdict := v }
  | exec_skipped_to_success :
      Step
        { proof := .verified, exec := .skipped, verdict := .allowed }
        { proof := .verified, exec := .succeeded, verdict := .allowed }
  | exec_skipped_to_failed :
      Step
        { proof := .verified, exec := .skipped, verdict := .allowed }
        { proof := .verified, exec := .failed, verdict := .allowed }
  | exec_success_stay (p : ProofStatus) (v : Verdict) :
      Step
        { proof := p, exec := .succeeded, verdict := v }
        { proof := p, exec := .succeeded, verdict := v }
  | exec_failed_stay (p : ProofStatus) (v : Verdict) :
      Step
        { proof := p, exec := .failed, verdict := v }
        { proof := p, exec := .failed, verdict := v }
  | exec_skipped_stay (p : ProofStatus) (v : Verdict) :
      Step
        { proof := p, exec := .skipped, verdict := v }
        { proof := p, exec := .skipped, verdict := v }
  | stutter (p : ProofStatus) (e : ExecStatus) (v : Verdict) :
      Step
        { proof := p, exec := e, verdict := v }
        { proof := p, exec := e, verdict := v }

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_denied_implies_skipped {s : State} (hInit : Initial s) :
    DeniedImpliesSkipped s := by
  intro _hDenied
  exact hInit.2

theorem initial_executed_implies_verified {s : State} (hInit : Initial s) :
    ExecutedImpliesVerified s := by
  intro hExecuted
  rcases hInit with ⟨_hProof, hSkipped⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hSkipped
  | inr hFailure =>
      cases hFailure.symm.trans hSkipped

theorem step_preserves_denied_implies_skipped {s t : State}
    (hStep : Step s t)
    (hInv : DeniedImpliesSkipped s) :
    DeniedImpliesSkipped t := by
  intro hDenied
  cases hStep with
  | proof_pending_stay =>
      exact hInv hDenied
  | proof_pending_verify =>
      exact hInv hDenied
  | proof_pending_fail =>
      exact hInv hDenied
  | proof_verified_stay =>
      exact hInv hDenied
  | proof_failed_stay =>
      exact hInv hDenied
  | exec_skipped_to_success =>
      cases hDenied
  | exec_skipped_to_failed =>
      cases hDenied
  | exec_success_stay =>
      cases hInv hDenied
  | exec_failed_stay =>
      cases hInv hDenied
  | exec_skipped_stay =>
      rfl
  | stutter =>
      exact hInv hDenied

theorem step_preserves_executed_implies_verified {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesVerified s) :
    ExecutedImpliesVerified t := by
  intro hExecuted
  cases hStep with
  | proof_pending_stay =>
      exact hInv hExecuted
  | proof_pending_verify =>
      rfl
  | proof_pending_fail =>
      have hImpossible : ProofStatus.pending = ProofStatus.verified := hInv hExecuted
      cases hImpossible
  | proof_verified_stay =>
      exact hInv hExecuted
  | proof_failed_stay =>
      exact hInv hExecuted
  | exec_skipped_to_success =>
      rfl
  | exec_skipped_to_failed =>
      rfl
  | exec_success_stay =>
      exact hInv hExecuted
  | exec_failed_stay =>
      exact hInv hExecuted
  | exec_skipped_stay =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | stutter =>
      exact hInv hExecuted

theorem reachable_denied_implies_skipped :
    ∀ {s : State}, Reachable s -> DeniedImpliesSkipped s
  | _, .init hInit =>
      initial_denied_implies_skipped hInit
  | _, .step hReach hStep =>
      step_preserves_denied_implies_skipped hStep (reachable_denied_implies_skipped hReach)

theorem reachable_executed_implies_verified :
    ∀ {s : State}, Reachable s -> ExecutedImpliesVerified s
  | _, .init hInit =>
      initial_executed_implies_verified hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_verified hStep (reachable_executed_implies_verified hReach)

theorem denied_reachable_states_stay_skipped
    {s : State} (hReach : Reachable s) :
    s.verdict = .denied -> s.exec = .skipped :=
  reachable_denied_implies_skipped hReach

theorem executed_reachable_states_require_verified_proofs
    {s : State} (hReach : Reachable s) :
    Executed s -> s.proof = .verified :=
  reachable_executed_implies_verified hReach

end MPRDExecutionLifecycle

/-!
Versioned aliases (same statements, stable names).
-/
abbrev denied_reachable_states_stay_skipped_v1 :=
  @MPRDExecutionLifecycle.denied_reachable_states_stay_skipped

abbrev executed_reachable_states_require_verified_proofs_v1 :=
  @MPRDExecutionLifecycle.executed_reachable_states_require_verified_proofs
