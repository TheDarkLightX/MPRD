/-
  MPRD_ExecutionGate.lean

  A guarded execution-gate model for MPRD.  This extends the lightweight
  lifecycle proof with explicit governance, replay, and binding assumptions.
-/

namespace MPRDExecutionGate

def proof_bundle_version : String := "mprd-leanproofs-v3"

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
  governanceOk : Bool
  replayOk : Bool
  bindingOk : Bool
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.proof = .pending ∧ s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ExecutedImpliesGuardedVerified (s : State) : Prop :=
  Executed s ->
    s.proof = .verified ∧
    s.verdict = .allowed ∧
    s.governanceOk = true ∧
    s.replayOk = true ∧
    s.bindingOk = true

inductive Step : State -> State -> Prop
  | proof_pending_stay (v : Verdict) (g r b : Bool) :
      Step
        { proof := .pending, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .pending, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | proof_pending_verify (v : Verdict) (g r b : Bool) :
      Step
        { proof := .pending, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .verified, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | proof_pending_fail (v : Verdict) (g r b : Bool) :
      Step
        { proof := .pending, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .failed, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | proof_verified_stay (v : Verdict) (g r b : Bool) :
      Step
        { proof := .verified, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .verified, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | proof_failed_stay (v : Verdict) (g r b : Bool) :
      Step
        { proof := .failed, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .failed, exec := .skipped, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | exec_skipped_to_success :
      Step
        { proof := .verified, exec := .skipped, verdict := .allowed, governanceOk := true, replayOk := true, bindingOk := true }
        { proof := .verified, exec := .succeeded, verdict := .allowed, governanceOk := true, replayOk := true, bindingOk := true }
  | exec_skipped_to_failed :
      Step
        { proof := .verified, exec := .skipped, verdict := .allowed, governanceOk := true, replayOk := true, bindingOk := true }
        { proof := .verified, exec := .failed, verdict := .allowed, governanceOk := true, replayOk := true, bindingOk := true }
  | exec_success_stay (v : Verdict) (g r b : Bool) :
      Step
        { proof := .verified, exec := .succeeded, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .verified, exec := .succeeded, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | exec_failed_stay (v : Verdict) (g r b : Bool) :
      Step
        { proof := .verified, exec := .failed, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
        { proof := .verified, exec := .failed, verdict := v, governanceOk := g, replayOk := r, bindingOk := b }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_guarded_verified {s : State} (hInit : Initial s) :
    ExecutedImpliesGuardedVerified s := by
  intro hExecuted
  rcases hInit with ⟨_hProof, hSkipped⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hSkipped
  | inr hFailure =>
      cases hFailure.symm.trans hSkipped

theorem step_preserves_executed_implies_guarded_verified {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesGuardedVerified s) :
    ExecutedImpliesGuardedVerified t := by
  intro hExecuted
  cases hStep with
  | proof_pending_stay =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | proof_pending_verify =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | proof_pending_fail =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | proof_verified_stay =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | proof_failed_stay =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess
      | inr hFailure =>
          cases hFailure
  | exec_skipped_to_success =>
      exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | exec_skipped_to_failed =>
      exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  | exec_success_stay =>
      exact hInv hExecuted
  | exec_failed_stay =>
      exact hInv hExecuted
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_all_guards :
    ∀ {s : State}, Reachable s -> ExecutedImpliesGuardedVerified s
  | _, .init hInit =>
      initial_executed_implies_guarded_verified hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_guarded_verified hStep
        (reachable_executed_states_require_all_guards hReach)

theorem executed_reachable_states_require_verified_allowed_authorized_bound
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.proof = .verified ∧
      s.verdict = .allowed ∧
      s.governanceOk = true ∧
      s.replayOk = true ∧
      s.bindingOk = true :=
  reachable_executed_states_require_all_guards hReach

end MPRDExecutionGate

abbrev executed_reachable_states_require_verified_allowed_authorized_bound_v1 :=
  @MPRDExecutionGate.executed_reachable_states_require_verified_allowed_authorized_bound
