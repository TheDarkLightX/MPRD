/-
  MPRD_ExecutionCommitmentBindings.lean

  A concrete execution-gate model for MPRD. This refines the earlier
  `bindingOk` flag into the individual commitment checks surfaced by
  `verify_journal_commitments_with_private_limits`.
-/

namespace MPRDExecutionCommitmentBindings

def proof_bundle_version : String := "mprd-leanproofs-v4"

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

structure BindingVector where
  journalAllowed : Bool
  limitsHashMatches : Bool
  decisionCommitmentValid : Bool
  policyHashMatches : Bool
  policyEpochMatches : Bool
  registryRootMatches : Bool
  stateSourceMatches : Bool
  stateEpochMatches : Bool
  stateAttestationMatches : Bool
  stateHashMatches : Bool
  candidateSetHashMatches : Bool
  chosenActionHashMatches : Bool
  nonceMatches : Bool
  deriving Repr, DecidableEq

def ConcreteBindingsHold (b : BindingVector) : Prop :=
  b.journalAllowed = true ∧
    b.limitsHashMatches = true ∧
    b.decisionCommitmentValid = true ∧
    b.policyHashMatches = true ∧
    b.policyEpochMatches = true ∧
    b.registryRootMatches = true ∧
    b.stateSourceMatches = true ∧
    b.stateEpochMatches = true ∧
    b.stateAttestationMatches = true ∧
    b.stateHashMatches = true ∧
    b.candidateSetHashMatches = true ∧
    b.chosenActionHashMatches = true ∧
    b.nonceMatches = true

structure Context where
  verdict : Verdict
  governanceOk : Bool
  replayOk : Bool
  bindings : BindingVector
  deriving Repr, DecidableEq

structure State where
  proof : ProofStatus
  exec : ExecStatus
  ctx : Context
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.proof = .pending ∧ s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ExecutedImpliesConcreteGate (s : State) : Prop :=
  Executed s ->
    s.proof = .verified ∧
      s.ctx.verdict = .allowed ∧
      s.ctx.governanceOk = true ∧
      s.ctx.replayOk = true ∧
      ConcreteBindingsHold s.ctx.bindings

inductive Step : State -> State -> Prop
  | proof_pending_stay (c : Context) :
      Step
        { proof := .pending, exec := .skipped, ctx := c }
        { proof := .pending, exec := .skipped, ctx := c }
  | proof_pending_verify (c : Context) :
      Step
        { proof := .pending, exec := .skipped, ctx := c }
        { proof := .verified, exec := .skipped, ctx := c }
  | proof_pending_fail (c : Context) :
      Step
        { proof := .pending, exec := .skipped, ctx := c }
        { proof := .failed, exec := .skipped, ctx := c }
  | proof_verified_stay (c : Context) :
      Step
        { proof := .verified, exec := .skipped, ctx := c }
        { proof := .verified, exec := .skipped, ctx := c }
  | proof_failed_stay (c : Context) :
      Step
        { proof := .failed, exec := .skipped, ctx := c }
        { proof := .failed, exec := .skipped, ctx := c }
  | exec_skipped_to_success (c : Context)
      (hVerdict : c.verdict = .allowed)
      (hGovernance : c.governanceOk = true)
      (hReplay : c.replayOk = true)
      (hBindings : ConcreteBindingsHold c.bindings) :
      Step
        { proof := .verified, exec := .skipped, ctx := c }
        { proof := .verified, exec := .succeeded, ctx := c }
  | exec_skipped_to_failed (c : Context)
      (hVerdict : c.verdict = .allowed)
      (hGovernance : c.governanceOk = true)
      (hReplay : c.replayOk = true)
      (hBindings : ConcreteBindingsHold c.bindings) :
      Step
        { proof := .verified, exec := .skipped, ctx := c }
        { proof := .verified, exec := .failed, ctx := c }
  | exec_success_stay (c : Context) :
      Step
        { proof := .verified, exec := .succeeded, ctx := c }
        { proof := .verified, exec := .succeeded, ctx := c }
  | exec_failed_stay (c : Context) :
      Step
        { proof := .verified, exec := .failed, ctx := c }
        { proof := .verified, exec := .failed, ctx := c }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_concrete_gate {s : State} (hInit : Initial s) :
    ExecutedImpliesConcreteGate s := by
  intro hExecuted
  rcases hInit with ⟨_hProof, hSkipped⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hSkipped
  | inr hFailure =>
      cases hFailure.symm.trans hSkipped

theorem step_preserves_executed_implies_concrete_gate {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesConcreteGate s) :
    ExecutedImpliesConcreteGate t := by
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
  | exec_skipped_to_success _ hVerdict hGovernance hReplay hBindings =>
      exact ⟨rfl, hVerdict, hGovernance, hReplay, hBindings⟩
  | exec_skipped_to_failed _ hVerdict hGovernance hReplay hBindings =>
      exact ⟨rfl, hVerdict, hGovernance, hReplay, hBindings⟩
  | exec_success_stay =>
      exact hInv hExecuted
  | exec_failed_stay =>
      exact hInv hExecuted
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_concrete_gate :
    ∀ {s : State}, Reachable s -> ExecutedImpliesConcreteGate s
  | _, .init hInit =>
      initial_executed_implies_concrete_gate hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_concrete_gate hStep
        (reachable_executed_states_require_concrete_gate hReach)

theorem executed_reachable_states_require_concrete_commitment_bindings
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.proof = .verified ∧
      s.ctx.verdict = .allowed ∧
      s.ctx.governanceOk = true ∧
      s.ctx.replayOk = true ∧
      s.ctx.bindings.journalAllowed = true ∧
      s.ctx.bindings.limitsHashMatches = true ∧
      s.ctx.bindings.decisionCommitmentValid = true ∧
      s.ctx.bindings.policyHashMatches = true ∧
      s.ctx.bindings.policyEpochMatches = true ∧
      s.ctx.bindings.registryRootMatches = true ∧
      s.ctx.bindings.stateSourceMatches = true ∧
      s.ctx.bindings.stateEpochMatches = true ∧
      s.ctx.bindings.stateAttestationMatches = true ∧
      s.ctx.bindings.stateHashMatches = true ∧
      s.ctx.bindings.candidateSetHashMatches = true ∧
      s.ctx.bindings.chosenActionHashMatches = true ∧
      s.ctx.bindings.nonceMatches = true := by
  intro hExecuted
  rcases reachable_executed_states_require_concrete_gate hReach hExecuted with
    ⟨hProof, hVerdict, hGovernance, hReplay, hBindings⟩
  rcases hBindings with
    ⟨hJournalAllowed, hLimitsHash, hDecisionCommitment, hPolicyHash, hPolicyEpoch,
      hRegistryRoot, hStateSource, hStateEpoch, hStateAttestation, hStateHash,
      hCandidateSet, hChosenAction, hNonce⟩
  exact ⟨hProof, hVerdict, hGovernance, hReplay, hJournalAllowed, hLimitsHash,
    hDecisionCommitment, hPolicyHash, hPolicyEpoch, hRegistryRoot, hStateSource,
    hStateEpoch, hStateAttestation, hStateHash, hCandidateSet, hChosenAction, hNonce⟩

end MPRDExecutionCommitmentBindings

abbrev executed_reachable_states_require_concrete_commitment_bindings_v1 :=
  @MPRDExecutionCommitmentBindings.executed_reachable_states_require_concrete_commitment_bindings
