/-
  MPRD_ExecutionBoundary.lean

  A composed execution-boundary model for MPRD. This joins the concrete
  journal/request commitment bindings with the executor preimage/schema gate.
-/

namespace MPRDExecutionBoundary

def proof_bundle_version : String := "mprd-leanproofs-v5"

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

structure ExecutorGate where
  preimagePresent : Bool
  limitsBytesBindingOk : Bool
  actionPreimageHashMatches : Bool
  schemaValid : Bool
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

def ExecutorGateHold (g : ExecutorGate) : Prop :=
  g.preimagePresent = true ∧
    g.limitsBytesBindingOk = true ∧
    g.actionPreimageHashMatches = true ∧
    g.schemaValid = true

structure Context where
  verdict : Verdict
  governanceOk : Bool
  replayOk : Bool
  bindings : BindingVector
  executorGate : ExecutorGate
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

def ExecutedImpliesFullBoundaryGate (s : State) : Prop :=
  Executed s ->
    s.proof = .verified ∧
      s.ctx.verdict = .allowed ∧
      s.ctx.governanceOk = true ∧
      s.ctx.replayOk = true ∧
      ConcreteBindingsHold s.ctx.bindings ∧
      ExecutorGateHold s.ctx.executorGate

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
      (hBindings : ConcreteBindingsHold c.bindings)
      (hExecutorGate : ExecutorGateHold c.executorGate) :
      Step
        { proof := .verified, exec := .skipped, ctx := c }
        { proof := .verified, exec := .succeeded, ctx := c }
  | exec_skipped_to_failed (c : Context)
      (hVerdict : c.verdict = .allowed)
      (hGovernance : c.governanceOk = true)
      (hReplay : c.replayOk = true)
      (hBindings : ConcreteBindingsHold c.bindings)
      (hExecutorGate : ExecutorGateHold c.executorGate) :
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

theorem initial_executed_implies_full_boundary_gate {s : State} (hInit : Initial s) :
    ExecutedImpliesFullBoundaryGate s := by
  intro hExecuted
  rcases hInit with ⟨_hProof, hSkipped⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hSkipped
  | inr hFailure =>
      cases hFailure.symm.trans hSkipped

theorem step_preserves_executed_implies_full_boundary_gate {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesFullBoundaryGate s) :
    ExecutedImpliesFullBoundaryGate t := by
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
  | exec_skipped_to_success _ hVerdict hGovernance hReplay hBindings hExecutorGate =>
      exact ⟨rfl, hVerdict, hGovernance, hReplay, hBindings, hExecutorGate⟩
  | exec_skipped_to_failed _ hVerdict hGovernance hReplay hBindings hExecutorGate =>
      exact ⟨rfl, hVerdict, hGovernance, hReplay, hBindings, hExecutorGate⟩
  | exec_success_stay =>
      exact hInv hExecuted
  | exec_failed_stay =>
      exact hInv hExecuted
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_full_boundary_gate :
    ∀ {s : State}, Reachable s -> ExecutedImpliesFullBoundaryGate s
  | _, .init hInit =>
      initial_executed_implies_full_boundary_gate hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_full_boundary_gate hStep
        (reachable_executed_states_require_full_boundary_gate hReach)

theorem executed_reachable_states_require_full_execution_boundary
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
      s.ctx.bindings.nonceMatches = true ∧
      s.ctx.executorGate.preimagePresent = true ∧
      s.ctx.executorGate.limitsBytesBindingOk = true ∧
      s.ctx.executorGate.actionPreimageHashMatches = true ∧
      s.ctx.executorGate.schemaValid = true := by
  intro hExecuted
  rcases reachable_executed_states_require_full_boundary_gate hReach hExecuted with
    ⟨hProof, hVerdict, hGovernance, hReplay, hBindings, hExecutorGate⟩
  rcases hBindings with
    ⟨hJournalAllowed, hLimitsHash, hDecisionCommitment, hPolicyHash, hPolicyEpoch,
      hRegistryRoot, hStateSource, hStateEpoch, hStateAttestation, hStateHash,
      hCandidateSet, hChosenAction, hNonce⟩
  rcases hExecutorGate with
    ⟨hPreimage, hLimitsBytes, hActionHash, hSchema⟩
  exact ⟨hProof, hVerdict, hGovernance, hReplay, hJournalAllowed, hLimitsHash,
    hDecisionCommitment, hPolicyHash, hPolicyEpoch, hRegistryRoot, hStateSource,
    hStateEpoch, hStateAttestation, hStateHash, hCandidateSet, hChosenAction,
    hNonce, hPreimage, hLimitsBytes, hActionHash, hSchema⟩

end MPRDExecutionBoundary

abbrev executed_reachable_states_require_full_execution_boundary_v1 :=
  @MPRDExecutionBoundary.executed_reachable_states_require_full_execution_boundary
