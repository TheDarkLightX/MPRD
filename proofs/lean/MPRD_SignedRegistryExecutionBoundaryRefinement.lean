/- 
  MPRD_SignedRegistryExecutionBoundaryRefinement.lean

  A lightweight no-witness refinement bridge between:

    * the concrete signed-registry execution-boundary model, and
    * the abstract `MPRD_ExecutionBoundary` theorem.

  This is still narrower than a full runtime-to-formal refinement theorem.
  It closes the intermediate semantic step that the richer signed-registry
  serve models can compose through before reaching the abstract execution
  boundary.
-/

import MPRD_ExecutionBoundary
import MPRD_SignedRegistryExecutionBoundary

namespace MPRDSignedRegistryExecutionBoundaryRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev SignedRegistryState := MPRDSignedRegistryExecutionBoundary.State

structure RefinementWitness where
  bindings : MPRDExecutionBoundary.BindingVector
  executorGate : MPRDExecutionBoundary.ExecutorGate
  deriving Repr, DecidableEq

def RefinementWitnessHolds (w : RefinementWitness) : Prop :=
  MPRDExecutionBoundary.ConcreteBindingsHold w.bindings ∧
    MPRDExecutionBoundary.ExecutorGateHold w.executorGate

def refinementWitnessOfSignedRegistryState (s : SignedRegistryState) : RefinementWitness :=
  { bindings :=
      { journalAllowed := s.bindingOk
        limitsHashMatches := s.bindingOk
        decisionCommitmentValid := s.bindingOk
        policyHashMatches := s.bindingOk
        policyEpochMatches := s.bindingOk
        registryRootMatches := s.bindingOk
        stateSourceMatches := s.bindingOk
        stateEpochMatches := s.bindingOk
        stateAttestationMatches := s.bindingOk
        stateHashMatches := s.bindingOk
        candidateSetHashMatches := s.bindingOk
        chosenActionHashMatches := s.bindingOk
        nonceMatches := s.bindingOk }
    executorGate :=
      { preimagePresent := s.executorOk
        limitsBytesBindingOk := s.executorOk
        actionPreimageHashMatches := s.executorOk
        schemaValid := s.executorOk } }

def refineContext (s : SignedRegistryState) (w : RefinementWitness) :
    MPRDExecutionBoundary.Context :=
  { verdict :=
      if s.allowed = true then
        MPRDExecutionBoundary.Verdict.allowed
      else
        MPRDExecutionBoundary.Verdict.denied
    governanceOk := s.governanceAligned
    replayOk := s.replayOk
    bindings := w.bindings
    executorGate := w.executorGate }

def refineSuccessState (s : SignedRegistryState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .succeeded
    ctx := refineContext s w }

def refineFailedState (s : SignedRegistryState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .failed
    ctx := refineContext s w }

def readyRebuiltSkippedState : SignedRegistryState :=
  { registryResolved := true
    checkpointBound := true
    executionAuthorizationBound := true
    governanceAligned := true
    verified := true
    allowed := true
    replayOk := true
    bindingOk := true
    executorOk := true
    readyRebuilt := true
    exec := .skipped }

def readyRebuiltSuccessState : SignedRegistryState :=
  { readyRebuiltSkippedState with exec := .succeeded }

def readyRebuiltFailureState : SignedRegistryState :=
  { readyRebuiltSkippedState with exec := .failed }

theorem reachable_ready_rebuilt_skipped_state :
    MPRDSignedRegistryExecutionBoundary.Reachable readyRebuiltSkippedState := by
  let s0 : SignedRegistryState :=
    { registryResolved := false
      checkpointBound := false
      executionAuthorizationBound := false
      governanceAligned := false
      verified := false
      allowed := false
      replayOk := false
      bindingOk := false
      executorOk := false
      readyRebuilt := false
      exec := .skipped }
  have h0 : MPRDSignedRegistryExecutionBoundary.Initial s0 := by
    simp [s0, MPRDSignedRegistryExecutionBoundary.Initial]
  have hReach0 : MPRDSignedRegistryExecutionBoundary.Reachable s0 :=
    MPRDSignedRegistryExecutionBoundary.Reachable.init h0
  have hReach1 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { s0 with registryResolved := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach0
      (MPRDSignedRegistryExecutionBoundary.Step.set_registry_resolved s0 rfl rfl)
  have hReach2 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { s0 with registryResolved := true } with checkpointBound := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach1
      (MPRDSignedRegistryExecutionBoundary.Step.bind_checkpoint
        { s0 with registryResolved := true } rfl rfl rfl)
  have hReach3 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { s0 with registryResolved := true } with checkpointBound := true }
            with executionAuthorizationBound := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach2
      (MPRDSignedRegistryExecutionBoundary.Step.bind_execution_authorization
        { { s0 with registryResolved := true } with checkpointBound := true }
        rfl rfl rfl)
  have hReach4 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { s0 with registryResolved := true } with checkpointBound := true }
              with executionAuthorizationBound := true } with governanceAligned := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach3
      (MPRDSignedRegistryExecutionBoundary.Step.align_governance
        { { { s0 with registryResolved := true } with checkpointBound := true }
            with executionAuthorizationBound := true }
        rfl rfl)
  have hReach5 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { { s0 with registryResolved := true } with checkpointBound := true }
                with executionAuthorizationBound := true } with governanceAligned := true }
            with verified := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach4
      (MPRDSignedRegistryExecutionBoundary.Step.set_verified
        { { { { s0 with registryResolved := true } with checkpointBound := true }
              with executionAuthorizationBound := true } with governanceAligned := true }
        rfl rfl)
  have hReach6 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                  with executionAuthorizationBound := true } with governanceAligned := true }
              with verified := true } with allowed := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach5
      (MPRDSignedRegistryExecutionBoundary.Step.set_allowed
        { { { { { s0 with registryResolved := true } with checkpointBound := true }
                with executionAuthorizationBound := true } with governanceAligned := true }
            with verified := true }
        rfl rfl)
  have hReach7 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                    with executionAuthorizationBound := true } with governanceAligned := true }
                with verified := true } with allowed := true } with replayOk := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach6
      (MPRDSignedRegistryExecutionBoundary.Step.set_replay_ok
        { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                  with executionAuthorizationBound := true } with governanceAligned := true }
              with verified := true } with allowed := true }
        rfl rfl)
  have hReach8 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                      with executionAuthorizationBound := true } with governanceAligned := true }
                  with verified := true } with allowed := true } with replayOk := true }
            with bindingOk := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach7
      (MPRDSignedRegistryExecutionBoundary.Step.set_binding_ok
        { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                    with executionAuthorizationBound := true } with governanceAligned := true }
                with verified := true } with allowed := true } with replayOk := true }
        rfl rfl)
  have hReach9 :
      MPRDSignedRegistryExecutionBoundary.Reachable
        { { { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                        with executionAuthorizationBound := true } with governanceAligned := true }
                    with verified := true } with allowed := true } with replayOk := true }
              with bindingOk := true } with executorOk := true } :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach8
      (MPRDSignedRegistryExecutionBoundary.Step.set_executor_ok
        { { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                      with executionAuthorizationBound := true } with governanceAligned := true }
                  with verified := true } with allowed := true } with replayOk := true }
            with bindingOk := true }
        rfl rfl)
  have hReach10 :
      MPRDSignedRegistryExecutionBoundary.Reachable readyRebuiltSkippedState :=
    MPRDSignedRegistryExecutionBoundary.Reachable.step hReach9
      (MPRDSignedRegistryExecutionBoundary.Step.rebuild_ready
        { { { { { { { { { s0 with registryResolved := true } with checkpointBound := true }
                        with executionAuthorizationBound := true } with governanceAligned := true }
                    with verified := true } with allowed := true } with replayOk := true }
              with bindingOk := true } with executorOk := true }
        rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl rfl)
  simpa [readyRebuiltSkippedState] using hReach10

theorem reachable_ready_rebuilt_success_state :
    MPRDSignedRegistryExecutionBoundary.Reachable readyRebuiltSuccessState := by
  exact MPRDSignedRegistryExecutionBoundary.Reachable.step
    reachable_ready_rebuilt_skipped_state
    (MPRDSignedRegistryExecutionBoundary.Step.execute_success
      readyRebuiltSkippedState rfl rfl)

theorem reachable_ready_rebuilt_failure_state :
    MPRDSignedRegistryExecutionBoundary.Reachable readyRebuiltFailureState := by
  exact MPRDSignedRegistryExecutionBoundary.Reachable.step
    reachable_ready_rebuilt_skipped_state
    (MPRDSignedRegistryExecutionBoundary.Step.execute_failed
      readyRebuiltSkippedState rfl rfl)

theorem refinementWitnessOfSignedRegistryState_holds_for_executed_states
    {s : SignedRegistryState}
    (hReach : MPRDSignedRegistryExecutionBoundary.Reachable s)
    (hExec : MPRDSignedRegistryExecutionBoundary.Executed s) :
    RefinementWitnessHolds (refinementWitnessOfSignedRegistryState s) := by
  rcases
      MPRDSignedRegistryExecutionBoundary.executed_reachable_states_require_signed_registry_execution_boundary
        hReach hExec with
    ⟨_hReady, _hResolved, _hCheckpoint, _hAuth, _hGovernance, _hVerified,
      _hAllowed, _hReplay, hBinding, hExecutor⟩
  constructor
  · simp [MPRDExecutionBoundary.ConcreteBindingsHold,
      refinementWitnessOfSignedRegistryState, hBinding]
  · simp [MPRDExecutionBoundary.ExecutorGateHold,
      refinementWitnessOfSignedRegistryState, hExecutor]

theorem executed_signed_registry_execution_states_refine_to_execution_boundary
    {s : SignedRegistryState}
    (hReach : MPRDSignedRegistryExecutionBoundary.Reachable s)
    (hExec : MPRDSignedRegistryExecutionBoundary.Executed s) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = (refinementWitnessOfSignedRegistryState s).bindings ∧
        t.ctx.executorGate = (refinementWitnessOfSignedRegistryState s).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  rcases
      MPRDSignedRegistryExecutionBoundary.executed_reachable_states_require_signed_registry_execution_boundary
        hReach hExec with
    ⟨_hReady, _hResolved, _hCheckpoint, _hAuth, hGovernance, _hVerified,
      hAllowed, hReplay, _hBinding, _hExecutor⟩
  let w := refinementWitnessOfSignedRegistryState s
  have hWitness : RefinementWitnessHolds w := by
    simpa [w] using refinementWitnessOfSignedRegistryState_holds_for_executed_states hReach hExec
  rcases hWitness with ⟨hBindings, hExecutorGate⟩
  let c := refineContext s w
  have hVerdict : c.verdict = MPRDExecutionBoundary.Verdict.allowed := by
    simp [c, refineContext, hAllowed]
  have hGovernanceOk : c.governanceOk = true := by
    simpa [c, refineContext] using hGovernance
  have hReplayOk : c.replayOk = true := by
    simpa [c, refineContext] using hReplay
  have hPendingInit :
      MPRDExecutionBoundary.Initial
        { proof := .pending, exec := .skipped, ctx := c } := by
    exact ⟨rfl, rfl⟩
  have hPendingReach :
      MPRDExecutionBoundary.Reachable
        { proof := .pending, exec := .skipped, ctx := c } :=
    MPRDExecutionBoundary.Reachable.init hPendingInit
  have hVerifiedReach :
      MPRDExecutionBoundary.Reachable
        { proof := .verified, exec := .skipped, ctx := c } :=
    MPRDExecutionBoundary.Reachable.step hPendingReach
      (MPRDExecutionBoundary.Step.proof_pending_verify c)
  cases hExec with
  | inl hSuccess =>
      let t := refineSuccessState s w
      have hReachT : MPRDExecutionBoundary.Reachable t := by
        exact MPRDExecutionBoundary.Reachable.step hVerifiedReach
          (MPRDExecutionBoundary.Step.exec_skipped_to_success c hVerdict hGovernanceOk
            hReplayOk hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inl rfl
      have hBoundary :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundary⟩
  | inr hFailure =>
      let t := refineFailedState s w
      have hReachT : MPRDExecutionBoundary.Reachable t := by
        exact MPRDExecutionBoundary.Reachable.step hVerifiedReach
          (MPRDExecutionBoundary.Step.exec_skipped_to_failed c hVerdict hGovernanceOk
            hReplayOk hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inr rfl
      have hBoundary :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundary⟩

end MPRDSignedRegistryExecutionBoundaryRefinement

abbrev executed_signed_registry_execution_states_refine_to_execution_boundary_v1 :=
  @MPRDSignedRegistryExecutionBoundaryRefinement.executed_signed_registry_execution_states_refine_to_execution_boundary
