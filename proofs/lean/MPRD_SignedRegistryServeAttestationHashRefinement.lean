/- 
  MPRD_SignedRegistryServeAttestationHashRefinement.lean

  A lightweight top-level refinement bridge for the richer signed-registry
  `mprd serve` attestation-hash path:

    executed states on the shipped serve model that already requires exact
    checkpoint-attestation, execution-authorization-hash, and
    registry-authorization-hash binding refine directly into a reachable
    abstract `MPRD_ExecutionBoundary` state.

  This still does not close the full runtime-to-formal refinement theorem.
  It narrows the remaining gap by removing the extra witness premise from the
  richer top-level serve model rather than only from the older grouped
  ready-packet model.
-/

import MPRD_ExecutionBoundary
import MPRD_SignedRegistryExecutionBoundary
import MPRD_SignedRegistryExecutionBoundaryRefinement
import MPRD_SignedRegistryServeAttestationHashBoundary

namespace MPRDSignedRegistryServeAttestationHashRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashBoundary.State

structure RefinementWitness where
  bindings : MPRDExecutionBoundary.BindingVector
  executorGate : MPRDExecutionBoundary.ExecutorGate
  deriving Repr, DecidableEq

def RefinementWitnessHolds (w : RefinementWitness) : Prop :=
  MPRDExecutionBoundary.ConcreteBindingsHold w.bindings ∧
    MPRDExecutionBoundary.ExecutorGateHold w.executorGate

def refinementWitnessOfServeState (s : ServeState) : RefinementWitness :=
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

def refineContext (s : ServeState) (w : RefinementWitness) :
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

def refineSuccessState (s : ServeState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .succeeded
    ctx := refineContext s w }

def refineFailedState (s : ServeState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .failed
    ctx := refineContext s w }

theorem refinementWitnessOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    RefinementWitnessHolds (refinementWitnessOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨_hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      _hResolved, _hCheckpoint, _hCheckpointHash, _hAuth, _hAuthHash,
      _hRegistryAuthHash, _hGovernance, _hBridgeWitness, _hVerified, _hAllowed,
      _hReplay, hBinding, hExecutor⟩
  constructor
  · simp [MPRDExecutionBoundary.ConcreteBindingsHold, refinementWitnessOfServeState, hBinding]
  · simp [MPRDExecutionBoundary.ExecutorGateHold, refinementWitnessOfServeState, hExecutor]

def mapExecutionStatus :
    MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus ->
      MPRDSignedRegistryExecutionBoundary.ExecStatus
  | .skipped => .skipped
  | .succeeded => .succeeded
  | .failed => .failed

def executionBoundaryViewOfServeState (s : ServeState) :
    MPRDSignedRegistryExecutionBoundary.State :=
  { registryResolved := s.registryResolved
    checkpointBound := s.checkpointBound
    executionAuthorizationBound := s.executionAuthorizationBound
    governanceAligned := s.governanceAligned
    verified := s.verified
    allowed := s.allowed
    replayOk := s.replayOk
    bindingOk := s.bindingOk
    executorOk := s.executorOk
    readyRebuilt := s.readyRebuilt
    exec := mapExecutionStatus s.exec }

theorem executed_signed_registry_serve_attestation_hash_states_refine_via_signed_registry_execution_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDSignedRegistryExecutionBoundary.Reachable (executionBoundaryViewOfServeState s) ∧
      MPRDSignedRegistryExecutionBoundary.Executed (executionBoundaryViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings =
              (MPRDSignedRegistryExecutionBoundaryRefinement.refinementWitnessOfSignedRegistryState
                (executionBoundaryViewOfServeState s)).bindings ∧
            t.ctx.executorGate =
              (MPRDSignedRegistryExecutionBoundaryRefinement.refinementWitnessOfSignedRegistryState
                (executionBoundaryViewOfServeState s)).executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      hResolved, hCheckpoint, _hCheckpointHash, hAuth, _hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, hVerified, hAllowed,
      hReplay, hBinding, hExecutor⟩
  cases hExec with
  | inl hSuccess =>
      have hExecStateEq :
          executionBoundaryViewOfServeState s =
            MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltSuccessState := by
        simp [executionBoundaryViewOfServeState, mapExecutionStatus,
          MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltSuccessState,
          MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltSkippedState,
          hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
          hReplay, hBinding, hExecutor, hReady, hSuccess]
      have hExecStateReach :
          MPRDSignedRegistryExecutionBoundary.Reachable
            (executionBoundaryViewOfServeState s) := by
        simpa [hExecStateEq] using
          MPRDSignedRegistryExecutionBoundaryRefinement.reachable_ready_rebuilt_success_state
      have hExecStateExec :
          MPRDSignedRegistryExecutionBoundary.Executed
            (executionBoundaryViewOfServeState s) := by
        simpa [hExecStateEq] using
          (Or.inl rfl :
            MPRDSignedRegistryExecutionBoundary.Executed
              MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltSuccessState)
      rcases
          MPRDSignedRegistryExecutionBoundaryRefinement.executed_signed_registry_execution_states_refine_to_execution_boundary
            hExecStateReach hExecStateExec with
        ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
      exact ⟨hExecStateReach, hExecStateExec,
        ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩⟩
  | inr hFailure =>
      have hExecStateEq :
          executionBoundaryViewOfServeState s =
            MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltFailureState := by
        simp [executionBoundaryViewOfServeState, mapExecutionStatus,
          MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltFailureState,
          MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltSkippedState,
          hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
          hReplay, hBinding, hExecutor, hReady, hFailure]
      have hExecStateReach :
          MPRDSignedRegistryExecutionBoundary.Reachable
            (executionBoundaryViewOfServeState s) := by
        simpa [hExecStateEq] using
          MPRDSignedRegistryExecutionBoundaryRefinement.reachable_ready_rebuilt_failure_state
      have hExecStateExec :
          MPRDSignedRegistryExecutionBoundary.Executed
            (executionBoundaryViewOfServeState s) := by
        simpa [hExecStateEq] using
          (Or.inr rfl :
            MPRDSignedRegistryExecutionBoundary.Executed
              MPRDSignedRegistryExecutionBoundaryRefinement.readyRebuiltFailureState)
      rcases
          MPRDSignedRegistryExecutionBoundaryRefinement.executed_signed_registry_execution_states_refine_to_execution_boundary
            hExecStateReach hExecStateExec with
        ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
      exact ⟨hExecStateReach, hExecStateExec,
        ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩⟩

theorem executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = (refinementWitnessOfServeState s).bindings ∧
        t.ctx.executorGate = (refinementWitnessOfServeState s).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  rcases
      executed_signed_registry_serve_attestation_hash_states_refine_via_signed_registry_execution_boundary
        hReach hExec with
    ⟨_hExecStateReach, _hExecStateExec, hAbstract⟩
  simpa [executionBoundaryViewOfServeState,
    MPRDSignedRegistryExecutionBoundaryRefinement.refinementWitnessOfSignedRegistryState,
    refinementWitnessOfServeState] using hAbstract

end MPRDSignedRegistryServeAttestationHashRefinement

abbrev executed_signed_registry_serve_attestation_hash_states_refine_via_signed_registry_execution_boundary_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_refine_via_signed_registry_execution_boundary

abbrev executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
