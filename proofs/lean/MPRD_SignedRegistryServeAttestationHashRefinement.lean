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
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨_hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      _hResolved, _hCheckpoint, _hCheckpointHash, _hAuth, _hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, _hVerified, hAllowed,
      hReplay, _hBinding, _hExecutor⟩
  let w := refinementWitnessOfServeState s
  have hWitness : RefinementWitnessHolds w := by
    simpa [w] using refinementWitnessOfServeState_holds_for_executed_states hReach hExec
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

end MPRDSignedRegistryServeAttestationHashRefinement

abbrev executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
