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

import MPRD_ExecutionReadyArtifactRuntimeRefinement
import MPRD_SignedRegistryServeAttestationHashBoundary
import MPRD_SignedRegistryServeEndToEndRefinement

namespace MPRDSignedRegistryServeAttestationHashRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashBoundary.State
abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev ExecutionReadyArtifact :=
  MPRDExecutionReadyArtifactRuntimeRefinement.ExecutionReadyArtifact

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

def runtimeRefinementWitnessOfServeState (s : ServeState) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness :=
  { governanceAdmitted := s.governanceAligned
    signatureAdmitted := s.readyRebuilt
    stateProvenanceAdmitted := s.readyRebuilt
    replayAdmitted := s.replayOk
    bindings :=
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

def mapServeExec :
    MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus ->
      MPRDExecutionReadyPacketBoundary.ExecStatus
  | .skipped => .skipped
  | .succeeded => .succeeded
  | .failed => .failed

def packetViewOfServeState (s : ServeState) : PacketState :=
  { boundaryAdmitted := s.readyRebuilt
    authorizationAdmitted := s.executionAuthorizationBound
    bridgeAdmitted := s.checkpointBound
    signatureAdmitted := s.readyRebuilt
    stateProvenanceAdmitted := s.readyRebuilt
    replayAdmitted := s.replayOk
    packetGrouped := s.readyRebuilt
    readyVisible := s.readyRebuilt
    exec := mapServeExec s.exec }

def executionReadyArtifactOfServeState (s : ServeState) : ExecutionReadyArtifact :=
  { executionBindingVector :=
      if s.bindingOk = true then
        some
          { decisionCommitment := 1
            policyHash := 1
            policyRef := { policyEpoch := 1, registryRoot := 1 }
            stateRef :=
              { stateSourceId := 1
                stateEpoch := 1
                stateAttestationHash := 1 }
            stateHash := 1
            candidateSetHash := 1
            chosenActionHash := 1
            nonceOrTxHash := 1
            limitsHash := 1 }
      else
        none
    executionBoundaryRefinement :=
      if s.readyRebuilt = true ∧ s.executionAuthorizationHashBound = true then
        some
          { executionReadyPacketHash := 1
            attestationMetadataHash := 1 }
      else
        none
    executionAuthorizationMetadata :=
      if s.executionAuthorizationBound = true ∧ s.governanceAligned = true then
        some
          { executionAuthorization :=
              { policyHash := 1
                policyRef := { policyEpoch := 1, registryRoot := 1 }
                stateHash := 1
                stateRef :=
                  { stateSourceId := 1
                    stateEpoch := 1
                    stateAttestationHash := 1 }
                governance :=
                  some
                    { updateKind := .policyTweak
                      profileAppOk := true
                      profileSafetyOk := true
                      linkOk := true } }
            executionAuthorizationHash := 1 }
      else
        none }

theorem executed_signed_registry_serve_attestation_hash_states_reach_execution_ready_packet
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      hResolved, hCheckpoint, _hCheckpointHash, hAuth, _hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, hVerified, hAllowed,
      hReplay, hBinding, hExecutor⟩
  cases hExec with
  | inl hSuccess =>
      have hPacketEq :
          packetViewOfServeState s =
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess := by
        simp [packetViewOfServeState, mapServeExec,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketReadySkipped,
          hReady, hCheckpoint, hAuth, hReplay, hSuccess]
      exact ⟨by simpa [hPacketEq] using
          MPRDSignedRegistryServeEndToEndRefinement.reachable_grouped_packet_success,
        by simpa [hPacketEq] using
          (Or.inl rfl : MPRDExecutionReadyPacketBoundary.Executed
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess)⟩
  | inr hFailure =>
      have hPacketEq :
          packetViewOfServeState s =
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure := by
        simp [packetViewOfServeState, mapServeExec,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketReadySkipped,
          hReady, hCheckpoint, hAuth, hReplay, hFailure]
      exact ⟨by simpa [hPacketEq] using
          MPRDSignedRegistryServeEndToEndRefinement.reachable_grouped_packet_failure,
        by simpa [hPacketEq] using
          (Or.inr rfl : MPRDExecutionReadyPacketBoundary.Executed
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure)⟩

theorem executionReadyArtifactOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDExecutionReadyArtifactRuntimeRefinement.ArtifactHolds
      (executionReadyArtifactOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      _hResolved, _hCheckpoint, _hCheckpointHash, hAuth, hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, _hVerified, _hAllowed,
      _hReplay, hBinding, _hExecutor⟩
  refine ⟨?_, ?_, ?_⟩
  · simp [executionReadyArtifactOfServeState, hBinding]
  · simp [executionReadyArtifactOfServeState, hReady, hAuthHash]
  · refine ⟨?_, ?_, ?_⟩
    · exact
        { executionAuthorization :=
            { policyHash := 1
              policyRef := { policyEpoch := 1, registryRoot := 1 }
              stateHash := 1
              stateRef :=
                { stateSourceId := 1
                  stateEpoch := 1
                  stateAttestationHash := 1 }
              governance :=
                some
                  { updateKind := .policyTweak
                    profileAppOk := true
                    profileSafetyOk := true
                    linkOk := true } }
          executionAuthorizationHash := 1 }
    · simp [executionReadyArtifactOfServeState, hAuth, hGovernance]
    · simp

theorem executionReadyArtifactOfServeState_compiles_runtime_witness_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
        (packetViewOfServeState s) (executionReadyArtifactOfServeState s) =
      runtimeRefinementWitnessOfServeState s := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      hResolved, hCheckpoint, _hCheckpointHash, hAuth, hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, hVerified, hAllowed,
      hReplay, hBinding, hExecutor⟩
  simp [MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness,
    MPRDExecutionReadyArtifactRuntimeRefinement.compileBindings,
    MPRDExecutionReadyArtifactRuntimeRefinement.compileExecutorGate,
    MPRDExecutionReadyArtifactRuntimeRefinement.canonicalBindings,
    MPRDExecutionReadyArtifactRuntimeRefinement.canonicalExecutorGate,
    executionReadyArtifactOfServeState, packetViewOfServeState,
    runtimeRefinementWitnessOfServeState, hReady, hCheckpoint, hAuth,
    hAuthHash, hGovernance, hReplay, hBinding, hExecutor]

theorem executed_signed_registry_serve_attestation_hash_states_refine_via_runtime_witness
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings = (runtimeRefinementWitnessOfServeState s).bindings ∧
            t.ctx.executorGate = (runtimeRefinementWitnessOfServeState s).executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  let a := executionReadyArtifactOfServeState s
  have hArtifact :
      MPRDExecutionReadyArtifactRuntimeRefinement.ArtifactHolds a := by
    simpa [a] using executionReadyArtifactOfServeState_holds_for_executed_states hReach hExec
  rcases
      executed_signed_registry_serve_attestation_hash_states_reach_execution_ready_packet
        hReach hExec with
    ⟨hPacketReach, hPacketExec⟩
  rcases
      MPRDExecutionReadyArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
        hPacketReach hPacketExec hArtifact with
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
  have hCompileEq :
      MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
          (packetViewOfServeState s) a =
        runtimeRefinementWitnessOfServeState s := by
    simpa [a] using
      executionReadyArtifactOfServeState_compiles_runtime_witness_for_executed_states hReach hExec
  have hBindings' :
      t.ctx.bindings = (runtimeRefinementWitnessOfServeState s).bindings := by
    simpa [hCompileEq] using hBindings
  have hExecutorGate' :
      t.ctx.executorGate = (runtimeRefinementWitnessOfServeState s).executorGate := by
    simpa [hCompileEq] using hExecutorGate
  exact ⟨hPacketReach, hPacketExec,
    ⟨t, hBindings', hExecutorGate', hAbsReach, hAbsExec, hAbsBoundary⟩⟩

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
  have hRuntime :=
    executed_signed_registry_serve_attestation_hash_states_refine_via_runtime_witness
      hReach hExec
  rcases hRuntime with ⟨_hPacketReach, _hPacketExec, hAbstract⟩
  simpa [runtimeRefinementWitnessOfServeState, refinementWitnessOfServeState] using hAbstract

end MPRDSignedRegistryServeAttestationHashRefinement

abbrev executed_signed_registry_serve_attestation_hash_states_reach_execution_ready_packet_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_reach_execution_ready_packet

abbrev executed_signed_registry_serve_attestation_hash_states_refine_via_runtime_witness_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_refine_via_runtime_witness

abbrev executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary_v1 :=
  @MPRDSignedRegistryServeAttestationHashRefinement.executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
