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
import MPRD_RegistryGovernanceExecutionAuthorizationArtifactCompiler
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

def concreteAuthorizationPacketOfServeState (s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.ConcretePacket :=
  { executionAuthorization :=
      { policyAuthority :=
          { policyHash := 1
            policyRef := { policyEpoch := 1, registryRoot := 1 } }
        stateBinding :=
          { stateHash := 1
            stateRef :=
              { stateSourceId := 1
                stateEpoch := 1
                stateAttestationHash := 1 } }
        governance :=
          if s.governanceAligned = true then
            some
              { updateKind := .policyTweak
                profileAppOk := true
                profileSafetyOk := true
                linkOk := true }
          else
            none }
    signedRegistryExecutionMetadata :=
      { executionAuthorization :=
          { executionAuthorization :=
              { policyHash := 1
                policyRef := { policyEpoch := 1, registryRoot := 1 }
                stateHash := 1
                stateRef :=
                  { stateSourceId := 1
                    stateEpoch := 1
                    stateAttestationHash := 1 }
                governance :=
                  if s.governanceAligned = true then
                    some
                      { updateKind := .policyTweak
                        profileAppOk := true
                        profileSafetyOk := true
                        linkOk := true }
                  else
                    none }
            executionAuthorizationHash := 1 }
        signedRegistryBridge :=
          { resolutionHash := 1
            execKindId := 1
            execVersionId := 1
            imageId := 1
            policySourceKindId := some 1
            policySourceHash := some 1
            registryCheckpointAttestationHash :=
              if s.checkpointAttestationHashBound = true then some 1 else none } } }

def concreteBoundaryWitnessOfServeState (s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.ExecutionBoundaryWitness :=
  { chosenActionPreimagePresent := s.executorOk
    limitsBindingPresent := s.executorOk }

def concreteExecutorAdmissionWitnessOfServeState (s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.ExecutionExecutorAdmissionWitness :=
  { signaturePresent := s.readyRebuilt
    stateProvenancePresent := s.readyRebuilt
    replayClearancePresent := s.replayOk }

def concreteBindingVectorPacketOfServeState (_s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.ExecutionBindingVectorPacket :=
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

def concreteBoundaryRefinementPacketOfServeState (_s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.ExecutionBoundaryRefinementPacket :=
  { executionReadyPacketHash := 1
    attestationMetadataHash := 1 }

def concreteAuthorizationArtifactOfServeState (s : ServeState) :
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.SignedRegistryExecutionArtifact :=
  MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.signedRegistryExecutionArtifactOfConcretePacket
    (concreteAuthorizationPacketOfServeState s)
    (concreteBoundaryWitnessOfServeState s)
    (concreteExecutorAdmissionWitnessOfServeState s)
    (concreteBindingVectorPacketOfServeState s)
    (concreteBoundaryRefinementPacketOfServeState s)

abbrev executionReadyArtifactOfServeState (s : ServeState) : ExecutionReadyArtifact :=
  MPRDSignedRegistryExecutionArtifactRuntimeRefinement.genericArtifactWitnessOfSignedRegistryArtifact
    (concreteAuthorizationArtifactOfServeState s)

theorem concreteAuthorizationArtifactOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ArtifactHolds
      (concreteAuthorizationArtifactOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      _hResolved, _hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, _hVerified, _hAllowed,
      hReplay, hBinding, hExecutor⟩
  apply
    MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.signed_registry_execution_artifact_of_concrete_packet_holds
  · simp [concreteBoundaryWitnessOfServeState,
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.boundaryWitnessHolds, hExecutor]
  · simp [concreteAuthorizationPacketOfServeState, hGovernance]
  · simp [concreteExecutorAdmissionWitnessOfServeState,
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executorAdmissionWitnessHolds,
      hReady, hReplay]

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
  exact
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.generic_artifact_witness_holds
      (concreteAuthorizationArtifactOfServeState_holds_for_executed_states hReach hExec)

theorem executionReadyArtifactOfServeState_compiles_runtime_witness_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashBoundary.Executed s) :
    MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
        (packetViewOfServeState s) (executionReadyArtifactOfServeState s) =
      runtimeRefinementWitnessOfServeState s := by
  rcases
      executed_signed_registry_serve_attestation_hash_states_reach_execution_ready_packet
        hReach hExec with
    ⟨hPacketReach, hPacketExec⟩
  have hConcrete :
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ArtifactHolds
        (concreteAuthorizationArtifactOfServeState s) := by
    exact concreteAuthorizationArtifactOfServeState_holds_for_executed_states hReach hExec
  have hCompileEq :
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness
          (concreteAuthorizationArtifactOfServeState s) =
        MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
          (packetViewOfServeState s) (executionReadyArtifactOfServeState s) := by
    simpa [executionReadyArtifactOfServeState] using
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compile_runtime_witness_matches_generic_artifact_witness_compiler
        hPacketReach hPacketExec hConcrete
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReach hExec with
    ⟨hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      hResolved, hCheckpoint, _hCheckpointHash, hAuth, hAuthHash,
      _hRegistryAuthHash, hGovernance, _hBridgeWitness, hVerified, hAllowed,
      hReplay, hBinding, hExecutor⟩
  have hSignedCompile :
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness
        (concreteAuthorizationArtifactOfServeState s) =
      runtimeRefinementWitnessOfServeState s := by
    simp [MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness,
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileBindings,
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileExecutorGate,
      concreteAuthorizationArtifactOfServeState,
      MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.exactAuthorizationWitnessOfConcretePacket,
      MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.signedRegistryExecutionArtifactOfConcretePacket,
      concreteAuthorizationPacketOfServeState, concreteBoundaryWitnessOfServeState,
      concreteExecutorAdmissionWitnessOfServeState, concreteBindingVectorPacketOfServeState,
      concreteBoundaryRefinementPacketOfServeState,
      runtimeRefinementWitnessOfServeState, hReady, hGovernance, hReplay,
      hBinding, hExecutor]
  exact hCompileEq.symm.trans hSignedCompile

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
