/- 
  MPRD_SignedRegistryServeAttestationHashArtifactBoundary.lean

  A lightweight top-level boundary theorem for the richer signed-registry
  `mprd serve` path after both:

    * the attestation-hash tightening, and
    * the grouped `ExecutionReadyPacketV1` admission boundary.

  This closes one more explicit seam on the shipped proof path: executed states
  on this richer serve model require a grouped signed-registry execution
  artifact before the exact signed-registry packet lane can be used.
-/

import MPRD_SignedRegistryExecutionArtifactRuntimeRefinement
import MPRD_SignedRegistryServeAttestationHashReadyPacketBoundary
import MPRD_SignedRegistryServeEndToEndRefinement

namespace MPRDSignedRegistryServeAttestationHashArtifactBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.State
abbrev Artifact :=
  MPRDSignedRegistryExecutionArtifactRuntimeRefinement.SignedRegistryExecutionArtifact
abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev ExecutionReadyPacket :=
  MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ExecutionReadyPacket

def mapServeExec :
    MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus ->
      MPRDExecutionReadyPacketBoundary.ExecStatus
  | .skipped => .skipped
  | .succeeded => .succeeded
  | .failed => .failed

def packetViewOfServeState (s : ServeState) : PacketState :=
  { boundaryAdmitted := s.boundaryAdmitted
    authorizationAdmitted := s.executionAuthorizationBound
    bridgeAdmitted := s.checkpointBound
    signatureAdmitted := s.signatureAdmitted
    stateProvenanceAdmitted := s.stateProvenanceAdmitted
    replayAdmitted := s.replayAdmitted
    packetGrouped := s.packetGrouped
    readyVisible := s.readyVisible
    exec := mapServeExec s.exec }

def executionReadyOfServeState
    (s : ServeState) :
    ExecutionReadyPacket :=
  { boundary :=
      { chosenActionPreimagePresent := s.boundaryAdmitted
        limitsBindingPresent := s.boundaryAdmitted }
    authorization :=
      some
        { policyAuthorityPresent := s.executionAuthorizationBound
          stateBindingPresent := s.executionAuthorizationBound
          governancePresent := s.governanceAligned }
    bridge :=
      some
        { registryAuthorizationPresent := s.bridgeWitnessPreserved
          checkpointAttestationPresent := s.checkpointAttestationHashBound }
    executorAdmission :=
      some
        { signaturePresent := s.signatureAdmitted
          stateProvenancePresent := s.stateProvenanceAdmitted
          replayClearancePresent := s.replayAdmitted } }

def artifactOfServeState (s : ServeState) : Artifact :=
  { executionReady := executionReadyOfServeState s
    executionBindingVector :=
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
      if s.packetGrouped = true ∧ s.executionAuthorizationHashBound = true then
        some
          { executionReadyPacketHash := 1
            attestationMetadataHash := 1 }
      else
        none
    signedRegistryExecutionMetadata :=
      if s.executionAuthorizationHashBound = true ∧
          s.registryAuthorizationHashBound = true then
        some
          { executionAuthorization := { executionAuthorizationHash := 1 }
            signedRegistryBridge :=
              { resolutionHash := 1
                registryCheckpointAttestationHash :=
                    if s.checkpointAttestationHashBound = true then some 1 else none } }
      else
        none }

theorem executed_reachable_states_require_signed_registry_serve_attestation_hash_artifact_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Executed s) :
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ArtifactHolds
      (artifactOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_ready_packet_boundary
        hReach hExec with
    ⟨hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, _hCheckpointHash, hAuth, hAuthHash,
      hRegistryAuthHash, hGovernance, hBridgeWitness, _hVerified, _hAllowed,
      hBinding, _hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  constructor
  · constructor
    · simpa [artifactOfServeState, executionReadyOfServeState] using hBoundary
    · simpa [artifactOfServeState, executionReadyOfServeState] using hBoundary
  constructor
  · refine ⟨?_, ?_, ?_⟩
    · exact
        { policyAuthorityPresent := s.executionAuthorizationBound
          stateBindingPresent := s.executionAuthorizationBound
          governancePresent := s.governanceAligned }
    · simp [artifactOfServeState, executionReadyOfServeState]
    · constructor
      · simpa [artifactOfServeState, executionReadyOfServeState] using hAuth
      · constructor
        · simpa [artifactOfServeState, executionReadyOfServeState] using hAuth
        · simpa [artifactOfServeState, executionReadyOfServeState] using hGovernance
  constructor
  · refine ⟨?_, ?_, ?_⟩
    · exact
        { registryAuthorizationPresent := s.bridgeWitnessPreserved
          checkpointAttestationPresent := s.checkpointAttestationHashBound }
    · simp [artifactOfServeState, executionReadyOfServeState]
    · simpa [MPRDSignedRegistryExecutionExactPacketWitnessCompiler.bridgeWitnessHolds,
        artifactOfServeState, executionReadyOfServeState] using hBridgeWitness
  constructor
  · refine ⟨?_, ?_, ?_⟩
    · exact
        { signaturePresent := s.signatureAdmitted
          stateProvenancePresent := s.stateProvenanceAdmitted
          replayClearancePresent := s.replayAdmitted }
    · simp [artifactOfServeState, executionReadyOfServeState]
    · constructor
      · simpa [artifactOfServeState, executionReadyOfServeState] using hSignature
      · constructor
        · simpa [artifactOfServeState, executionReadyOfServeState] using hStateProv
        · simpa [artifactOfServeState, executionReadyOfServeState] using hReplay
  constructor
  · simp [artifactOfServeState, hBinding]
  constructor
  · simp [artifactOfServeState, hPacket, hAuthHash]
  · simp [artifactOfServeState, hAuthHash, hRegistryAuthHash]

theorem executed_reachable_states_require_signed_registry_serve_attestation_hash_packet_view
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) := by
  rcases
      MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_ready_packet_boundary
        hReach hExec with
    ⟨hPacket, hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, hCheckpoint, _hCheckpointHash, hAuth, _hAuthHash,
      _hRegistryAuthHash, _hGovernance, _hBridgeWitness, _hVerified, _hAllowed,
      _hBinding, _hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  cases hExec with
  | inl hSuccess =>
      have hPacketEq :
          packetViewOfServeState s =
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess := by
        simp [packetViewOfServeState, mapServeExec,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketReadySkipped,
          hBoundary, hAuth, hCheckpoint, hSignature, hStateProv, hReplay,
          hPacket, hReady, hSuccess]
      refine ⟨?_, ?_⟩
      · simpa [hPacketEq] using
          MPRDSignedRegistryServeEndToEndRefinement.reachable_grouped_packet_success
      · simpa [hPacketEq] using
          (Or.inl rfl : MPRDExecutionReadyPacketBoundary.Executed
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketSuccess)
  | inr hFailure =>
      have hPacketEq :
          packetViewOfServeState s =
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure := by
        simp [packetViewOfServeState, mapServeExec,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure,
          MPRDSignedRegistryServeEndToEndRefinement.groupedPacketReadySkipped,
          hBoundary, hAuth, hCheckpoint, hSignature, hStateProv, hReplay,
          hPacket, hReady, hFailure]
      refine ⟨?_, ?_⟩
      · simpa [hPacketEq] using
          MPRDSignedRegistryServeEndToEndRefinement.reachable_grouped_packet_failure
      · simpa [hPacketEq] using
          (Or.inr rfl : MPRDExecutionReadyPacketBoundary.Executed
            MPRDSignedRegistryServeEndToEndRefinement.groupedPacketFailure)

end MPRDSignedRegistryServeAttestationHashArtifactBoundary

abbrev executed_reachable_states_require_signed_registry_serve_attestation_hash_artifact_boundary_v1 :=
  @MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_artifact_boundary

abbrev executed_reachable_states_require_signed_registry_serve_attestation_hash_packet_view_v1 :=
  @MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_packet_view
