/- 
  MPRD_RegistryGovernanceExecutionAuthorizationArtifactCompiler.lean

  A lightweight local compiler theorem from the grouped concrete ready-bridge
  authorization packet into the grouped signed-registry execution artifact
  witness lane.

  This is intentionally narrower than a top-level runtime refinement theorem.
  It closes one more local seam: once the live ready bridge has materialized
  the concrete registry/governance authorization packet, the next proof step
  can consume one canonical signed-registry execution artifact and, from that,
  one canonical generic execute-ready artifact witness instead of rebuilding
  authorization metadata and exact witness bits by hand.
-/

import MPRD_RegistryGovernanceExecutionAuthorizationPacketCompiler
import MPRD_SignedRegistryExecutionArtifactRuntimeRefinement

namespace MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ConcretePacket :=
  MPRDRegistryGovernanceExecutionAuthorizationPacketCompiler.RegistryGovernanceExecutionAuthorizationPacket

abbrev ExecutionBoundaryWitness :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.ExecutionBoundaryWitness

abbrev ExecutionAuthorizationWitness :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.ExecutionAuthorizationWitness

abbrev ExecutionRegistryBridgeWitness :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.ExecutionRegistryBridgeWitness

abbrev ExecutionExecutorAdmissionWitness :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.ExecutionExecutorAdmissionWitness

abbrev ExactPacket :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.SignedRegistryExecutionExactPacket

abbrev SignedRegistryExecutionArtifact :=
  MPRDSignedRegistryExecutionArtifactRuntimeRefinement.SignedRegistryExecutionArtifact

abbrev ExecutionBindingVectorPacket :=
  MPRDExecutionBindingVectorPacketBoundary.ExecutionBindingVectorPacket

abbrev ExecutionBoundaryRefinementPacket :=
  MPRDExecutionBoundaryRefinementPacketBoundary.ExecutionBoundaryRefinementPacket

abbrev SignedRegistryExecutionMetadataPacket :=
  MPRDSignedRegistryExecutionMetadataPacketBoundary.SignedRegistryExecutionMetadataPacket

def exactAuthorizationWitnessOfConcretePacket
    (packet : ConcretePacket) : ExecutionAuthorizationWitness :=
  { policyAuthorityPresent := true
    stateBindingPresent := true
    governancePresent := packet.executionAuthorization.governance.isSome }

def exactBridgeWitnessOfConcretePacket
    (packet : ConcretePacket) : ExecutionRegistryBridgeWitness :=
  { registryAuthorizationPresent := true
    checkpointAttestationPresent :=
      packet.signedRegistryExecutionMetadata.signedRegistryBridge.registryCheckpointAttestationHash.isSome }

def signedRegistryExecutionMetadataOfConcretePacket
    (packet : ConcretePacket) : SignedRegistryExecutionMetadataPacket :=
  { executionAuthorization :=
      { executionAuthorizationHash :=
          packet.signedRegistryExecutionMetadata.executionAuthorization.executionAuthorizationHash }
    signedRegistryBridge :=
      { resolutionHash :=
          packet.signedRegistryExecutionMetadata.signedRegistryBridge.resolutionHash
        registryCheckpointAttestationHash :=
          packet.signedRegistryExecutionMetadata.signedRegistryBridge.registryCheckpointAttestationHash } }

def exactPacketOfConcreteAuthorizationPacket
    (packet : ConcretePacket)
    (boundary : ExecutionBoundaryWitness)
    (executorAdmission : ExecutionExecutorAdmissionWitness)
    (_bindingVector : ExecutionBindingVectorPacket)
    (_refinement : ExecutionBoundaryRefinementPacket) : ExactPacket :=
  { executionReady :=
      { boundary := boundary
        authorization := some (exactAuthorizationWitnessOfConcretePacket packet)
        bridge := some (exactBridgeWitnessOfConcretePacket packet)
        executorAdmission := some executorAdmission }
    executionBindingVector := { exactTuplePresent := true }
    executionBoundaryRefinement :=
      { readyPacketHashPresent := true
        attestationMetadataHashPresent := true }
    signedRegistryExecutionMetadata :=
      { executionAuthorizationMetadataPresent := true
        signedRegistryBridgeMetadataPresent := true } }

def signedRegistryExecutionArtifactOfConcretePacket
    (packet : ConcretePacket)
    (boundary : ExecutionBoundaryWitness)
    (executorAdmission : ExecutionExecutorAdmissionWitness)
    (bindingVector : ExecutionBindingVectorPacket)
    (refinement : ExecutionBoundaryRefinementPacket) :
    SignedRegistryExecutionArtifact :=
  { executionReady :=
      { boundary := boundary
        authorization := some (exactAuthorizationWitnessOfConcretePacket packet)
        bridge := some (exactBridgeWitnessOfConcretePacket packet)
        executorAdmission := some executorAdmission }
    executionBindingVector := some bindingVector
    executionBoundaryRefinement := some refinement
    signedRegistryExecutionMetadata :=
      some (signedRegistryExecutionMetadataOfConcretePacket packet) }

theorem exact_authorization_witness_of_concrete_packet_holds
    {packet : ConcretePacket}
    (hGovernance : packet.executionAuthorization.governance.isSome = true) :
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.authorizationWitnessHolds
      (exactAuthorizationWitnessOfConcretePacket packet) := by
  simp [exactAuthorizationWitnessOfConcretePacket, hGovernance,
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.authorizationWitnessHolds]

theorem exact_bridge_witness_of_concrete_packet_holds
    (packet : ConcretePacket) :
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.bridgeWitnessHolds
      (exactBridgeWitnessOfConcretePacket packet) := by
  simp [exactBridgeWitnessOfConcretePacket,
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.bridgeWitnessHolds]

theorem signed_registry_execution_artifact_of_concrete_packet_compiles_exact_packet
    (packet : ConcretePacket)
    (boundary : ExecutionBoundaryWitness)
    (executorAdmission : ExecutionExecutorAdmissionWitness)
    (bindingVector : ExecutionBindingVectorPacket)
    (refinement : ExecutionBoundaryRefinementPacket) :
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileExactPacket
        (signedRegistryExecutionArtifactOfConcretePacket
          packet boundary executorAdmission bindingVector refinement) =
      exactPacketOfConcreteAuthorizationPacket
        packet boundary executorAdmission bindingVector refinement := by
  rfl

theorem signed_registry_execution_artifact_of_concrete_packet_holds
    {packet : ConcretePacket}
    {boundary : ExecutionBoundaryWitness}
    {executorAdmission : ExecutionExecutorAdmissionWitness}
    {bindingVector : ExecutionBindingVectorPacket}
    {refinement : ExecutionBoundaryRefinementPacket}
    (hBoundary :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.boundaryWitnessHolds
        boundary)
    (hGovernance : packet.executionAuthorization.governance.isSome = true)
    (hExecutorAdmission :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executorAdmissionWitnessHolds
        executorAdmission) :
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ArtifactHolds
      (signedRegistryExecutionArtifactOfConcretePacket
        packet boundary executorAdmission bindingVector refinement) := by
  refine ⟨hBoundary, ?_, ?_, ?_, rfl, rfl, rfl⟩
  · refine ⟨exactAuthorizationWitnessOfConcretePacket packet, rfl, ?_⟩
    exact exact_authorization_witness_of_concrete_packet_holds hGovernance
  · refine ⟨exactBridgeWitnessOfConcretePacket packet, rfl, ?_⟩
    exact exact_bridge_witness_of_concrete_packet_holds packet
  · exact ⟨executorAdmission, rfl, hExecutorAdmission⟩

theorem concrete_authorization_packet_artifact_admits_generic_execution_ready_artifact_witness
    {packet : ConcretePacket}
    {boundary : ExecutionBoundaryWitness}
    {executorAdmission : ExecutionExecutorAdmissionWitness}
    {bindingVector : ExecutionBindingVectorPacket}
    {refinement : ExecutionBoundaryRefinementPacket}
    (hBoundary :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.boundaryWitnessHolds
        boundary)
    (hGovernance : packet.executionAuthorization.governance.isSome = true)
    (hExecutorAdmission :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executorAdmissionWitnessHolds
        executorAdmission) :
    MPRDExecutionReadyArtifactRuntimeRefinement.ArtifactHolds
      (MPRDSignedRegistryExecutionArtifactRuntimeRefinement.genericArtifactWitnessOfSignedRegistryArtifact
        (signedRegistryExecutionArtifactOfConcretePacket
          packet boundary executorAdmission bindingVector refinement)) := by
  exact
    MPRDSignedRegistryExecutionArtifactRuntimeRefinement.generic_artifact_witness_holds
      (signed_registry_execution_artifact_of_concrete_packet_holds
        hBoundary hGovernance hExecutorAdmission)

end MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler

abbrev signed_registry_execution_artifact_of_concrete_authorization_packet_holds_v1 :=
  @MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.signed_registry_execution_artifact_of_concrete_packet_holds

abbrev concrete_authorization_packet_artifact_admits_generic_execution_ready_artifact_witness_v1 :=
  @MPRDRegistryGovernanceExecutionAuthorizationArtifactCompiler.concrete_authorization_packet_artifact_admits_generic_execution_ready_artifact_witness
