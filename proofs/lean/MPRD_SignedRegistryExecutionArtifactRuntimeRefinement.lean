/- 
  MPRD_SignedRegistryExecutionArtifactRuntimeRefinement.lean

  A lightweight compiler/refinement bridge from the grouped signed-registry
  execution artifact language into the exact signed-registry packet lane.

  This is intentionally narrower than a full runtime-to-formal refinement
  theorem. It closes one more local seam: once the shipped grouped runtime
  artifact exists and its grouped `ExecutionReadyPacketV1` admissions hold, the
  next refinement step can consume one canonical artifact language instead of a
  manually reconstructed exact packet.
-/

import MPRD_ExecutionBindingVectorPacketBoundary
import MPRD_ExecutionBoundaryRefinementPacketBoundary
import MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement
import MPRD_SignedRegistryExecutionMetadataPacketBoundary

namespace MPRDSignedRegistryExecutionArtifactRuntimeRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev ExactPacket :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.SignedRegistryExecutionExactPacket
abbrev ExecutionReadyPacket :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.ExecutionReadyPacket

structure SignedRegistryExecutionArtifact where
  executionReady : ExecutionReadyPacket
  executionBindingVector :
    Option MPRDExecutionBindingVectorPacketBoundary.ExecutionBindingVectorPacket
  executionBoundaryRefinement :
    Option MPRDExecutionBoundaryRefinementPacketBoundary.ExecutionBoundaryRefinementPacket
  signedRegistryExecutionMetadata :
    Option MPRDSignedRegistryExecutionMetadataPacketBoundary.SignedRegistryExecutionMetadataPacket
  deriving Repr, DecidableEq

def ArtifactHolds (a : SignedRegistryExecutionArtifact) : Prop :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.boundaryWitnessHolds
      a.executionReady.boundary ∧
    (∃ authorization,
      a.executionReady.authorization = some authorization ∧
        MPRDSignedRegistryExecutionExactPacketWitnessCompiler.authorizationWitnessHolds
          authorization) ∧
      (∃ bridge,
        a.executionReady.bridge = some bridge ∧
          MPRDSignedRegistryExecutionExactPacketWitnessCompiler.bridgeWitnessHolds bridge) ∧
        (∃ admission,
          a.executionReady.executorAdmission = some admission ∧
            MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executorAdmissionWitnessHolds
              admission) ∧
          a.executionBindingVector.isSome = true ∧
            a.executionBoundaryRefinement.isSome = true ∧
              a.signedRegistryExecutionMetadata.isSome = true

def compileExactPacket (a : SignedRegistryExecutionArtifact) : ExactPacket :=
  { executionReady := a.executionReady
    executionBindingVector := { exactTuplePresent := a.executionBindingVector.isSome }
    executionBoundaryRefinement :=
      { readyPacketHashPresent := a.executionBoundaryRefinement.isSome
        attestationMetadataHashPresent := a.executionBoundaryRefinement.isSome }
    signedRegistryExecutionMetadata :=
      { executionAuthorizationMetadataPresent := a.signedRegistryExecutionMetadata.isSome
        signedRegistryBridgeMetadataPresent := a.signedRegistryExecutionMetadata.isSome } }

theorem compiled_exact_packet_holds
    {a : SignedRegistryExecutionArtifact}
    (h : ArtifactHolds a) :
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executionWitnessRelevantHolds
      (compileExactPacket a) := by
  rcases h with
    ⟨hBoundary, hAuthorization, hBridge, hAdmission, hBindingVector, hRefinement, hMetadata⟩
  constructor
  · simpa [compileExactPacket] using hBoundary
  constructor
  · rcases hAuthorization with ⟨authorization, hAuthSome, hAuth⟩
    exact ⟨authorization, by simpa [compileExactPacket] using hAuthSome, hAuth⟩
  constructor
  · rcases hBridge with ⟨bridge, hBridgeSome, hBridgeHolds⟩
    exact ⟨bridge, by simpa [compileExactPacket] using hBridgeSome, hBridgeHolds⟩
  constructor
  · rcases hAdmission with ⟨admission, hAdmissionSome, hAdmissionHolds⟩
    exact ⟨admission, by simpa [compileExactPacket] using hAdmissionSome, hAdmissionHolds⟩
  · simp [compileExactPacket, hBindingVector, hRefinement, hMetadata]

theorem executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {a : SignedRegistryExecutionArtifact}
    (hArtifact : ArtifactHolds a) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings =
          (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness
            (compileExactPacket a)).bindings ∧
        t.ctx.executorGate =
            (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness
              (compileExactPacket a)).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  exact
    MPRDSignedRegistryExecutionExactPacketRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
      hReach hExec (compiled_exact_packet_holds hArtifact)

end MPRDSignedRegistryExecutionArtifactRuntimeRefinement

abbrev signed_registry_execution_artifact_compiles_exact_packet_v1 :=
  @MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compiled_exact_packet_holds

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_from_signed_registry_execution_artifact_v1 :=
  @MPRDSignedRegistryExecutionArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
