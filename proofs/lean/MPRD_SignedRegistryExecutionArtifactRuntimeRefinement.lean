/- 
  MPRD_SignedRegistryExecutionArtifactRuntimeRefinement.lean

  A lightweight compiler/refinement bridge from the grouped signed-registry
  execution artifact language into the grouped runtime refinement-witness lane.

  This is intentionally narrower than a full runtime-to-formal refinement
  theorem. It closes one more local seam: once the shipped grouped runtime
  artifact exists and its grouped `ExecutionReadyPacketV1` admissions hold, the
  next refinement step can consume one canonical artifact language instead of a
  manually reconstructed exact packet or a hand-built runtime witness.
-/

import MPRD_ExecutionBindingVectorPacketBoundary
import MPRD_ExecutionBoundaryRefinementPacketBoundary
import MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement
import MPRD_SignedRegistryExecutionMetadataPacketBoundary

namespace MPRDSignedRegistryExecutionArtifactRuntimeRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev RuntimeWitness :=
  MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness
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

def compileBindings (a : SignedRegistryExecutionArtifact) :
    MPRDExecutionBoundary.BindingVector :=
  -- This local artifact lane only tracks exact-tuple presence, so every
  -- concrete binding bit is compiled from the same grouped witness surface.
  { journalAllowed := a.executionBindingVector.isSome
    limitsHashMatches := a.executionBindingVector.isSome
    decisionCommitmentValid := a.executionBindingVector.isSome
    policyHashMatches := a.executionBindingVector.isSome
    policyEpochMatches := a.executionBindingVector.isSome
    registryRootMatches := a.executionBindingVector.isSome
    stateSourceMatches := a.executionBindingVector.isSome
    stateEpochMatches := a.executionBindingVector.isSome
    stateAttestationMatches := a.executionBindingVector.isSome
    stateHashMatches := a.executionBindingVector.isSome
    candidateSetHashMatches := a.executionBindingVector.isSome
    chosenActionHashMatches := a.executionBindingVector.isSome
    nonceMatches := a.executionBindingVector.isSome }

def compileExecutorGate (a : SignedRegistryExecutionArtifact) :
    MPRDExecutionBoundary.ExecutorGate :=
  -- Boundary admissions carry the execute-ready preimage bits; the grouped
  -- binding-vector presence stands in for the remaining hash/schema checks.
  { preimagePresent := a.executionReady.boundary.chosenActionPreimagePresent
    limitsBytesBindingOk := a.executionReady.boundary.limitsBindingPresent
    actionPreimageHashMatches := a.executionBindingVector.isSome
    schemaValid := a.executionBindingVector.isSome }

def compileRuntimeWitness (a : SignedRegistryExecutionArtifact) :
    RuntimeWitness :=
  { governanceAdmitted :=
      match a.executionReady.authorization with
      | some authorization => authorization.governancePresent
      | none => false
    signatureAdmitted :=
      match a.executionReady.executorAdmission with
      | some admission => admission.signaturePresent
      | none => false
    stateProvenanceAdmitted :=
      match a.executionReady.executorAdmission with
      | some admission => admission.stateProvenancePresent
      | none => false
    replayAdmitted :=
      match a.executionReady.executorAdmission with
      | some admission => admission.replayClearancePresent
      | none => false
    bindings := compileBindings a
    executorGate := compileExecutorGate a }

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

theorem compile_runtime_witness_matches_exact_packet_compiler
    (a : SignedRegistryExecutionArtifact) :
    compileRuntimeWitness a =
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness
        (compileExactPacket a) := by
  cases a
  rfl

theorem compiled_runtime_witness_holds
    {a : SignedRegistryExecutionArtifact}
    (h : ArtifactHolds a) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
      (compileRuntimeWitness a) := by
  have hExact :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executionWitnessRelevantHolds
        (compileExactPacket a) := by
    exact compiled_exact_packet_holds h
  have hCompiled :
      MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
        (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness
          (compileExactPacket a)) := by
    exact
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compiled_runtime_witness_holds
        hExact
  simpa [compile_runtime_witness_matches_exact_packet_compiler a] using hCompiled

theorem executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {a : SignedRegistryExecutionArtifact}
    (hArtifact : ArtifactHolds a) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = (compileRuntimeWitness a).bindings ∧
        t.ctx.executorGate = (compileRuntimeWitness a).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  simpa [MPRDExecutionReadyRefinementWitnessCompiler.compileWitness, compileRuntimeWitness]
    using
      MPRDExecutionReadyRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
        hReach hExec (compiled_runtime_witness_holds hArtifact)

end MPRDSignedRegistryExecutionArtifactRuntimeRefinement

abbrev signed_registry_execution_artifact_compiles_exact_packet_v1 :=
  @MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compiled_exact_packet_holds

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_from_signed_registry_execution_artifact_v1 :=
  @MPRDSignedRegistryExecutionArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
