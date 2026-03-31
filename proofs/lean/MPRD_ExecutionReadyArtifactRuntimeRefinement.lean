/- 
  MPRD_ExecutionReadyArtifactRuntimeRefinement.lean

  A lightweight compiler/refinement bridge from the grouped generic
  execute-ready runtime artifact language into the grouped runtime
  refinement-witness lane.

  This is intentionally narrower than a top-level runtime-to-formal execution
  theorem. It closes one more local seam: once the live execute-ready packet
  admissions and grouped binding/refinement/authorization packets exist
  together, the next refinement step can consume one canonical grouped runtime
  artifact instead of a hand-built runtime witness.
-/

import MPRD_ExecutionAuthorizationMetadataPacketBoundary
import MPRD_ExecutionBindingVectorPacketBoundary
import MPRD_ExecutionBoundaryRefinementPacketBoundary
import MPRD_ExecutionReadyRuntimeRefinement

namespace MPRDExecutionReadyArtifactRuntimeRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev RuntimeWitness :=
  MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness

structure ExecutionReadyArtifact where
  executionBindingVector :
    Option MPRDExecutionBindingVectorPacketBoundary.ExecutionBindingVectorPacket
  executionBoundaryRefinement :
    Option MPRDExecutionBoundaryRefinementPacketBoundary.ExecutionBoundaryRefinementPacket
  executionAuthorizationMetadata :
    Option MPRDExecutionAuthorizationMetadataPacketBoundary.ExecutionAuthorizationMetadataPacket
  deriving Repr, DecidableEq

def ArtifactHolds (a : ExecutionReadyArtifact) : Prop :=
  a.executionBindingVector.isSome = true ∧
    a.executionBoundaryRefinement.isSome = true ∧
      (∃ metadata,
        a.executionAuthorizationMetadata = some metadata ∧
          metadata.executionAuthorization.governance.isSome = true)

def canonicalBindings : MPRDExecutionBoundary.BindingVector :=
  { journalAllowed := true
    limitsHashMatches := true
    decisionCommitmentValid := true
    policyHashMatches := true
    policyEpochMatches := true
    registryRootMatches := true
    stateSourceMatches := true
    stateEpochMatches := true
    stateAttestationMatches := true
    stateHashMatches := true
    candidateSetHashMatches := true
    chosenActionHashMatches := true
    nonceMatches := true }

def emptyBindings : MPRDExecutionBoundary.BindingVector :=
  { journalAllowed := false
    limitsHashMatches := false
    decisionCommitmentValid := false
    policyHashMatches := false
    policyEpochMatches := false
    registryRootMatches := false
    stateSourceMatches := false
    stateEpochMatches := false
    stateAttestationMatches := false
    stateHashMatches := false
    candidateSetHashMatches := false
    chosenActionHashMatches := false
    nonceMatches := false }

def canonicalExecutorGate : MPRDExecutionBoundary.ExecutorGate :=
  { preimagePresent := true
    limitsBytesBindingOk := true
    actionPreimageHashMatches := true
    schemaValid := true }

def emptyExecutorGate : MPRDExecutionBoundary.ExecutorGate :=
  { preimagePresent := false
    limitsBytesBindingOk := false
    actionPreimageHashMatches := false
    schemaValid := false }

def compileBindings (a : ExecutionReadyArtifact) : MPRDExecutionBoundary.BindingVector :=
  if a.executionBindingVector.isSome = true then canonicalBindings else emptyBindings

def compileExecutorGate (s : PacketState) : MPRDExecutionBoundary.ExecutorGate :=
  if s.boundaryAdmitted = true then canonicalExecutorGate else emptyExecutorGate

def compileRuntimeWitness (s : PacketState) (a : ExecutionReadyArtifact) :
    RuntimeWitness :=
  { governanceAdmitted :=
      match a.executionAuthorizationMetadata with
      | some metadata => metadata.executionAuthorization.governance.isSome
      | none => false
    signatureAdmitted := s.signatureAdmitted
    stateProvenanceAdmitted := s.stateProvenanceAdmitted
    replayAdmitted := s.replayAdmitted
    bindings := compileBindings a
    executorGate := compileExecutorGate s }

theorem compiled_runtime_witness_holds
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {a : ExecutionReadyArtifact}
    (hArtifact : ArtifactHolds a) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
      (compileRuntimeWitness s a) := by
  rcases
      MPRDExecutionReadyPacketBoundary.executed_reachable_states_require_execution_ready_packet_boundary
        hReach hExec with
    ⟨_hPacket, _hReady, hBoundary, _hAuth, _hBridge, hSignature, hStateProv, hReplay⟩
  rcases hArtifact with ⟨hBindingPacket, _hRefinement, metadata, hMetadataSome, hGovernance⟩
  constructor
  · simpa [compileRuntimeWitness, hMetadataSome] using hGovernance
  constructor
  · simpa [compileRuntimeWitness] using hSignature
  constructor
  · simpa [compileRuntimeWitness] using hStateProv
  constructor
  · simpa [compileRuntimeWitness] using hReplay
  constructor
  · simp [compileRuntimeWitness, compileBindings, hBindingPacket, canonicalBindings,
      MPRDExecutionBoundary.ConcreteBindingsHold]
  · simp [compileRuntimeWitness, compileExecutorGate, hBoundary, canonicalExecutorGate,
      MPRDExecutionBoundary.ExecutorGateHold]

theorem executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {a : ExecutionReadyArtifact}
    (hArtifact : ArtifactHolds a) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = (compileRuntimeWitness s a).bindings ∧
        t.ctx.executorGate = (compileRuntimeWitness s a).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  exact
    MPRDExecutionReadyRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
      hReach hExec (compiled_runtime_witness_holds hReach hExec hArtifact)

end MPRDExecutionReadyArtifactRuntimeRefinement

abbrev execution_ready_artifact_compiles_runtime_witness_v1 :=
  @MPRDExecutionReadyArtifactRuntimeRefinement.compiled_runtime_witness_holds

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_from_execution_ready_artifact_v1 :=
  @MPRDExecutionReadyArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
