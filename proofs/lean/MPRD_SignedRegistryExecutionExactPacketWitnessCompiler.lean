/- 
  MPRD_SignedRegistryExecutionExactPacketWitnessCompiler.lean

  A lightweight local compiler from a richer exact signed-registry execution
  packet language into the grouped runtime execute-ready refinement witness.

  This closes a real witness-language gap:

    the older signed-registry refinement packet language is hash-oriented and
    too lossy to serve as the smallest exact witness language for the runtime
    refinement step. This exact packet language instead preserves the concrete
    execute-ready admissions plus the concrete binding-vector presence, which is
    the minimal exact surface needed for this compiler target.

  This is still narrower than a top-level runtime refinement theorem. It only
  says that once these exact grouped runtime packets exist, there is one
  canonical runtime refinement-witness shape for the next proof lane.
-/

import MPRD_ExecutionReadyRefinementWitnessCompiler

namespace MPRDSignedRegistryExecutionExactPacketWitnessCompiler

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure ExecutionBoundaryWitness where
  chosenActionPreimagePresent : Bool
  limitsBindingPresent : Bool
  deriving Repr, DecidableEq

structure ExecutionAuthorizationWitness where
  policyAuthorityPresent : Bool
  stateBindingPresent : Bool
  governancePresent : Bool
  deriving Repr, DecidableEq

structure ExecutionRegistryBridgeWitness where
  registryAuthorizationPresent : Bool
  checkpointAttestationPresent : Bool
  deriving Repr, DecidableEq

structure ExecutionExecutorAdmissionWitness where
  signaturePresent : Bool
  stateProvenancePresent : Bool
  replayClearancePresent : Bool
  deriving Repr, DecidableEq

structure ExecutionReadyPacket where
  boundary : ExecutionBoundaryWitness
  authorization : Option ExecutionAuthorizationWitness
  bridge : Option ExecutionRegistryBridgeWitness
  executorAdmission : Option ExecutionExecutorAdmissionWitness
  deriving Repr, DecidableEq

structure ExecutionBindingVectorPacket where
  exactTuplePresent : Bool
  deriving Repr, DecidableEq

structure ExecutionBoundaryRefinementPacket where
  readyPacketHashPresent : Bool
  attestationMetadataHashPresent : Bool
  deriving Repr, DecidableEq

structure SignedRegistryExecutionMetadataPacket where
  executionAuthorizationMetadataPresent : Bool
  signedRegistryBridgeMetadataPresent : Bool
  deriving Repr, DecidableEq

structure SignedRegistryExecutionExactPacket where
  executionReady : ExecutionReadyPacket
  executionBindingVector : ExecutionBindingVectorPacket
  executionBoundaryRefinement : ExecutionBoundaryRefinementPacket
  signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket
  deriving Repr, DecidableEq

def boundaryWitnessHolds (w : ExecutionBoundaryWitness) : Prop :=
  w.chosenActionPreimagePresent = true ∧
    w.limitsBindingPresent = true

def authorizationWitnessHolds (w : ExecutionAuthorizationWitness) : Prop :=
  w.policyAuthorityPresent = true ∧
    w.stateBindingPresent = true ∧
      w.governancePresent = true

def bridgeWitnessHolds (w : ExecutionRegistryBridgeWitness) : Prop :=
  w.registryAuthorizationPresent = true

def executorAdmissionWitnessHolds (w : ExecutionExecutorAdmissionWitness) : Prop :=
  w.signaturePresent = true ∧
    w.stateProvenancePresent = true ∧
      w.replayClearancePresent = true

def executionWitnessRelevantHolds (p : SignedRegistryExecutionExactPacket) : Prop :=
  boundaryWitnessHolds p.executionReady.boundary ∧
    (∃ authorization : ExecutionAuthorizationWitness,
      p.executionReady.authorization = some authorization ∧
        authorizationWitnessHolds authorization) ∧
      (∃ bridge : ExecutionRegistryBridgeWitness,
        p.executionReady.bridge = some bridge ∧
          bridgeWitnessHolds bridge) ∧
        (∃ admission : ExecutionExecutorAdmissionWitness,
          p.executionReady.executorAdmission = some admission ∧
            executorAdmissionWitnessHolds admission) ∧
          p.executionBindingVector.exactTuplePresent = true

def compileBindings (p : SignedRegistryExecutionExactPacket) :
    MPRDExecutionBoundary.BindingVector :=
  { journalAllowed := p.executionBindingVector.exactTuplePresent
    limitsHashMatches := p.executionBindingVector.exactTuplePresent
    decisionCommitmentValid := p.executionBindingVector.exactTuplePresent
    policyHashMatches := p.executionBindingVector.exactTuplePresent
    policyEpochMatches := p.executionBindingVector.exactTuplePresent
    registryRootMatches := p.executionBindingVector.exactTuplePresent
    stateSourceMatches := p.executionBindingVector.exactTuplePresent
    stateEpochMatches := p.executionBindingVector.exactTuplePresent
    stateAttestationMatches := p.executionBindingVector.exactTuplePresent
    stateHashMatches := p.executionBindingVector.exactTuplePresent
    candidateSetHashMatches := p.executionBindingVector.exactTuplePresent
    chosenActionHashMatches := p.executionBindingVector.exactTuplePresent
    nonceMatches := p.executionBindingVector.exactTuplePresent }

def compileExecutorGate (p : SignedRegistryExecutionExactPacket) :
    MPRDExecutionBoundary.ExecutorGate :=
  { preimagePresent := p.executionReady.boundary.chosenActionPreimagePresent
    limitsBytesBindingOk := p.executionReady.boundary.limitsBindingPresent
    actionPreimageHashMatches := p.executionBindingVector.exactTuplePresent
    schemaValid := p.executionBindingVector.exactTuplePresent }

def compileRuntimeWitness (p : SignedRegistryExecutionExactPacket) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness :=
  { governanceAdmitted :=
      match p.executionReady.authorization with
      | some authorization => authorization.governancePresent
      | none => false
    signatureAdmitted :=
      match p.executionReady.executorAdmission with
      | some admission => admission.signaturePresent
      | none => false
    stateProvenanceAdmitted :=
      match p.executionReady.executorAdmission with
      | some admission => admission.stateProvenancePresent
      | none => false
    replayAdmitted :=
      match p.executionReady.executorAdmission with
      | some admission => admission.replayClearancePresent
      | none => false
    bindings := compileBindings p
    executorGate := compileExecutorGate p }

theorem compiled_runtime_witness_holds
    {p : SignedRegistryExecutionExactPacket}
    (h : executionWitnessRelevantHolds p) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
      (compileRuntimeWitness p) := by
  rcases h with ⟨hBoundary, hAuthorization, hBridge, hAdmission, hBinding⟩
  rcases hBoundary with ⟨hPreimage, hLimits⟩
  rcases hAuthorization with ⟨authorization, hAuthSome, hAuth⟩
  rcases hAuth with ⟨_hPolicyAuthority, _hStateBinding, hGovernance⟩
  rcases hBridge with ⟨_bridge, _hBridgeSome, _hBridge⟩
  rcases hAdmission with ⟨admission, hAdmissionSome, hAdmissionHolds⟩
  rcases hAdmissionHolds with ⟨hSignature, hStateProv, hReplay⟩
  constructor
  · simpa [compileRuntimeWitness, hAuthSome] using hGovernance
  constructor
  · simpa [compileRuntimeWitness, hAdmissionSome] using hSignature
  constructor
  · simpa [compileRuntimeWitness, hAdmissionSome] using hStateProv
  constructor
  · simpa [compileRuntimeWitness, hAdmissionSome] using hReplay
  constructor
  · simp [compileRuntimeWitness, compileBindings, MPRDExecutionBoundary.ConcreteBindingsHold,
      hBinding]
  · simp [compileRuntimeWitness, compileExecutorGate, MPRDExecutionBoundary.ExecutorGateHold,
      hPreimage, hLimits, hBinding]

end MPRDSignedRegistryExecutionExactPacketWitnessCompiler

abbrev signed_registry_execution_exact_packet_compiles_runtime_witness_v1 :=
  @MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compiled_runtime_witness_holds
