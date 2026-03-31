/-
  MPRD_RegistryGovernanceExecutionAuthorizationPacketCompiler.lean

  A lightweight local compiler theorem for the grouped concrete ready-bridge
  authorization packet in `mprd-zk`:

    once the concrete governance sources reconcile, the live execution-
    authorization witness projected into grouped metadata is extensionally
    equal to the direct concrete registry/governance metadata compiler, and the
    grouped packet preserves both sides exactly.

  This is intentionally narrower than a top-level runtime refinement theorem.
  It closes the local seam where the new grouped concrete bridge packet is
  justified only by an inline equality check inside the runtime helper.
-/

namespace MPRDRegistryGovernanceExecutionAuthorizationPacketCompiler

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure PolicyRef where
  policyEpoch : Nat
  registryRoot : Nat
  deriving Repr, DecidableEq

structure StateRef where
  stateSourceId : Nat
  stateEpoch : Nat
  stateAttestationHash : Nat
  deriving Repr, DecidableEq

inductive GovernanceUpdateKind where
  | policyTweak
  | safetyRuleChange
  | agentCapabilityExpand
  deriving Repr, DecidableEq

structure GovernanceAdmission where
  updateKind : GovernanceUpdateKind
  profileAppOk : Bool
  profileSafetyOk : Bool
  linkOk : Bool
  deriving Repr, DecidableEq

structure PolicyAuthorityWitness where
  policyHash : Nat
  policyRef : PolicyRef
  deriving Repr, DecidableEq

structure StateBindingWitness where
  stateHash : Nat
  stateRef : StateRef
  deriving Repr, DecidableEq

structure ExecutionAuthorizationWitness where
  policyAuthority : PolicyAuthorityWitness
  stateBinding : StateBindingWitness
  governance : Option GovernanceAdmission
  deriving Repr, DecidableEq

structure ExecutionAuthorizationAttestation where
  policyHash : Nat
  policyRef : PolicyRef
  stateHash : Nat
  stateRef : StateRef
  governance : Option GovernanceAdmission
  deriving Repr, DecidableEq

structure ExecutionAuthorizationMetadataPacket where
  executionAuthorization : ExecutionAuthorizationAttestation
  executionAuthorizationHash : Nat
  deriving Repr, DecidableEq

structure SignedRegistryBridgeMetadataPacket where
  resolutionHash : Nat
  execKindId : Nat
  execVersionId : Nat
  imageId : Nat
  policySourceKindId : Option Nat
  policySourceHash : Option Nat
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

structure SignedRegistryExecutionMetadataPacket where
  executionAuthorization : ExecutionAuthorizationMetadataPacket
  signedRegistryBridge : SignedRegistryBridgeMetadataPacket
  deriving Repr, DecidableEq

structure RegistryGovernanceExecutionAuthorizationPacket where
  executionAuthorization : ExecutionAuthorizationWitness
  signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket
  deriving Repr, DecidableEq

structure ConcreteGovernanceSources where
  stateGovernance : Option GovernanceAdmission
  inputGovernance : Option GovernanceAdmission
  deriving Repr, DecidableEq

def reconcileGovernance
    (stateGovernance : Option GovernanceAdmission)
    (inputGovernance : Option GovernanceAdmission) :
    Option GovernanceAdmission :=
  match stateGovernance, inputGovernance with
  | some fromState, some fromInput =>
      if fromState = fromInput then some fromState else none
  | some fromState, none => some fromState
  | none, some fromInput => some fromInput
  | none, none => none

def executionAuthorizationMetadataPacketFromWitness
    (authorization : ExecutionAuthorizationWitness)
    (executionAuthorizationHash : Nat) :
    ExecutionAuthorizationMetadataPacket :=
  { executionAuthorization :=
      { policyHash := authorization.policyAuthority.policyHash
        policyRef := authorization.policyAuthority.policyRef
        stateHash := authorization.stateBinding.stateHash
        stateRef := authorization.stateBinding.stateRef
        governance := authorization.governance }
    executionAuthorizationHash := executionAuthorizationHash }

def executionAuthorizationMetadataPacketFromConcreteInputs
    (policyAuthority : PolicyAuthorityWitness)
    (stateBinding : StateBindingWitness)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat) :
    Option ExecutionAuthorizationMetadataPacket :=
  (reconcileGovernance sources.stateGovernance sources.inputGovernance).map
    (fun governance =>
      { executionAuthorization :=
          { policyHash := policyAuthority.policyHash
            policyRef := policyAuthority.policyRef
            stateHash := stateBinding.stateHash
            stateRef := stateBinding.stateRef
            governance := some governance }
        executionAuthorizationHash := executionAuthorizationHash })

def registryGovernanceExecutionAuthorizationPacketFromWitnessAndMetadata
    (executionAuthorization : ExecutionAuthorizationWitness)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    RegistryGovernanceExecutionAuthorizationPacket :=
  { executionAuthorization := executionAuthorization
    signedRegistryExecutionMetadata := signedRegistryExecutionMetadata }

theorem witness_projection_matches_concrete_metadata_compiler
    (policyAuthority : PolicyAuthorityWitness)
    (stateBinding : StateBindingWitness)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket)
    (governance : GovernanceAdmission)
    (hRecon :
      reconcileGovernance sources.stateGovernance sources.inputGovernance =
        some governance) :
    let executionAuthorization : ExecutionAuthorizationWitness :=
      { policyAuthority := policyAuthority
        stateBinding := stateBinding
        governance := some governance }
    let concreteMetadata :=
      executionAuthorizationMetadataPacketFromConcreteInputs
        policyAuthority
        stateBinding
        sources
        executionAuthorizationHash
    let groupedPacket :=
      registryGovernanceExecutionAuthorizationPacketFromWitnessAndMetadata
        executionAuthorization
        { executionAuthorization :=
            executionAuthorizationMetadataPacketFromWitness
              executionAuthorization
              executionAuthorizationHash
          signedRegistryBridge := signedRegistryBridge }
    concreteMetadata = some groupedPacket.signedRegistryExecutionMetadata.executionAuthorization := by
  simp [executionAuthorizationMetadataPacketFromConcreteInputs,
    executionAuthorizationMetadataPacketFromWitness,
    registryGovernanceExecutionAuthorizationPacketFromWitnessAndMetadata, hRecon]

theorem grouped_packet_preserves_exact_witness_and_metadata
    (executionAuthorization : ExecutionAuthorizationWitness)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    let packet :=
      registryGovernanceExecutionAuthorizationPacketFromWitnessAndMetadata
        executionAuthorization
        signedRegistryExecutionMetadata
    packet.executionAuthorization = executionAuthorization ∧
      packet.signedRegistryExecutionMetadata = signedRegistryExecutionMetadata := by
  simp [registryGovernanceExecutionAuthorizationPacketFromWitnessAndMetadata]

end MPRDRegistryGovernanceExecutionAuthorizationPacketCompiler

abbrev registry_governance_execution_authorization_packet_preserves_exact_witness_and_metadata_v1 :=
  @MPRDRegistryGovernanceExecutionAuthorizationPacketCompiler.grouped_packet_preserves_exact_witness_and_metadata
