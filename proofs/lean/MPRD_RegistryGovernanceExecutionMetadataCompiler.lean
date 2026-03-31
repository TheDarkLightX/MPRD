/-
  MPRD_RegistryGovernanceExecutionMetadataCompiler.lean

  A lightweight local compiler theorem for the concrete registry/governance
  bridge in `mprd-zk`:

    once the concrete governance sources reconcile, the concrete registry
    resolution plus policy/state fields compile to the exact grouped
    `SignedRegistryExecutionMetadataPacketV1` language.

  This is intentionally narrower than a top-level runtime refinement theorem.
  It closes the local seam where the ready-bridge helper rebuilt the live
  execution-authorization metadata packet from concrete registry and governance
  objects ad hoc, without one named compiler law over that concrete input
  language.
-/

namespace MPRDRegistryGovernanceExecutionMetadataCompiler

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

def executionAuthorizationMetadataPacketFromConcreteInputs
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat) :
    Option ExecutionAuthorizationMetadataPacket :=
  (reconcileGovernance sources.stateGovernance sources.inputGovernance).map
    (fun governance =>
      { executionAuthorization :=
          { policyHash := policyHash
            policyRef := policyRef
            stateHash := stateHash
            stateRef := stateRef
            governance := some governance }
        executionAuthorizationHash := executionAuthorizationHash })

def executionAuthorizationMetadataPacketFromConcreteInputsOrNone
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat) :
    ExecutionAuthorizationMetadataPacket :=
  match reconcileGovernance sources.stateGovernance sources.inputGovernance with
  | some governance =>
      { executionAuthorization :=
          { policyHash := policyHash
            policyRef := policyRef
            stateHash := stateHash
            stateRef := stateRef
            governance := some governance }
        executionAuthorizationHash := executionAuthorizationHash }
  | none =>
      { executionAuthorization :=
          { policyHash := policyHash
            policyRef := policyRef
            stateHash := stateHash
            stateRef := stateRef
            governance := none }
        executionAuthorizationHash := executionAuthorizationHash }

def signedRegistryExecutionMetadataPacketFromConcreteInputs
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket) :
    Option SignedRegistryExecutionMetadataPacket :=
  (executionAuthorizationMetadataPacketFromConcreteInputs
    policyHash
    policyRef
    stateHash
    stateRef
    sources
    executionAuthorizationHash).map
      (fun executionAuthorization =>
        { executionAuthorization := executionAuthorization
          signedRegistryBridge := signedRegistryBridge })

theorem reconcile_governance_detects_drift
    (fromState fromInput : GovernanceAdmission)
    (hDrift : fromState ≠ fromInput) :
    reconcileGovernance (some fromState) (some fromInput) = none := by
  simp [reconcileGovernance, hDrift]

theorem concrete_inputs_compile_exact_execution_authorization_metadata_packet
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat)
    (governance : GovernanceAdmission)
    (hRecon :
      reconcileGovernance sources.stateGovernance sources.inputGovernance =
        some governance) :
    executionAuthorizationMetadataPacketFromConcreteInputs
        policyHash
        policyRef
        stateHash
        stateRef
        sources
        executionAuthorizationHash =
      some {
        executionAuthorization := {
          policyHash := policyHash
          policyRef := policyRef
          stateHash := stateHash
          stateRef := stateRef
          governance := some governance
        }
        executionAuthorizationHash := executionAuthorizationHash
      } := by
  simp [executionAuthorizationMetadataPacketFromConcreteInputs, hRecon]

theorem concrete_inputs_compile_exact_signed_registry_execution_metadata_packet
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (sources : ConcreteGovernanceSources)
    (executionAuthorizationHash : Nat)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket)
    (governance : GovernanceAdmission)
    (hRecon :
      reconcileGovernance sources.stateGovernance sources.inputGovernance =
        some governance) :
    signedRegistryExecutionMetadataPacketFromConcreteInputs
        policyHash
        policyRef
        stateHash
        stateRef
        sources
        executionAuthorizationHash
        signedRegistryBridge =
      some {
        executionAuthorization := {
          executionAuthorization := {
            policyHash := policyHash
            policyRef := policyRef
            stateHash := stateHash
            stateRef := stateRef
            governance := some governance
          }
          executionAuthorizationHash := executionAuthorizationHash
        }
        signedRegistryBridge := signedRegistryBridge
      } := by
  simp [signedRegistryExecutionMetadataPacketFromConcreteInputs,
    executionAuthorizationMetadataPacketFromConcreteInputs, hRecon]

end MPRDRegistryGovernanceExecutionMetadataCompiler

abbrev concrete_registry_governance_inputs_compile_exact_signed_registry_execution_metadata_packet_v1 :=
  @MPRDRegistryGovernanceExecutionMetadataCompiler.concrete_inputs_compile_exact_signed_registry_execution_metadata_packet
