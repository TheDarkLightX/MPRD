/- 
  MPRD_ExecutionAuthorizationWitnessProjection.lean

  A lightweight local theorem for the exact projection between:

    * the live `ExecutionAuthorizationWitnessV1` carried on the execute path, and
    * the grouped `ExecutionAuthorizationAttestationV1` packet used for
      attestation stamping and audit.

  This closes the local seam where those two runtime objects were structurally
  equivalent but only connected by duplicated field wiring.
-/

namespace MPRDExecutionAuthorizationWitnessProjection

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

abbrev ExecutionAuthorizationStampInput := ExecutionAuthorizationAttestation

def executionAuthorizationAttestationFromLooseFields
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (governance : Option GovernanceAdmission) :
    ExecutionAuthorizationAttestation :=
  { policyHash := policyHash
    policyRef := policyRef
    stateHash := stateHash
    stateRef := stateRef
    governance := governance }

def executionAuthorizationAttestationFromWitness
    (authorization : ExecutionAuthorizationWitness) :
    ExecutionAuthorizationAttestation :=
  executionAuthorizationAttestationFromLooseFields
    authorization.policyAuthority.policyHash
    authorization.policyAuthority.policyRef
    authorization.stateBinding.stateHash
    authorization.stateBinding.stateRef
    authorization.governance

def executionAuthorizationStampInputFromWitness
    (authorization : ExecutionAuthorizationWitness) :
    ExecutionAuthorizationStampInput :=
  executionAuthorizationAttestationFromWitness authorization

def executionAuthorizationStampInputFromLooseFields
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateHash : Nat)
    (stateRef : StateRef)
    (governance : Option GovernanceAdmission) :
    ExecutionAuthorizationStampInput :=
  executionAuthorizationAttestationFromLooseFields
    policyHash policyRef stateHash stateRef governance

theorem witness_projection_preserves_exact_execution_authorization_fields
    (authorization : ExecutionAuthorizationWitness) :
    let projected := executionAuthorizationAttestationFromWitness authorization
    projected.policyHash = authorization.policyAuthority.policyHash ∧
      projected.policyRef = authorization.policyAuthority.policyRef ∧
        projected.stateHash = authorization.stateBinding.stateHash ∧
          projected.stateRef = authorization.stateBinding.stateRef ∧
            projected.governance = authorization.governance := by
  simp [executionAuthorizationAttestationFromWitness,
    executionAuthorizationAttestationFromLooseFields]

theorem witness_projection_matches_loose_field_packet
    (authorization : ExecutionAuthorizationWitness) :
    executionAuthorizationAttestationFromWitness authorization =
      executionAuthorizationAttestationFromLooseFields
        authorization.policyAuthority.policyHash
        authorization.policyAuthority.policyRef
        authorization.stateBinding.stateHash
        authorization.stateBinding.stateRef
        authorization.governance := by
  rfl

theorem witness_projection_matches_loose_field_stamp_input
    (authorization : ExecutionAuthorizationWitness) :
    executionAuthorizationStampInputFromWitness authorization =
      executionAuthorizationStampInputFromLooseFields
        authorization.policyAuthority.policyHash
        authorization.policyAuthority.policyRef
        authorization.stateBinding.stateHash
        authorization.stateBinding.stateRef
        authorization.governance := by
  rfl

theorem extensional_stamp_inputs_agree_on_equal_authorization_packets
    (authorization : ExecutionAuthorizationWitness)
    (packet : ExecutionAuthorizationAttestation)
    (hEq : packet = executionAuthorizationAttestationFromWitness authorization) :
    packet = executionAuthorizationStampInputFromWitness authorization := by
  simpa [executionAuthorizationStampInputFromWitness] using hEq

end MPRDExecutionAuthorizationWitnessProjection

abbrev execution_authorization_witness_projection_matches_loose_field_stamp_input_v1 :=
  @MPRDExecutionAuthorizationWitnessProjection.witness_projection_matches_loose_field_stamp_input
