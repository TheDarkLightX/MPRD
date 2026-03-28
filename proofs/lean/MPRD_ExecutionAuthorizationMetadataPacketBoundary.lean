/- 
  MPRD_ExecutionAuthorizationMetadataPacketBoundary.lean

  A lightweight local theorem for the grouped execution-authorization metadata
  packet:

    the grouped `ExecutionAuthorizationMetadataPacketV1` language is
    extensionally equal to a separate loose two-field language carrying the
    exact `ExecutionAuthorizationAttestationV1` packet plus the canonical
    `execution_authorization_hash_v1` value reconstructed from metadata.

  This is intentionally narrower than a proof about hashing or raw metadata
  maps. It closes the local seam where the live metadata surface was still
  represented as an adjacent attestation packet plus hash by convention.
-/

namespace MPRDExecutionAuthorizationMetadataPacketBoundary

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

structure ExecutionAuthorizationMetadataLooseFields where
  executionAuthorization : ExecutionAuthorizationAttestation
  executionAuthorizationHash : Nat
  deriving Repr, DecidableEq

def executionAuthorizationMetadataPacketFromLooseFields
    (executionAuthorization : ExecutionAuthorizationAttestation)
    (executionAuthorizationHash : Nat) :
    ExecutionAuthorizationMetadataPacket :=
  { executionAuthorization := executionAuthorization
    executionAuthorizationHash := executionAuthorizationHash }

def executionAuthorizationMetadataLooseFieldsFromFields
    (executionAuthorization : ExecutionAuthorizationAttestation)
    (executionAuthorizationHash : Nat) :
    ExecutionAuthorizationMetadataLooseFields :=
  { executionAuthorization := executionAuthorization
    executionAuthorizationHash := executionAuthorizationHash }

def executionAuthorizationMetadataPacketFromLooseTuple
    (tuple : ExecutionAuthorizationMetadataLooseFields) :
    ExecutionAuthorizationMetadataPacket :=
  { executionAuthorization := tuple.executionAuthorization
    executionAuthorizationHash := tuple.executionAuthorizationHash }

theorem metadata_packet_matches_loose_tuple
    (executionAuthorization : ExecutionAuthorizationAttestation)
    (executionAuthorizationHash : Nat) :
    executionAuthorizationMetadataPacketFromLooseFields
        executionAuthorization
        executionAuthorizationHash =
      executionAuthorizationMetadataPacketFromLooseTuple
        (executionAuthorizationMetadataLooseFieldsFromFields
          executionAuthorization
          executionAuthorizationHash) := by
  rfl

theorem metadata_packet_preserves_exact_fields
    (executionAuthorization : ExecutionAuthorizationAttestation)
    (executionAuthorizationHash : Nat) :
    let packet :=
      executionAuthorizationMetadataPacketFromLooseFields
        executionAuthorization
        executionAuthorizationHash
    packet.executionAuthorization = executionAuthorization ∧
      packet.executionAuthorizationHash = executionAuthorizationHash := by
  simp [executionAuthorizationMetadataPacketFromLooseFields]

end MPRDExecutionAuthorizationMetadataPacketBoundary

abbrev execution_authorization_metadata_packet_matches_loose_tuple_v1 :=
  @MPRDExecutionAuthorizationMetadataPacketBoundary.metadata_packet_matches_loose_tuple
