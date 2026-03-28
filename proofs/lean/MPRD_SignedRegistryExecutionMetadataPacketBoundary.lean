/- 
  MPRD_SignedRegistryExecutionMetadataPacketBoundary.lean

  A lightweight local theorem for the grouped signed-registry execution
  metadata packet:

    the grouped `SignedRegistryExecutionMetadataPacketV1` language is
    extensionally equal to a separate loose two-field language carrying the
    exact execution-authorization metadata packet plus the exact
    signed-registry bridge metadata packet.

  This is intentionally narrower than a theorem about raw metadata maps or the
  top-level signed-registry refinement chain. It closes the local seam where
  the ready-bridge verifier still consumed those two grouped metadata packets as
  adjacent siblings by convention.
-/

namespace MPRDSignedRegistryExecutionMetadataPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure ExecutionAuthorizationMetadataPacket where
  executionAuthorizationHash : Nat
  deriving Repr, DecidableEq

structure SignedRegistryBridgeMetadataPacket where
  resolutionHash : Nat
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

structure SignedRegistryExecutionMetadataPacket where
  executionAuthorization : ExecutionAuthorizationMetadataPacket
  signedRegistryBridge : SignedRegistryBridgeMetadataPacket
  deriving Repr, DecidableEq

structure SignedRegistryExecutionMetadataLooseFields where
  executionAuthorization : ExecutionAuthorizationMetadataPacket
  signedRegistryBridge : SignedRegistryBridgeMetadataPacket
  deriving Repr, DecidableEq

def signedRegistryExecutionMetadataPacketFromLooseFields
    (executionAuthorization : ExecutionAuthorizationMetadataPacket)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket) :
    SignedRegistryExecutionMetadataPacket :=
  { executionAuthorization := executionAuthorization
    signedRegistryBridge := signedRegistryBridge }

def signedRegistryExecutionMetadataLooseFieldsFromFields
    (executionAuthorization : ExecutionAuthorizationMetadataPacket)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket) :
    SignedRegistryExecutionMetadataLooseFields :=
  { executionAuthorization := executionAuthorization
    signedRegistryBridge := signedRegistryBridge }

def signedRegistryExecutionMetadataPacketFromLooseTuple
    (tuple : SignedRegistryExecutionMetadataLooseFields) :
    SignedRegistryExecutionMetadataPacket :=
  { executionAuthorization := tuple.executionAuthorization
    signedRegistryBridge := tuple.signedRegistryBridge }

theorem signed_registry_execution_metadata_packet_matches_loose_tuple
    (executionAuthorization : ExecutionAuthorizationMetadataPacket)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket) :
    signedRegistryExecutionMetadataPacketFromLooseFields
        executionAuthorization
        signedRegistryBridge =
      signedRegistryExecutionMetadataPacketFromLooseTuple
        (signedRegistryExecutionMetadataLooseFieldsFromFields
          executionAuthorization
          signedRegistryBridge) := by
  rfl

theorem signed_registry_execution_metadata_packet_preserves_exact_fields
    (executionAuthorization : ExecutionAuthorizationMetadataPacket)
    (signedRegistryBridge : SignedRegistryBridgeMetadataPacket) :
    let packet :=
      signedRegistryExecutionMetadataPacketFromLooseFields
        executionAuthorization
        signedRegistryBridge
    packet.executionAuthorization = executionAuthorization ∧
      packet.signedRegistryBridge = signedRegistryBridge := by
  simp [signedRegistryExecutionMetadataPacketFromLooseFields]

end MPRDSignedRegistryExecutionMetadataPacketBoundary

abbrev signed_registry_execution_metadata_packet_matches_loose_tuple_v1 :=
  @MPRDSignedRegistryExecutionMetadataPacketBoundary.signed_registry_execution_metadata_packet_matches_loose_tuple

abbrev signed_registry_execution_metadata_packet_preserves_exact_fields_v1 :=
  @MPRDSignedRegistryExecutionMetadataPacketBoundary.signed_registry_execution_metadata_packet_preserves_exact_fields
