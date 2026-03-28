/- 
  MPRD_SignedRegistryBridgeMetadataPacketBoundary.lean

  A lightweight local theorem for the grouped signed-registry bridge metadata
  packet:

    the grouped `SignedRegistryBridgeMetadataPacketV1` language is
    extensionally equal to a separate loose two-field language carrying the
    exact registry-authorization attestation packet plus the optional signed
    registry checkpoint attestation hash reconstructed from metadata.

  This is intentionally narrower than a proof about raw metadata maps or the
  registry hash functions themselves. It closes the local seam where the live
  signed-registry metadata surface was still represented as adjacent registry
  authorization and checkpoint facts by convention.
-/

namespace MPRDSignedRegistryBridgeMetadataPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure RegistryAuthorizationAttestationMetadata where
  resolutionHash : Nat
  execKindId : Nat
  execVersionId : Nat
  imageId : Nat
  policySourceKindId : Option Nat
  policySourceHash : Option Nat
  deriving Repr, DecidableEq

structure SignedRegistryBridgeMetadataPacket where
  registryAuthorization : RegistryAuthorizationAttestationMetadata
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

structure SignedRegistryBridgeMetadataLooseFields where
  registryAuthorization : RegistryAuthorizationAttestationMetadata
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

def signedRegistryBridgeMetadataPacketFromLooseFields
    (registryAuthorization : RegistryAuthorizationAttestationMetadata)
    (registryCheckpointAttestationHash : Option Nat) :
    SignedRegistryBridgeMetadataPacket :=
  { registryAuthorization := registryAuthorization
    registryCheckpointAttestationHash := registryCheckpointAttestationHash }

def signedRegistryBridgeMetadataLooseFieldsFromFields
    (registryAuthorization : RegistryAuthorizationAttestationMetadata)
    (registryCheckpointAttestationHash : Option Nat) :
    SignedRegistryBridgeMetadataLooseFields :=
  { registryAuthorization := registryAuthorization
    registryCheckpointAttestationHash := registryCheckpointAttestationHash }

def signedRegistryBridgeMetadataPacketFromLooseTuple
    (tuple : SignedRegistryBridgeMetadataLooseFields) :
    SignedRegistryBridgeMetadataPacket :=
  { registryAuthorization := tuple.registryAuthorization
    registryCheckpointAttestationHash := tuple.registryCheckpointAttestationHash }

theorem signed_registry_bridge_metadata_packet_matches_loose_tuple
    (registryAuthorization : RegistryAuthorizationAttestationMetadata)
    (registryCheckpointAttestationHash : Option Nat) :
    signedRegistryBridgeMetadataPacketFromLooseFields
        registryAuthorization
        registryCheckpointAttestationHash =
      signedRegistryBridgeMetadataPacketFromLooseTuple
        (signedRegistryBridgeMetadataLooseFieldsFromFields
          registryAuthorization
          registryCheckpointAttestationHash) := by
  rfl

theorem signed_registry_bridge_metadata_packet_preserves_exact_fields
    (registryAuthorization : RegistryAuthorizationAttestationMetadata)
    (registryCheckpointAttestationHash : Option Nat) :
    let packet :=
      signedRegistryBridgeMetadataPacketFromLooseFields
        registryAuthorization
        registryCheckpointAttestationHash
    packet.registryAuthorization = registryAuthorization ∧
      packet.registryCheckpointAttestationHash =
        registryCheckpointAttestationHash := by
  simp [signedRegistryBridgeMetadataPacketFromLooseFields]

end MPRDSignedRegistryBridgeMetadataPacketBoundary

abbrev signed_registry_bridge_metadata_packet_matches_loose_tuple_v1 :=
  @MPRDSignedRegistryBridgeMetadataPacketBoundary.signed_registry_bridge_metadata_packet_matches_loose_tuple

abbrev signed_registry_bridge_metadata_packet_preserves_exact_fields_v1 :=
  @MPRDSignedRegistryBridgeMetadataPacketBoundary.signed_registry_bridge_metadata_packet_preserves_exact_fields
