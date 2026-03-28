/- 
  MPRD_SignedRegistryExecutionRefinementPacketBoundary.lean

  A lightweight local theorem for the grouped signed-registry execution
  refinement packet:

    the grouped `SignedRegistryExecutionRefinementPacketV1` language is
    extensionally equal to a separate loose four-field language carrying the
    exact grouped execution-ready packet, execution-binding-vector packet,
    execution-boundary refinement packet, and signed-registry execution
    metadata packet.

  This is intentionally narrower than a top-level runtime refinement theorem.
  It closes the local seam where those already-grouped subpackets still sat as
  adjacent siblings by convention on the signed-registry refinement lane.
-/

namespace MPRDSignedRegistryExecutionRefinementPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure ExecutionReadyPacket where
  boundaryHash : Nat
  authorizationHash : Option Nat
  bridgeHash : Option Nat
  executorAdmissionHash : Option Nat
  deriving Repr, DecidableEq

structure ExecutionBindingVectorPacket where
  bindingHash : Nat
  deriving Repr, DecidableEq

structure ExecutionBoundaryRefinementPacket where
  executionReadyPacketHash : Nat
  attestationMetadataHash : Nat
  deriving Repr, DecidableEq

structure ExecutionAuthorizationMetadataPacket where
  executionAuthorizationHash : Nat
  deriving Repr, DecidableEq

structure SignedRegistryBridgeMetadataPacket where
  registryAuthorizationHash : Nat
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

structure SignedRegistryExecutionMetadataPacket where
  executionAuthorization : ExecutionAuthorizationMetadataPacket
  signedRegistryBridge : SignedRegistryBridgeMetadataPacket
  deriving Repr, DecidableEq

structure SignedRegistryExecutionRefinementPacket where
  executionReady : ExecutionReadyPacket
  executionBindingVector : ExecutionBindingVectorPacket
  executionBoundaryRefinement : ExecutionBoundaryRefinementPacket
  signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket
  deriving Repr, DecidableEq

structure SignedRegistryExecutionRefinementLooseFields where
  executionReady : ExecutionReadyPacket
  executionBindingVector : ExecutionBindingVectorPacket
  executionBoundaryRefinement : ExecutionBoundaryRefinementPacket
  signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket
  deriving Repr, DecidableEq

def signedRegistryExecutionRefinementPacketFromLooseFields
    (executionReady : ExecutionReadyPacket)
    (executionBindingVector : ExecutionBindingVectorPacket)
    (executionBoundaryRefinement : ExecutionBoundaryRefinementPacket)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    SignedRegistryExecutionRefinementPacket :=
  { executionReady := executionReady
    executionBindingVector := executionBindingVector
    executionBoundaryRefinement := executionBoundaryRefinement
    signedRegistryExecutionMetadata := signedRegistryExecutionMetadata }

def signedRegistryExecutionRefinementLooseFieldsFromFields
    (executionReady : ExecutionReadyPacket)
    (executionBindingVector : ExecutionBindingVectorPacket)
    (executionBoundaryRefinement : ExecutionBoundaryRefinementPacket)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    SignedRegistryExecutionRefinementLooseFields :=
  { executionReady := executionReady
    executionBindingVector := executionBindingVector
    executionBoundaryRefinement := executionBoundaryRefinement
    signedRegistryExecutionMetadata := signedRegistryExecutionMetadata }

def signedRegistryExecutionRefinementPacketFromLooseTuple
    (tuple : SignedRegistryExecutionRefinementLooseFields) :
    SignedRegistryExecutionRefinementPacket :=
  { executionReady := tuple.executionReady
    executionBindingVector := tuple.executionBindingVector
    executionBoundaryRefinement := tuple.executionBoundaryRefinement
    signedRegistryExecutionMetadata := tuple.signedRegistryExecutionMetadata }

theorem signed_registry_execution_refinement_packet_matches_loose_tuple
    (executionReady : ExecutionReadyPacket)
    (executionBindingVector : ExecutionBindingVectorPacket)
    (executionBoundaryRefinement : ExecutionBoundaryRefinementPacket)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    signedRegistryExecutionRefinementPacketFromLooseFields
        executionReady
        executionBindingVector
        executionBoundaryRefinement
        signedRegistryExecutionMetadata =
      signedRegistryExecutionRefinementPacketFromLooseTuple
        (signedRegistryExecutionRefinementLooseFieldsFromFields
          executionReady
          executionBindingVector
          executionBoundaryRefinement
          signedRegistryExecutionMetadata) := by
  rfl

theorem signed_registry_execution_refinement_packet_preserves_exact_fields
    (executionReady : ExecutionReadyPacket)
    (executionBindingVector : ExecutionBindingVectorPacket)
    (executionBoundaryRefinement : ExecutionBoundaryRefinementPacket)
    (signedRegistryExecutionMetadata : SignedRegistryExecutionMetadataPacket) :
    let packet :=
      signedRegistryExecutionRefinementPacketFromLooseFields
        executionReady
        executionBindingVector
        executionBoundaryRefinement
        signedRegistryExecutionMetadata
    packet.executionReady = executionReady ∧
      packet.executionBindingVector = executionBindingVector ∧
      packet.executionBoundaryRefinement = executionBoundaryRefinement ∧
      packet.signedRegistryExecutionMetadata = signedRegistryExecutionMetadata := by
  simp [signedRegistryExecutionRefinementPacketFromLooseFields]

end MPRDSignedRegistryExecutionRefinementPacketBoundary

abbrev signed_registry_execution_refinement_packet_matches_loose_tuple_v1 :=
  @MPRDSignedRegistryExecutionRefinementPacketBoundary.signed_registry_execution_refinement_packet_matches_loose_tuple

abbrev signed_registry_execution_refinement_packet_preserves_exact_fields_v1 :=
  @MPRDSignedRegistryExecutionRefinementPacketBoundary.signed_registry_execution_refinement_packet_preserves_exact_fields
