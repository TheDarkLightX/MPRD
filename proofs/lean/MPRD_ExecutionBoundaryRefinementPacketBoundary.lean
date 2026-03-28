/- 
  MPRD_ExecutionBoundaryRefinementPacketBoundary.lean

  A lightweight local theorem for the grouped refinement packet:

    the grouped `ExecutionBoundaryRefinementPacketV1` language is extensionally
    equal to a separate loose two-field language carrying the same
    `execution_ready_packet_hash` and `attestation_metadata_hash` inputs used by
    `execution_boundary_refinement_hash_v1(...)`.

  This closes the local seam where the top-level refinement artifact was still
  reconstructed from adjacent hashes by convention.
-/

namespace MPRDExecutionBoundaryRefinementPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure ExecutionBoundaryRefinementPacket where
  executionReadyPacketHash : Nat
  attestationMetadataHash : Nat
  deriving Repr, DecidableEq

structure ExecutionBoundaryRefinementLooseFields where
  executionReadyPacketHash : Nat
  attestationMetadataHash : Nat
  deriving Repr, DecidableEq

def executionBoundaryRefinementPacketFromLooseFields
    (executionReadyPacketHash : Nat)
    (attestationMetadataHash : Nat) :
    ExecutionBoundaryRefinementPacket :=
  { executionReadyPacketHash := executionReadyPacketHash
    attestationMetadataHash := attestationMetadataHash }

def executionBoundaryRefinementLooseFieldsFromFields
    (executionReadyPacketHash : Nat)
    (attestationMetadataHash : Nat) :
    ExecutionBoundaryRefinementLooseFields :=
  { executionReadyPacketHash := executionReadyPacketHash
    attestationMetadataHash := attestationMetadataHash }

def executionBoundaryRefinementPacketFromLooseTuple
    (tuple : ExecutionBoundaryRefinementLooseFields) :
    ExecutionBoundaryRefinementPacket :=
  { executionReadyPacketHash := tuple.executionReadyPacketHash
    attestationMetadataHash := tuple.attestationMetadataHash }

theorem refinement_packet_matches_loose_tuple
    (executionReadyPacketHash : Nat)
    (attestationMetadataHash : Nat) :
    executionBoundaryRefinementPacketFromLooseFields
        executionReadyPacketHash
        attestationMetadataHash =
      executionBoundaryRefinementPacketFromLooseTuple
        (executionBoundaryRefinementLooseFieldsFromFields
          executionReadyPacketHash
          attestationMetadataHash) := by
  rfl

theorem refinement_packet_preserves_exact_fields
    (executionReadyPacketHash : Nat)
    (attestationMetadataHash : Nat) :
    let packet :=
      executionBoundaryRefinementPacketFromLooseFields
        executionReadyPacketHash
        attestationMetadataHash
    packet.executionReadyPacketHash = executionReadyPacketHash ∧
      packet.attestationMetadataHash = attestationMetadataHash := by
  simp [executionBoundaryRefinementPacketFromLooseFields]

end MPRDExecutionBoundaryRefinementPacketBoundary

abbrev execution_boundary_refinement_packet_matches_loose_tuple_v1 :=
  @MPRDExecutionBoundaryRefinementPacketBoundary.refinement_packet_matches_loose_tuple
