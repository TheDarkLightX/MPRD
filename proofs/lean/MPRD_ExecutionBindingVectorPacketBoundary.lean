/- 
  MPRD_ExecutionBindingVectorPacketBoundary.lean

  A lightweight local theorem for the grouped binding-vector packet:

    the grouped `ExecutionBindingVectorPacketV1` language is extensionally equal
    to a separate loose field-language carrying the same binding inputs used by
    `execution_binding_vector_hash_v1(...)`.

  This closes the local seam where the binding half of the abstract execution
  boundary was still reconstructed from a multi-argument runtime tuple, while
  keeping the claim scoped to the local field-language projection rather than
  the full validated Rust call surface.
-/

namespace MPRDExecutionBindingVectorPacketBoundary

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

structure ExecutionBindingVectorPacket where
  decisionCommitment : Nat
  policyHash : Nat
  policyRef : PolicyRef
  stateRef : StateRef
  stateHash : Nat
  candidateSetHash : Nat
  chosenActionHash : Nat
  nonceOrTxHash : Nat
  limitsHash : Nat
  deriving Repr, DecidableEq

structure ExecutionBindingVectorLooseFields where
  decisionCommitment : Nat
  policyHash : Nat
  policyRef : PolicyRef
  stateRef : StateRef
  stateHash : Nat
  candidateSetHash : Nat
  chosenActionHash : Nat
  nonceOrTxHash : Nat
  limitsHash : Nat
  deriving Repr, DecidableEq

def executionBindingVectorPacketFromLooseFields
    (decisionCommitment : Nat)
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateRef : StateRef)
    (stateHash : Nat)
    (candidateSetHash : Nat)
    (chosenActionHash : Nat)
    (nonceOrTxHash : Nat)
    (limitsHash : Nat) :
    ExecutionBindingVectorPacket :=
  { decisionCommitment := decisionCommitment
    policyHash := policyHash
    policyRef := policyRef
    stateRef := stateRef
    stateHash := stateHash
    candidateSetHash := candidateSetHash
    chosenActionHash := chosenActionHash
    nonceOrTxHash := nonceOrTxHash
    limitsHash := limitsHash }

def executionBindingVectorLooseFieldsFromFields
    (decisionCommitment : Nat)
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateRef : StateRef)
    (stateHash : Nat)
    (candidateSetHash : Nat)
    (chosenActionHash : Nat)
    (nonceOrTxHash : Nat)
    (limitsHash : Nat) :
    ExecutionBindingVectorLooseFields :=
  { decisionCommitment := decisionCommitment
    policyHash := policyHash
    policyRef := policyRef
    stateRef := stateRef
    stateHash := stateHash
    candidateSetHash := candidateSetHash
    chosenActionHash := chosenActionHash
    nonceOrTxHash := nonceOrTxHash
    limitsHash := limitsHash }

def executionBindingVectorPacketFromLooseTuple
    (tuple : ExecutionBindingVectorLooseFields) :
    ExecutionBindingVectorPacket :=
  { decisionCommitment := tuple.decisionCommitment
    policyHash := tuple.policyHash
    policyRef := tuple.policyRef
    stateRef := tuple.stateRef
    stateHash := tuple.stateHash
    candidateSetHash := tuple.candidateSetHash
    chosenActionHash := tuple.chosenActionHash
    nonceOrTxHash := tuple.nonceOrTxHash
    limitsHash := tuple.limitsHash }

theorem binding_vector_packet_matches_loose_tuple
    (decisionCommitment : Nat)
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateRef : StateRef)
    (stateHash : Nat)
    (candidateSetHash : Nat)
    (chosenActionHash : Nat)
    (nonceOrTxHash : Nat)
    (limitsHash : Nat) :
    executionBindingVectorPacketFromLooseFields
        decisionCommitment
        policyHash
        policyRef
        stateRef
        stateHash
        candidateSetHash
        chosenActionHash
        nonceOrTxHash
        limitsHash =
      executionBindingVectorPacketFromLooseTuple
        (executionBindingVectorLooseFieldsFromFields
          decisionCommitment
          policyHash
          policyRef
          stateRef
          stateHash
          candidateSetHash
          chosenActionHash
          nonceOrTxHash
          limitsHash) := by
  rfl

theorem binding_vector_packet_preserves_exact_fields
    (decisionCommitment : Nat)
    (policyHash : Nat)
    (policyRef : PolicyRef)
    (stateRef : StateRef)
    (stateHash : Nat)
    (candidateSetHash : Nat)
    (chosenActionHash : Nat)
    (nonceOrTxHash : Nat)
    (limitsHash : Nat) :
    let packet :=
      executionBindingVectorPacketFromLooseFields
        decisionCommitment
        policyHash
        policyRef
        stateRef
        stateHash
        candidateSetHash
        chosenActionHash
        nonceOrTxHash
        limitsHash
    packet.decisionCommitment = decisionCommitment ∧
      packet.policyHash = policyHash ∧
        packet.policyRef = policyRef ∧
          packet.stateRef = stateRef ∧
            packet.stateHash = stateHash ∧
              packet.candidateSetHash = candidateSetHash ∧
                packet.chosenActionHash = chosenActionHash ∧
                  packet.nonceOrTxHash = nonceOrTxHash ∧
                    packet.limitsHash = limitsHash := by
  simp [executionBindingVectorPacketFromLooseFields]

end MPRDExecutionBindingVectorPacketBoundary

abbrev execution_binding_vector_packet_matches_loose_tuple_v1 :=
  @MPRDExecutionBindingVectorPacketBoundary.binding_vector_packet_matches_loose_tuple
