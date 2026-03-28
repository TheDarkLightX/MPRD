/- 
  MPRD_AttestationReadyExecutionAuthorizationBoundary.lean

  A lightweight local theorem for the narrowed attestation-ready boundary:

    once `prepare_attestation_ready(...)` succeeds, the grouped
    execution-authorization packet carried by `AttestationReadyBundle`
    is extensionally equal to the old loose policy/state/governance field tuple
    used for attestation stamping.

  This is intentionally narrower than a full runtime refinement proof. It
  closes the immediate trust gap around the refactor from loose-field stamping
  to grouped-packet stamping.
-/

namespace MPRDAttestationReadyExecutionAuthorizationBoundary

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

structure DecisionToken where
  policyHash : Nat
  policyRef : PolicyRef
  deriving Repr, DecidableEq

structure StateSnapshot where
  stateHash : Nat
  stateRef : StateRef
  deriving Repr, DecidableEq

structure ExecutionAuthorizationAttestation where
  policyHash : Nat
  policyRef : PolicyRef
  stateHash : Nat
  stateRef : StateRef
  governance : Option GovernanceAdmission
  deriving Repr, DecidableEq

abbrev ExecutionAuthorizationStampInput := ExecutionAuthorizationAttestation

structure AttestationReadyBundle where
  token : DecisionToken
  state : StateSnapshot
  governance : Option GovernanceAdmission
  executionAuthorization : ExecutionAuthorizationAttestation
  deriving Repr, DecidableEq

def executionAuthorizationAttestationFromLooseFields
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    ExecutionAuthorizationAttestation :=
  { policyHash := token.policyHash
    policyRef := token.policyRef
    stateHash := state.stateHash
    stateRef := state.stateRef
    governance := governance }

def executionAuthorizationStampInputFromLooseFields
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    ExecutionAuthorizationStampInput :=
  executionAuthorizationAttestationFromLooseFields token state governance

def executionAuthorizationStampInputFromPacket
    (packet : ExecutionAuthorizationAttestation) :
    ExecutionAuthorizationStampInput :=
  packet

def prepareAttestationReady
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    AttestationReadyBundle :=
  { token := token
    state := state
    governance := governance
    executionAuthorization :=
      executionAuthorizationAttestationFromLooseFields token state governance }

theorem prepare_attestation_ready_groups_exact_execution_authorization
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    (prepareAttestationReady token state governance).executionAuthorization =
      executionAuthorizationAttestationFromLooseFields token state governance := by
  rfl

theorem prepared_ready_bundle_preserves_exact_execution_authorization_fields
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    let ready := prepareAttestationReady token state governance
    ready.executionAuthorization.policyHash = token.policyHash ∧
      ready.executionAuthorization.policyRef = token.policyRef ∧
        ready.executionAuthorization.stateHash = state.stateHash ∧
          ready.executionAuthorization.stateRef = state.stateRef ∧
            ready.executionAuthorization.governance = governance := by
  simp [prepareAttestationReady, executionAuthorizationAttestationFromLooseFields]

theorem execution_authorization_stamp_input_from_packet_matches_loose_fields
    (token : DecisionToken)
    (state : StateSnapshot)
    (governance : Option GovernanceAdmission) :
    let ready := prepareAttestationReady token state governance
    executionAuthorizationStampInputFromPacket ready.executionAuthorization =
      executionAuthorizationStampInputFromLooseFields token state governance := by
  simp [prepareAttestationReady, executionAuthorizationStampInputFromPacket,
    executionAuthorizationStampInputFromLooseFields,
    executionAuthorizationAttestationFromLooseFields]

theorem ready_bundle_stamping_is_extensional_in_execution_authorization_packet
    (ready : AttestationReadyBundle)
    (hPacket :
      ready.executionAuthorization =
        executionAuthorizationAttestationFromLooseFields
          ready.token ready.state ready.governance) :
    executionAuthorizationStampInputFromPacket ready.executionAuthorization =
      executionAuthorizationStampInputFromLooseFields
        ready.token ready.state ready.governance := by
  simpa [executionAuthorizationStampInputFromPacket,
    executionAuthorizationStampInputFromLooseFields] using congrArg id hPacket

end MPRDAttestationReadyExecutionAuthorizationBoundary

abbrev prepare_attestation_ready_groups_exact_execution_authorization_v1 :=
  @MPRDAttestationReadyExecutionAuthorizationBoundary.prepare_attestation_ready_groups_exact_execution_authorization

abbrev execution_authorization_stamp_input_from_packet_matches_loose_fields_v1 :=
  @MPRDAttestationReadyExecutionAuthorizationBoundary.execution_authorization_stamp_input_from_packet_matches_loose_fields
