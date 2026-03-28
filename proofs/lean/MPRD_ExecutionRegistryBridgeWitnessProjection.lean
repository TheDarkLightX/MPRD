/- 
  MPRD_ExecutionRegistryBridgeWitnessProjection.lean

  A lightweight local theorem for the exact projection between:

    * the live `ExecutionRegistryBridgeWitnessV1` carried on the execute path, and
    * the grouped registry-bridge attestation packet language used for ready-packet
      hashing and audit.

  This closes the local seam where the bridge witness and the attestation/hash
  language were structurally equivalent but connected only by duplicated tuple
  wiring.
-/

namespace MPRDExecutionRegistryBridgeWitnessProjection

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure RegistryAuthorizationAttestation where
  resolutionHash : Nat
  execKindId : Nat
  execVersionId : Nat
  imageId : Nat
  policySourceKindId : Option Nat
  policySourceHash : Option Nat
  deriving Repr, DecidableEq

structure RegistryAuthorizationWitness where
  resolutionHash : Nat
  execKindId : Nat
  execVersionId : Nat
  imageId : Nat
  policySourceKindId : Option Nat
  policySourceHash : Option Nat
  deriving Repr, DecidableEq

structure ExecutionRegistryBridgeWitness where
  registryAuthorization : RegistryAuthorizationWitness
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

structure ExecutionRegistryBridgeAttestation where
  registryAuthorization : RegistryAuthorizationAttestation
  registryCheckpointAttestationHash : Option Nat
  deriving Repr, DecidableEq

def registryAuthorizationAttestationFromLooseFields
    (resolutionHash : Nat)
    (execKindId : Nat)
    (execVersionId : Nat)
    (imageId : Nat)
    (policySourceKindId : Option Nat)
    (policySourceHash : Option Nat) :
    RegistryAuthorizationAttestation :=
  { resolutionHash := resolutionHash
    execKindId := execKindId
    execVersionId := execVersionId
    imageId := imageId
    policySourceKindId := policySourceKindId
    policySourceHash := policySourceHash }

def registryAuthorizationAttestationFromWitness
    (authorization : RegistryAuthorizationWitness) :
    RegistryAuthorizationAttestation :=
  registryAuthorizationAttestationFromLooseFields
    authorization.resolutionHash
    authorization.execKindId
    authorization.execVersionId
    authorization.imageId
    authorization.policySourceKindId
    authorization.policySourceHash

def executionRegistryBridgeAttestationFromWitness
    (bridge : ExecutionRegistryBridgeWitness) :
    ExecutionRegistryBridgeAttestation :=
  { registryAuthorization :=
      registryAuthorizationAttestationFromWitness bridge.registryAuthorization
    registryCheckpointAttestationHash := bridge.registryCheckpointAttestationHash }

theorem registry_authorization_projection_matches_loose_tuple
    (authorization : RegistryAuthorizationWitness) :
    registryAuthorizationAttestationFromWitness authorization =
      registryAuthorizationAttestationFromLooseFields
        authorization.resolutionHash
        authorization.execKindId
        authorization.execVersionId
        authorization.imageId
        authorization.policySourceKindId
        authorization.policySourceHash := by
  rfl

theorem registry_authorization_projection_preserves_exact_fields
    (authorization : RegistryAuthorizationWitness) :
    let projected := registryAuthorizationAttestationFromWitness authorization
    projected.resolutionHash = authorization.resolutionHash ∧
      projected.execKindId = authorization.execKindId ∧
        projected.execVersionId = authorization.execVersionId ∧
          projected.imageId = authorization.imageId ∧
            projected.policySourceKindId = authorization.policySourceKindId ∧
              projected.policySourceHash = authorization.policySourceHash := by
  simp [registryAuthorizationAttestationFromWitness,
    registryAuthorizationAttestationFromLooseFields]

theorem execution_bridge_projection_preserves_checkpoint_and_registry_packet
    (bridge : ExecutionRegistryBridgeWitness) :
    let projected := executionRegistryBridgeAttestationFromWitness bridge
    projected.registryAuthorization =
      registryAuthorizationAttestationFromWitness bridge.registryAuthorization ∧
      projected.registryCheckpointAttestationHash =
        bridge.registryCheckpointAttestationHash := by
  simp [executionRegistryBridgeAttestationFromWitness]

end MPRDExecutionRegistryBridgeWitnessProjection

abbrev execution_registry_bridge_projection_preserves_checkpoint_and_registry_packet_v1 :=
  @MPRDExecutionRegistryBridgeWitnessProjection.execution_bridge_projection_preserves_checkpoint_and_registry_packet
