/- 
  MPRD_SignedRegistryServeAttestationHashIdempotentFileComposition.lean

  A lightweight concrete composition theorem for the strongest shipped local
  effect lane:

    once the attestation-hash-strengthened signed-registry `mprd serve` path
    and the shipped `idempotent_file` sink are modeling the same successful
    execution, the composed state requires both the stronger serve
    attestation-hash facts and the concrete durable local-file barrier facts.
-/

import MPRD_SignedRegistryServeAttestationHashBoundary
import MPRD_SignedRegistryServeIdempotentFileBoundary

namespace MPRDSignedRegistryServeAttestationHashIdempotentFileComposition

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashBoundary.State
abbrev FileState := MPRDSignedRegistryServeIdempotentFileBoundary.State

def ExecCompatible
    (s : MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus)
    (f : MPRDSignedRegistryServeIdempotentFileBoundary.ExecStatus) : Prop :=
  match s, f with
  | .skipped, .skipped => True
  | .succeeded, .succeeded => True
  | .failed, .failed => True
  | _, _ => False

def Compatible (s : ServeState) (f : FileState) : Prop :=
  s.registryAnchorValidated = f.registryAnchorValidated ∧
    s.stateAnchorValidated = f.stateAnchorValidated ∧
      s.policySelected = f.policySelected ∧
        s.productionVerifierBound = f.productionVerifierBound ∧
          s.bridgeInvoked = f.bridgeInvoked ∧
            s.registryResolved = f.registryResolved ∧
              s.checkpointBound = f.checkpointBound ∧
                s.executionAuthorizationBound = f.executionAuthorizationBound ∧
                  s.governanceAligned = f.governanceAligned ∧
                    s.verified = f.verified ∧
                      s.allowed = f.allowed ∧
                        s.replayOk = f.replayOk ∧
                          s.bindingOk = f.bindingOk ∧
                            s.executorOk = f.executorOk ∧
                              s.readyRebuilt = f.readyRebuilt ∧
                                ExecCompatible s.exec f.exec

theorem exec_compatible_file_succeeded
    {s : MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus}
    {f : MPRDSignedRegistryServeIdempotentFileBoundary.ExecStatus}
    (hCompat : ExecCompatible s f)
    (hServeExec : s = .succeeded) :
    f = .succeeded := by
  cases hServeExec
  cases f <;> cases hCompat <;> rfl

theorem compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_file
    {s : ServeState} {f : FileState}
    (hCompat : Compatible s f)
    (hReachServe : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hReachFile : MPRDSignedRegistryServeIdempotentFileBoundary.Reachable f)
    (hServeExec : s.exec = .succeeded) :
    s.readyRebuilt = true ∧
      s.registryAnchorValidated = true ∧
        s.stateAnchorValidated = true ∧
          s.policySelected = true ∧
            s.productionVerifierBound = true ∧
              s.bridgeInvoked = true ∧
                s.registryResolved = true ∧
                  s.checkpointBound = true ∧
                    s.checkpointAttestationHashBound = true ∧
                      s.executionAuthorizationBound = true ∧
                        s.executionAuthorizationHashBound = true ∧
                          s.registryAuthorizationHashBound = true ∧
                            s.governanceAligned = true ∧
                              s.bridgeWitnessPreserved = true ∧
                                s.verified = true ∧
                                  s.allowed = true ∧
                                    s.replayOk = true ∧
                                      s.bindingOk = true ∧
                                        s.executorOk = true ∧
                                          f.idempotentFileSelected = true ∧
                                            f.auditFileConfigured = true ∧
                                              f.localFileBarrierRecorded = true := by
  rcases hCompat with
    ⟨_hRegistryAnchorEq, _hStateAnchorEq, _hPolicyEq, _hVerifierEq, _hBridgeEq,
      _hResolvedEq, _hCheckpointEq, _hAuthEq, _hGovernanceEq, _hVerifiedEq,
      _hAllowedEq, _hReplayEq, _hBindingEq, _hExecutorEq, _hReadyEq,
      hExecCompat⟩
  have hFileExec : f.exec = .succeeded := by
    exact exec_compatible_file_succeeded hExecCompat hServeExec
  have hFileExecuted : MPRDSignedRegistryServeIdempotentFileBoundary.Executed f :=
    Or.inl hFileExec
  have hServeExecuted : MPRDSignedRegistryServeAttestationHashBoundary.Executed s :=
    Or.inl hServeExec
  rcases
      MPRDSignedRegistryServeAttestationHashBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_boundary
        hReachServe hServeExecuted with
    ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
      hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
      hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
      hReplay, hBinding, hExecutor⟩
  rcases
      MPRDSignedRegistryServeIdempotentFileBoundary.executed_reachable_states_require_signed_registry_serve_idempotent_file_boundary
        hReachFile hFileExecuted with
    ⟨_hReadyFile, _hRegistryAnchorFile, _hStateAnchorFile, _hPolicyFile,
      _hVerifierFile, _hBridgeFile, _hResolvedFile, _hCheckpointFile,
      _hAuthFile, _hGovernanceFile, _hVerifiedFile, _hAllowedFile,
      _hReplayFile, _hBindingFile, _hExecutorFile, hIdempotentFile,
      hAuditFile, hLocalBarrier⟩
  exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
    hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
    hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
    hReplay, hBinding, hExecutor, hIdempotentFile, hAuditFile,
    hLocalBarrier hFileExec⟩

end MPRDSignedRegistryServeAttestationHashIdempotentFileComposition

abbrev compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_file_v1 :=
  @MPRDSignedRegistryServeAttestationHashIdempotentFileComposition.compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_file
