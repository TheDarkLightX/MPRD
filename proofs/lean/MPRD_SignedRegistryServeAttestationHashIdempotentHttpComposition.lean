/- 
  MPRD_SignedRegistryServeAttestationHashIdempotentHttpComposition.lean

  A lightweight concrete composition theorem for the strongest shipped remote
  effect lane:

    once the attestation-hash-strengthened signed-registry `mprd serve` path
    and the shipped `idempotent_http` sink are modeling the same successful
    execution, the composed state requires both the stronger serve
    attestation-hash facts and the concrete pending/committed HTTP barrier
    facts.
-/

import MPRD_SignedRegistryServeAttestationHashBoundary
import MPRD_SignedRegistryServeIdempotentHttpBoundary

namespace MPRDSignedRegistryServeAttestationHashIdempotentHttpComposition

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashBoundary.State
abbrev HttpState := MPRDSignedRegistryServeIdempotentHttpBoundary.State

def ExecCompatible
    (s : MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus)
    (h : MPRDSignedRegistryServeIdempotentHttpBoundary.ExecStatus) : Prop :=
  match s, h with
  | .skipped, .skipped => True
  | .succeeded, .succeeded => True
  | .failed, .failed => True
  | _, _ => False

def Compatible (s : ServeState) (h : HttpState) : Prop :=
  s.registryAnchorValidated = h.registryAnchorValidated ∧
    s.stateAnchorValidated = h.stateAnchorValidated ∧
      s.policySelected = h.policySelected ∧
        s.productionVerifierBound = h.productionVerifierBound ∧
          s.bridgeInvoked = h.bridgeInvoked ∧
            s.registryResolved = h.registryResolved ∧
              s.checkpointBound = h.checkpointBound ∧
                s.executionAuthorizationBound = h.executionAuthorizationBound ∧
                  s.governanceAligned = h.governanceAligned ∧
                    s.verified = h.verified ∧
                      s.allowed = h.allowed ∧
                        s.replayOk = h.replayOk ∧
                          s.bindingOk = h.bindingOk ∧
                            s.executorOk = h.executorOk ∧
                              s.readyRebuilt = h.readyRebuilt ∧
                                ExecCompatible s.exec h.exec

theorem exec_compatible_http_succeeded
    {s : MPRDSignedRegistryServeAttestationHashBoundary.ExecStatus}
    {h : MPRDSignedRegistryServeIdempotentHttpBoundary.ExecStatus}
    (hCompat : ExecCompatible s h)
    (hServeExec : s = .succeeded) :
    h = .succeeded := by
  cases hServeExec
  cases h <;> cases hCompat <;> rfl

theorem compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_http
    {s : ServeState} {h : HttpState}
    (hCompat : Compatible s h)
    (hReachServe : MPRDSignedRegistryServeAttestationHashBoundary.Reachable s)
    (hReachHttp : MPRDSignedRegistryServeIdempotentHttpBoundary.Reachable h)
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
                                          h.idempotentHttpSelected = true ∧
                                            h.effectJournalConfigured = true ∧
                                              h.pendingBarrierChecked = true ∧
                                                h.committedBarrierRecorded = true := by
  rcases hCompat with
    ⟨_hRegistryAnchorEq, _hStateAnchorEq, _hPolicyEq, _hVerifierEq, _hBridgeEq,
      _hResolvedEq, _hCheckpointEq, _hAuthEq, _hGovernanceEq, _hVerifiedEq,
      _hAllowedEq, _hReplayEq, _hBindingEq, _hExecutorEq, _hReadyEq,
      hExecCompat⟩
  have hHttpExec : h.exec = .succeeded := by
    exact exec_compatible_http_succeeded hExecCompat hServeExec
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
      MPRDSignedRegistryServeIdempotentHttpBoundary.succeeded_reachable_states_require_signed_registry_serve_idempotent_http_boundary
        hReachHttp hHttpExec with
    ⟨_hReadyHttp, _hRegistryAnchorHttp, _hStateAnchorHttp, _hPolicyHttp,
      _hVerifierHttp, _hBridgeHttp, _hResolvedHttp, _hCheckpointHttp,
      _hAuthHttp, _hGovernanceHttp, _hVerifiedHttp, _hAllowedHttp,
      _hReplayHttp, _hBindingHttp, _hExecutorHttp, hIdempotentHttp, hJournal,
      hPending, hCommitted⟩
  exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
    hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
    hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
    hReplay, hBinding, hExecutor, hIdempotentHttp, hJournal, hPending,
    hCommitted⟩

end MPRDSignedRegistryServeAttestationHashIdempotentHttpComposition

abbrev compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_http_v1 :=
  @MPRDSignedRegistryServeAttestationHashIdempotentHttpComposition.compatible_succeeded_reachable_states_require_signed_registry_serve_attestation_hash_idempotent_http
