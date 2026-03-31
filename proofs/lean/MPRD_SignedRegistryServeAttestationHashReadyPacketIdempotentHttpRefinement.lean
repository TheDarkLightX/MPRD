/- 
  MPRD_SignedRegistryServeAttestationHashReadyPacketIdempotentHttpRefinement.lean

  A lightweight top-level refinement theorem for the strongest shipped remote
  effect lane:

    when the richer attestation-hash-plus-ready-packet signed-registry
    `mprd serve` model and the shipped `idempotent_http` sink are modeling the
    same successful execution, the composed state carries both:

      * the stronger serve facts plus the abstract execution-boundary witness,
        through the exact signed-registry packet refinement lane, and
      * the concrete pending/committed HTTP barrier facts.
-/

import MPRD_SignedRegistryServeAttestationHashExactPacketRefinement
import MPRD_SignedRegistryServeIdempotentHttpBoundary

namespace MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentHttpRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState :=
  MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.State
abbrev HttpState := MPRDSignedRegistryServeIdempotentHttpBoundary.State
abbrev packetViewOfServeState :=
  MPRDSignedRegistryServeAttestationHashExactPacketRefinement.packetViewOfServeState
abbrev artifactOfServeState :=
  MPRDSignedRegistryServeAttestationHashExactPacketRefinement.artifactOfServeState

abbrev runtimeWitnessOfServeState (s : ServeState) :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness
    (MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileExactPacket
      (artifactOfServeState s))

def ExecCompatible
    (s : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus)
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
                        s.replayAdmitted = h.replayOk ∧
                          s.bindingOk = h.bindingOk ∧
                            s.executorOk = h.executorOk ∧
                              s.readyVisible = h.readyRebuilt ∧
                                ExecCompatible s.exec h.exec

theorem exec_compatible_http_succeeded
    {s : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus}
    {h : MPRDSignedRegistryServeIdempotentHttpBoundary.ExecStatus}
    (hCompat : ExecCompatible s h)
    (hServeExec : s = .succeeded) :
    h = .succeeded := by
  cases hServeExec
  cases h <;> cases hCompat <;> rfl

theorem compatible_succeeded_reachable_states_refine_to_execution_boundary_and_idempotent_http_barrier
    {s : ServeState} {h : HttpState}
    (hCompat : Compatible s h)
    (hReachServe : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Reachable s)
    (hReachHttp : MPRDSignedRegistryServeIdempotentHttpBoundary.Reachable h)
    (hServeExec : s.exec = .succeeded) :
    s.packetGrouped = true ∧
      s.readyVisible = true ∧
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
                                      s.bindingOk = true ∧
                                        s.executorOk = true ∧
                                          (∃ t : MPRDExecutionBoundary.State,
                                            t.ctx.bindings = (runtimeWitnessOfServeState s).bindings ∧
                                              t.ctx.executorGate = (runtimeWitnessOfServeState s).executorGate ∧
                                                MPRDExecutionBoundary.Reachable t ∧
                                                  MPRDExecutionBoundary.Executed t ∧
                                                    MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) ∧
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
  have hServeExecuted :
      MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Executed s :=
    Or.inl hServeExec
  rcases
      MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_ready_packet_boundary
        hReachServe hServeExecuted with
    ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
      hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
      hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
      hBinding, hExecutor, _hBoundary, _hSignature, _hStateProv, _hReplay⟩
  rcases
      MPRDSignedRegistryServeAttestationHashExactPacketRefinement.executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
        hReachServe hServeExecuted with
    ⟨_hPacketReach, _hPacketExec,
      ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩⟩
  rcases
      MPRDSignedRegistryServeIdempotentHttpBoundary.succeeded_reachable_states_require_signed_registry_serve_idempotent_http_boundary
        hReachHttp hHttpExec with
    ⟨_hReadyHttp, _hRegistryAnchorHttp, _hStateAnchorHttp, _hPolicyHttp,
      _hVerifierHttp, _hBridgeHttp, _hResolvedHttp, _hCheckpointHttp,
      _hAuthHttp, _hGovernanceHttp, _hVerifiedHttp, _hAllowedHttp,
      _hReplayHttp, _hBindingHttp, _hExecutorHttp, hIdempotentHttp, hJournal,
      hPending, hCommitted⟩
  exact ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier,
    hBridge, hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
    hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
    hBinding, hExecutor,
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩,
    hIdempotentHttp, hJournal, hPending, hCommitted⟩

end MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentHttpRefinement

abbrev compatible_succeeded_reachable_states_refine_to_execution_boundary_and_idempotent_http_barrier_v1 :=
  @MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentHttpRefinement.compatible_succeeded_reachable_states_refine_to_execution_boundary_and_idempotent_http_barrier
