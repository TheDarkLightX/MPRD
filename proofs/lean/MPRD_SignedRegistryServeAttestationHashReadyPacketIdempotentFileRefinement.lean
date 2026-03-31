/- 
  MPRD_SignedRegistryServeAttestationHashReadyPacketIdempotentFileRefinement.lean

  A lightweight top-level refinement theorem for the strongest shipped local
  effect lane:

    when the richer attestation-hash-plus-ready-packet signed-registry
    `mprd serve` model and the shipped `idempotent_file` sink are modeling the
    same executed path, the composed state carries both:

      * the stronger serve facts plus the abstract execution-boundary witness,
        through the grouped signed-registry execution artifact lane and the
        smaller generic execute-ready artifact witness, and
      * the concrete durable local-file barrier facts.
-/

import MPRD_SignedRegistryServeAttestationHashArtifactBoundary
import MPRD_SignedRegistryServeIdempotentFileBoundary

namespace MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentFileRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState :=
  MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.State
abbrev FileState := MPRDSignedRegistryServeIdempotentFileBoundary.State
abbrev packetViewOfServeState :=
  MPRDSignedRegistryServeAttestationHashArtifactBoundary.packetViewOfServeState
abbrev artifactOfServeState :=
  MPRDSignedRegistryServeAttestationHashArtifactBoundary.artifactOfServeState

abbrev runtimeWitnessOfServeState (s : ServeState) :=
  MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness
    (artifactOfServeState s)

def ExecCompatible
    (s : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus)
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
                        s.replayAdmitted = f.replayOk ∧
                          s.bindingOk = f.bindingOk ∧
                            s.executorOk = f.executorOk ∧
                              s.readyVisible = f.readyRebuilt ∧
                                ExecCompatible s.exec f.exec

theorem exec_compatible_file_succeeded
    {s : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus}
    {f : MPRDSignedRegistryServeIdempotentFileBoundary.ExecStatus}
    (hCompat : ExecCompatible s f)
    (hServeExec : s = .succeeded) :
    f = .succeeded := by
  cases hServeExec
  cases f <;> cases hCompat <;> rfl

theorem exec_compatible_file_failed
    {s : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.ExecStatus}
    {f : MPRDSignedRegistryServeIdempotentFileBoundary.ExecStatus}
    (hCompat : ExecCompatible s f)
    (hServeExec : s = .failed) :
    f = .failed := by
  cases hServeExec
  cases f <;> cases hCompat <;> rfl

theorem compatible_executed_reachable_states_refine_to_execution_boundary_and_idempotent_file_barrier
    {s : ServeState} {f : FileState}
    (hCompat : Compatible s f)
    (hReachServe : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Reachable s)
    (hReachFile : MPRDSignedRegistryServeIdempotentFileBoundary.Reachable f)
    (hServeExec : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Executed s) :
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
                                            f.idempotentFileSelected = true ∧
                                              f.auditFileConfigured = true ∧
                                                (f.exec = .succeeded -> f.localFileBarrierRecorded = true) := by
  rcases hCompat with
    ⟨_hRegistryAnchorEq, _hStateAnchorEq, _hPolicyEq, _hVerifierEq, _hBridgeEq,
      _hResolvedEq, _hCheckpointEq, _hAuthEq, _hGovernanceEq, _hVerifiedEq,
      _hAllowedEq, _hReplayEq, _hBindingEq, _hExecutorEq, _hReadyEq,
      hExecCompat⟩
  have hFileExec :
      MPRDSignedRegistryServeIdempotentFileBoundary.Executed f := by
    cases hServeExec with
    | inl hSucc =>
        have : f.exec = .succeeded := by
          exact exec_compatible_file_succeeded hExecCompat hSucc
        exact Or.inl this
    | inr hFail =>
        have : f.exec = .failed := by
          exact exec_compatible_file_failed hExecCompat hFail
        exact Or.inr this
  rcases
      MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_ready_packet_boundary
        hReachServe hServeExec with
    ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
      hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
      hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
      hBinding, hExecutor, _hBoundary, _hSignature, _hStateProv, _hReplay⟩
  rcases
      MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_packet_view
        hReachServe hServeExec with
    ⟨hPacketReach, hPacketExec⟩
  rcases
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_generic_artifact_witness
        hPacketReach hPacketExec
        (MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_artifact_boundary
          hReachServe hServeExec) with
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
  rcases
      MPRDSignedRegistryServeIdempotentFileBoundary.executed_reachable_states_require_signed_registry_serve_idempotent_file_boundary
        hReachFile hFileExec with
    ⟨_hReadyFile, _hRegistryAnchorFile, _hStateAnchorFile, _hPolicyFile,
      _hVerifierFile, _hBridgeFile, _hResolvedFile, _hCheckpointFile,
      _hAuthFile, _hGovernanceFile, _hVerifiedFile, _hAllowedFile,
      _hReplayFile, _hBindingFile, _hExecutorFile, hIdempotentFile,
      hAuditFile, hLocalBarrier⟩
  exact ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier,
    hBridge, hResolved, hCheckpoint, hCheckpointHash, hAuth, hAuthHash,
    hRegistryAuthHash, hGovernance, hBridgeWitness, hVerified, hAllowed,
    hBinding, hExecutor,
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩,
    hIdempotentFile, hAuditFile, hLocalBarrier⟩

end MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentFileRefinement

abbrev compatible_executed_reachable_states_refine_to_execution_boundary_and_idempotent_file_barrier_v1 :=
  @MPRDSignedRegistryServeAttestationHashReadyPacketIdempotentFileRefinement.compatible_executed_reachable_states_refine_to_execution_boundary_and_idempotent_file_barrier
