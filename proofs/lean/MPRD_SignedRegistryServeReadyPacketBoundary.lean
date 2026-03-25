/- 
  MPRD_SignedRegistryServeReadyPacketBoundary.lean

  A lightweight top-level model for the shipped signed-registry `mprd serve`
  path after the `ExecutionReadyPacketV1` grouping:

    executing through the production serve path requires the signed-registry
    serve-boundary facts and the grouped ready-packet admissions to be present
    together before the live `execute_ready` boundary can fire.
-/

namespace MPRDSignedRegistryServeReadyPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  registryAnchorValidated : Bool
  stateAnchorValidated : Bool
  policySelected : Bool
  productionVerifierBound : Bool
  bridgeInvoked : Bool
  registryResolved : Bool
  checkpointBound : Bool
  executionAuthorizationBound : Bool
  governanceAligned : Bool
  verified : Bool
  allowed : Bool
  bindingOk : Bool
  executorOk : Bool
  boundaryAdmitted : Bool
  signatureAdmitted : Bool
  stateProvenanceAdmitted : Bool
  replayAdmitted : Bool
  packetGrouped : Bool
  readyVisible : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.registryAnchorValidated = false ∧
    s.stateAnchorValidated = false ∧
      s.policySelected = false ∧
        s.productionVerifierBound = false ∧
          s.bridgeInvoked = false ∧
            s.registryResolved = false ∧
              s.checkpointBound = false ∧
                s.executionAuthorizationBound = false ∧
                  s.governanceAligned = false ∧
                    s.verified = false ∧
                      s.allowed = false ∧
                        s.bindingOk = false ∧
                          s.executorOk = false ∧
                            s.boundaryAdmitted = false ∧
                              s.signatureAdmitted = false ∧
                                s.stateProvenanceAdmitted = false ∧
                                  s.replayAdmitted = false ∧
                                    s.packetGrouped = false ∧
                                      s.readyVisible = false ∧
                                        s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def PacketGroupedImpliesSignedRegistryServeReadyPacketBoundary (s : State) : Prop :=
  s.packetGrouped = true ->
    s.registryAnchorValidated = true ∧
      s.stateAnchorValidated = true ∧
        s.policySelected = true ∧
          s.productionVerifierBound = true ∧
            s.bridgeInvoked = true ∧
              s.registryResolved = true ∧
                s.checkpointBound = true ∧
                  s.executionAuthorizationBound = true ∧
                    s.governanceAligned = true ∧
                      s.verified = true ∧
                        s.allowed = true ∧
                          s.bindingOk = true ∧
                            s.executorOk = true ∧
                              s.boundaryAdmitted = true ∧
                                s.signatureAdmitted = true ∧
                                  s.stateProvenanceAdmitted = true ∧
                                    s.replayAdmitted = true

def ExecutedImpliesSignedRegistryServeReadyPacketBoundary (s : State) : Prop :=
  Executed s ->
    s.packetGrouped = true ∧
      s.readyVisible = true ∧
        s.registryAnchorValidated = true ∧
          s.stateAnchorValidated = true ∧
            s.policySelected = true ∧
              s.productionVerifierBound = true ∧
                s.bridgeInvoked = true ∧
                  s.registryResolved = true ∧
                    s.checkpointBound = true ∧
                      s.executionAuthorizationBound = true ∧
                        s.governanceAligned = true ∧
                          s.verified = true ∧
                            s.allowed = true ∧
                              s.bindingOk = true ∧
                                s.executorOk = true ∧
                                  s.boundaryAdmitted = true ∧
                                    s.signatureAdmitted = true ∧
                                      s.stateProvenanceAdmitted = true ∧
                                        s.replayAdmitted = true

inductive Step : State -> State -> Prop
  | validate_registry_anchor (s : State) :
      s.registryAnchorValidated = false ->
      s.exec = .skipped ->
      Step s { s with registryAnchorValidated := true }
  | validate_state_anchor (s : State) :
      s.stateAnchorValidated = false ->
      s.exec = .skipped ->
      Step s { s with stateAnchorValidated := true }
  | select_policy (s : State) :
      s.registryAnchorValidated = true ->
      s.policySelected = false ->
      s.exec = .skipped ->
      Step s { s with policySelected := true }
  | bind_production_verifier (s : State) :
      s.registryAnchorValidated = true ->
      s.productionVerifierBound = false ->
      s.exec = .skipped ->
      Step s { s with productionVerifierBound := true }
  | invoke_ready_bridge (s : State) :
      s.stateAnchorValidated = true ->
      s.policySelected = true ->
      s.productionVerifierBound = true ->
      s.bridgeInvoked = false ->
      s.exec = .skipped ->
      Step s { s with bridgeInvoked := true }
  | set_registry_resolved (s : State) :
      s.bridgeInvoked = true ->
      s.registryResolved = false ->
      s.exec = .skipped ->
      Step s { s with registryResolved := true }
  | bind_checkpoint (s : State) :
      s.bridgeInvoked = true ->
      s.registryResolved = true ->
      s.checkpointBound = false ->
      s.exec = .skipped ->
      Step s { s with checkpointBound := true }
  | bind_execution_authorization (s : State) :
      s.bridgeInvoked = true ->
      s.registryResolved = true ->
      s.executionAuthorizationBound = false ->
      s.exec = .skipped ->
      Step s { s with executionAuthorizationBound := true }
  | align_governance (s : State) :
      s.bridgeInvoked = true ->
      s.governanceAligned = false ->
      s.exec = .skipped ->
      Step s { s with governanceAligned := true }
  | set_verified (s : State) :
      s.bridgeInvoked = true ->
      s.verified = false ->
      s.exec = .skipped ->
      Step s { s with verified := true }
  | set_allowed (s : State) :
      s.bridgeInvoked = true ->
      s.allowed = false ->
      s.exec = .skipped ->
      Step s { s with allowed := true }
  | set_binding_ok (s : State) :
      s.bridgeInvoked = true ->
      s.bindingOk = false ->
      s.exec = .skipped ->
      Step s { s with bindingOk := true }
  | set_executor_ok (s : State) :
      s.bridgeInvoked = true ->
      s.executorOk = false ->
      s.exec = .skipped ->
      Step s { s with executorOk := true }
  | admit_boundary (s : State) :
      s.executionAuthorizationBound = true ->
      s.boundaryAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with boundaryAdmitted := true }
  | admit_signature (s : State) :
      s.boundaryAdmitted = true ->
      s.signatureAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with signatureAdmitted := true }
  | admit_state_provenance (s : State) :
      s.boundaryAdmitted = true ->
      s.stateProvenanceAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with stateProvenanceAdmitted := true }
  | admit_replay (s : State) :
      s.boundaryAdmitted = true ->
      s.replayAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with replayAdmitted := true }
  | group_packet (s : State) :
      s.registryAnchorValidated = true ->
      s.stateAnchorValidated = true ->
      s.policySelected = true ->
      s.productionVerifierBound = true ->
      s.bridgeInvoked = true ->
      s.registryResolved = true ->
      s.checkpointBound = true ->
      s.executionAuthorizationBound = true ->
      s.governanceAligned = true ->
      s.verified = true ->
      s.allowed = true ->
      s.bindingOk = true ->
      s.executorOk = true ->
      s.boundaryAdmitted = true ->
      s.signatureAdmitted = true ->
      s.stateProvenanceAdmitted = true ->
      s.replayAdmitted = true ->
      s.packetGrouped = false ->
      s.exec = .skipped ->
      Step s { s with packetGrouped := true }
  | expose_ready (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = false ->
      s.exec = .skipped ->
      Step s { s with readyVisible := true }
  | execute_success (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = true ->
      s.exec = .skipped ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = true ->
      s.exec = .skipped ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_packet_grouped_implies_signed_registry_serve_ready_packet_boundary {s : State}
    (hInit : Initial s) : PacketGroupedImpliesSignedRegistryServeReadyPacketBoundary s := by
  intro hGrouped
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, _hResolved,
      _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed, _hBinding,
      _hExecutor, _hBoundary, _hSignature, _hStateProv, _hReplay, hGrouped0,
      _hReady, _hExec⟩
  cases hGrouped.symm.trans hGrouped0

theorem step_preserves_packet_grouped_implies_signed_registry_serve_ready_packet_boundary
    {s t : State} (hStep : Step s t)
    (hInv : PacketGroupedImpliesSignedRegistryServeReadyPacketBoundary s) :
    PacketGroupedImpliesSignedRegistryServeReadyPacketBoundary t := by
  intro hGrouped
  cases hStep with
  | validate_registry_anchor _ _ =>
      rcases hInv hGrouped with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨rfl, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | validate_state_anchor _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, _hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, rfl, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | select_policy hRegistryAnchor _ _ =>
      rcases hInv hGrouped with
        ⟨_hRegistryAnchor, hStateAnchor, _hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, rfl, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | bind_production_verifier hRegistryAnchor _ _ =>
      rcases hInv hGrouped with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, _hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, rfl, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | invoke_ready_bridge hStateAnchor hPolicy hVerifier _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, rfl, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | set_registry_resolved hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, rfl,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | bind_checkpoint hBridge hResolved _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          _hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        rfl, hAuth, hGovernance, hVerified, hAllowed, hBinding, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | bind_execution_authorization hBridge hResolved _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, _hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, rfl, hGovernance, hVerified, hAllowed, hBinding, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | align_governance hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, _hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, rfl, hVerified, hAllowed, hBinding, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | set_verified hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, _hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, rfl, hAllowed, hBinding, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | set_allowed hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, _hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, rfl, hBinding, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | set_binding_ok hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, _hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, rfl, hExecutor,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | set_executor_ok hBridge _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          _hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding, rfl,
        hBoundary, hSignature, hStateProv, hReplay⟩
  | admit_boundary hAuth _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, _hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, _hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, rfl, hSignature, hStateProv, hReplay⟩
  | admit_signature hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, _hBoundary, _hSignature, hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, rfl, hStateProv, hReplay⟩
  | admit_state_provenance hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, _hBoundary, hSignature, _hStateProv, hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, rfl, hReplay⟩
  | admit_replay hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, _hBoundary, hSignature, hStateProv, _hReplay⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, rfl⟩
  | group_packet hRegistryAnchor hStateAnchor hPolicy hVerifier hBridge hResolved
      hCheckpoint hAuth hGovernance hVerified hAllowed hBinding hExecutor
      hBoundary hSignature hStateProv hReplay _ _ =>
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
        hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
  | expose_ready hPacket _ _ =>
      exact hInv hPacket
  | execute_success hPacket _ _ =>
      exact hInv hPacket
  | execute_failed hPacket _ _ =>
      exact hInv hPacket
  | stutter =>
      exact hInv hGrouped

theorem reachable_packet_grouped_states_require_signed_registry_serve_ready_packet_boundary :
    ∀ {s : State}, Reachable s -> PacketGroupedImpliesSignedRegistryServeReadyPacketBoundary s
  | _, .init hInit =>
      initial_packet_grouped_implies_signed_registry_serve_ready_packet_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_packet_grouped_implies_signed_registry_serve_ready_packet_boundary hStep
        (reachable_packet_grouped_states_require_signed_registry_serve_ready_packet_boundary hReach)

theorem initial_executed_implies_signed_registry_serve_ready_packet_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesSignedRegistryServeReadyPacketBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, _hResolved,
      _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed, _hBinding,
      _hExecutor, _hBoundary, _hSignature, _hStateProv, _hReplay, _hGrouped,
      _hReady, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_signed_registry_serve_ready_packet_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesSignedRegistryServeReadyPacketBoundary s) :
    ExecutedImpliesSignedRegistryServeReadyPacketBoundary t := by
  intro hExecuted
  cases hStep with
  | validate_registry_anchor _ hExec
  | validate_state_anchor _ hExec
  | select_policy _ _ hExec
  | bind_production_verifier _ _ hExec
  | invoke_ready_bridge _ _ _ _ hExec
  | set_registry_resolved _ _ hExec
  | bind_checkpoint _ _ _ hExec
  | bind_execution_authorization _ _ _ hExec
  | align_governance _ _ hExec
  | set_verified _ _ hExec
  | set_allowed _ _ hExec
  | set_binding_ok _ _ hExec
  | set_executor_ok _ _ hExec
  | admit_boundary _ _ hExec
  | admit_signature _ _ hExec
  | admit_state_provenance _ _ hExec
  | admit_replay _ _ hExec
  | group_packet _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hExec
  | expose_ready _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hPacket hReady _ =>
      rcases reachable_packet_grouped_states_require_signed_registry_serve_ready_packet_boundary hReach hPacket with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier,
        hBridge, hResolved, hCheckpoint, hAuth, hGovernance, hVerified,
        hAllowed, hBinding, hExecutor, hBoundary, hSignature, hStateProv,
        hReplay⟩
  | execute_failed hPacket hReady _ =>
      rcases reachable_packet_grouped_states_require_signed_registry_serve_ready_packet_boundary hReach hPacket with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hBinding,
          hExecutor, hBoundary, hSignature, hStateProv, hReplay⟩
      exact ⟨hPacket, hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier,
        hBridge, hResolved, hCheckpoint, hAuth, hGovernance, hVerified,
        hAllowed, hBinding, hExecutor, hBoundary, hSignature, hStateProv,
        hReplay⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_signed_registry_serve_ready_packet_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesSignedRegistryServeReadyPacketBoundary s
  | _, .init hInit =>
      initial_executed_implies_signed_registry_serve_ready_packet_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_signed_registry_serve_ready_packet_boundary hStep hReach
        (reachable_executed_states_require_signed_registry_serve_ready_packet_boundary hReach)

theorem executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
    s.packetGrouped = true ∧
      s.readyVisible = true ∧
        s.registryAnchorValidated = true ∧
          s.stateAnchorValidated = true ∧
            s.policySelected = true ∧
              s.productionVerifierBound = true ∧
                s.bridgeInvoked = true ∧
                  s.registryResolved = true ∧
                    s.checkpointBound = true ∧
                      s.executionAuthorizationBound = true ∧
                        s.governanceAligned = true ∧
                          s.verified = true ∧
                            s.allowed = true ∧
                              s.bindingOk = true ∧
                                s.executorOk = true ∧
                                  s.boundaryAdmitted = true ∧
                                    s.signatureAdmitted = true ∧
                                      s.stateProvenanceAdmitted = true ∧
                                        s.replayAdmitted = true := by
  exact reachable_executed_states_require_signed_registry_serve_ready_packet_boundary hReach hExec

end MPRDSignedRegistryServeReadyPacketBoundary

abbrev executed_reachable_states_require_signed_registry_serve_ready_packet_boundary_v1 :=
  @MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
