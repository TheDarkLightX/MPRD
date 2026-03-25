/- 
  MPRD_SignedRegistryServeIdempotentHttpBoundary.lean

  A lightweight top-level model for the shipped signed-registry `mprd serve`
  path when the concrete side-effect sink is `idempotent_http`:

    successful remote execution through the production serve path requires the
    signed-registry serve-boundary facts, explicit `idempotent_http`
    selection, configured effect journal binding, a barrier check before the
    remote attempt, and a committed local effect barrier before success.
-/

namespace MPRDSignedRegistryServeIdempotentHttpBoundary

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
  replayOk : Bool
  bindingOk : Bool
  executorOk : Bool
  readyRebuilt : Bool
  idempotentHttpSelected : Bool
  effectJournalConfigured : Bool
  pendingBarrierChecked : Bool
  committedBarrierRecorded : Bool
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
                        s.replayOk = false ∧
                          s.bindingOk = false ∧
                            s.executorOk = false ∧
                              s.readyRebuilt = false ∧
                                s.idempotentHttpSelected = false ∧
                                  s.effectJournalConfigured = false ∧
                                    s.pendingBarrierChecked = false ∧
                                      s.committedBarrierRecorded = false ∧
                                        s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ReadyRebuiltImpliesSignedRegistryServeIdempotentHttpBoundary (s : State) : Prop :=
  s.readyRebuilt = true ->
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
                          s.replayOk = true ∧
                            s.bindingOk = true ∧
                              s.executorOk = true ∧
                                s.idempotentHttpSelected = true ∧
                                  s.effectJournalConfigured = true ∧
                                    s.pendingBarrierChecked = true

def ExecutedImpliesSignedRegistryServeIdempotentHttpBoundary (s : State) : Prop :=
  Executed s ->
    s.readyRebuilt = true ∧
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
                            s.replayOk = true ∧
                              s.bindingOk = true ∧
                                s.executorOk = true ∧
                                  s.idempotentHttpSelected = true ∧
                                    s.effectJournalConfigured = true ∧
                                      s.pendingBarrierChecked = true ∧
                                        (s.exec = .succeeded ->
                                          s.committedBarrierRecorded = true)

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
  | set_replay_ok (s : State) :
      s.bridgeInvoked = true ->
      s.replayOk = false ->
      s.exec = .skipped ->
      Step s { s with replayOk := true }
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
  | select_idempotent_http (s : State) :
      s.idempotentHttpSelected = false ->
      s.exec = .skipped ->
      Step s { s with idempotentHttpSelected := true }
  | configure_effect_journal (s : State) :
      s.idempotentHttpSelected = true ->
      s.effectJournalConfigured = false ->
      s.exec = .skipped ->
      Step s { s with effectJournalConfigured := true }
  | check_pending_barrier (s : State) :
      s.idempotentHttpSelected = true ->
      s.effectJournalConfigured = true ->
      s.pendingBarrierChecked = false ->
      s.exec = .skipped ->
      Step s { s with pendingBarrierChecked := true }
  | rebuild_ready (s : State) :
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
      s.replayOk = true ->
      s.bindingOk = true ->
      s.executorOk = true ->
      s.idempotentHttpSelected = true ->
      s.effectJournalConfigured = true ->
      s.pendingBarrierChecked = true ->
      s.readyRebuilt = false ->
      s.exec = .skipped ->
      Step s { s with readyRebuilt := true }
  | record_committed_barrier (s : State) :
      s.readyRebuilt = true ->
      s.pendingBarrierChecked = true ->
      s.committedBarrierRecorded = false ->
      s.exec = .skipped ->
      Step s { s with committedBarrierRecorded := true }
  | execute_success (s : State) :
      s.readyRebuilt = true ->
      s.committedBarrierRecorded = true ->
      s.exec = .skipped ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.readyRebuilt = true ->
      s.exec = .skipped ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_ready_rebuilt_implies_signed_registry_serve_idempotent_http_boundary {s : State}
    (hInit : Initial s) : ReadyRebuiltImpliesSignedRegistryServeIdempotentHttpBoundary s := by
  intro hReady
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, _hResolved,
      _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed, _hReplay,
      _hBinding, _hExecutor, hReady0, _hIdempotentHttp, _hJournal,
      _hPending, _hCommitted, _hExec⟩
  cases hReady.symm.trans hReady0

theorem step_preserves_ready_rebuilt_implies_signed_registry_serve_idempotent_http_boundary
    {s t : State} (hStep : Step s t)
    (hInv : ReadyRebuiltImpliesSignedRegistryServeIdempotentHttpBoundary s) :
    ReadyRebuiltImpliesSignedRegistryServeIdempotentHttpBoundary t := by
  intro hReady
  cases hStep with
  | validate_registry_anchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨rfl, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | validate_state_anchor _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, _hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, rfl, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | select_policy hRegistryAnchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, _hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, rfl, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | bind_production_verifier hRegistryAnchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, _hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, rfl, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | invoke_ready_bridge hStateAnchor hPolicy hVerifier _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, rfl, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_registry_resolved hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, rfl,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | bind_checkpoint hBridge hResolved _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          _hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        rfl, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | bind_execution_authorization hBridge hResolved _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, _hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, rfl, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | align_governance hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, _hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, rfl, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_verified hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, _hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, rfl, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_allowed hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, _hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, rfl, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_replay_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, _hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, rfl, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_binding_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          _hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, rfl,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | set_executor_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, _hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        rfl, hIdempotentHttp, hJournal, hPending⟩
  | select_idempotent_http _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, _hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, rfl, hJournal, hPending⟩
  | configure_effect_journal hIdempotentHttp _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, _hIdempotentHttp, _hJournal, hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, rfl, hPending⟩
  | check_pending_barrier hIdempotentHttp hJournal _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, _hIdempotentHttp, _hJournal, _hPending⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, rfl⟩
  | rebuild_ready hRegistryAnchor hStateAnchor hPolicy hVerifier hBridge hResolved
      hCheckpoint hAuth hGovernance hVerified hAllowed hReplay hBinding hExecutor
      hIdempotentHttp hJournal hPending _ _ =>
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor, hIdempotentHttp, hJournal, hPending⟩
  | record_committed_barrier hReady0 hPending _ _ =>
      exact hInv hReady0
  | execute_success hReady0 _ _ =>
      exact hInv hReady0
  | execute_failed hReady0 _ =>
      exact hInv hReady0
  | stutter =>
      exact hInv hReady

theorem reachable_ready_rebuilt_states_require_signed_registry_serve_idempotent_http_boundary :
    ∀ {s : State}, Reachable s -> ReadyRebuiltImpliesSignedRegistryServeIdempotentHttpBoundary s
  | _, .init hInit =>
      initial_ready_rebuilt_implies_signed_registry_serve_idempotent_http_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_ready_rebuilt_implies_signed_registry_serve_idempotent_http_boundary hStep
        (reachable_ready_rebuilt_states_require_signed_registry_serve_idempotent_http_boundary hReach)

theorem initial_executed_implies_signed_registry_serve_idempotent_http_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesSignedRegistryServeIdempotentHttpBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, _hResolved,
      _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed, _hReplay,
      _hBinding, _hExecutor, _hReady, _hIdempotentHttp, _hJournal,
      _hPending, _hCommitted, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_signed_registry_serve_idempotent_http_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesSignedRegistryServeIdempotentHttpBoundary s) :
    ExecutedImpliesSignedRegistryServeIdempotentHttpBoundary t := by
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
  | set_replay_ok _ _ hExec
  | set_binding_ok _ _ hExec
  | set_executor_ok _ _ hExec
  | select_idempotent_http _ hExec
  | configure_effect_journal _ _ hExec
  | check_pending_barrier _ _ _ hExec
  | rebuild_ready _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hExec
  | record_committed_barrier _ _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hReady hCommitted _ =>
      rcases
          reachable_ready_rebuilt_states_require_signed_registry_serve_idempotent_http_boundary
            hReach hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
        hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
        hReplay, hBinding, hExecutor, hIdempotentHttp, hJournal, hPending,
        by
          intro hSucceeded
          exact hCommitted⟩
  | execute_failed hReady _ =>
      rcases
          reachable_ready_rebuilt_states_require_signed_registry_serve_idempotent_http_boundary
            hReach hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor, hIdempotentHttp, hJournal, hPending⟩
      exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
        hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
        hReplay, hBinding, hExecutor, hIdempotentHttp, hJournal, hPending,
        by
          intro hSucceeded
          cases hSucceeded.symm.trans rfl⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_signed_registry_serve_idempotent_http_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesSignedRegistryServeIdempotentHttpBoundary s
  | _, .init hInit =>
      initial_executed_implies_signed_registry_serve_idempotent_http_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_signed_registry_serve_idempotent_http_boundary hStep hReach
        (reachable_executed_states_require_signed_registry_serve_idempotent_http_boundary hReach)

theorem succeeded_reachable_states_require_signed_registry_serve_idempotent_http_boundary
    {s : State} (hReach : Reachable s) (hExec : s.exec = .succeeded) :
    s.readyRebuilt = true ∧
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
                            s.replayOk = true ∧
                              s.bindingOk = true ∧
                                s.executorOk = true ∧
                                  s.idempotentHttpSelected = true ∧
                                    s.effectJournalConfigured = true ∧
                                      s.pendingBarrierChecked = true ∧
                                        s.committedBarrierRecorded = true := by
  have hExecuted : Executed s := Or.inl hExec
  rcases reachable_executed_states_require_signed_registry_serve_idempotent_http_boundary hReach hExecuted with
    ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
      hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
      hBinding, hExecutor, hIdempotentHttp, hJournal, hPending, hCommitted⟩
  exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
    hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
    hBinding, hExecutor, hIdempotentHttp, hJournal, hPending, hCommitted hExec⟩

end MPRDSignedRegistryServeIdempotentHttpBoundary

abbrev succeeded_reachable_states_require_signed_registry_serve_idempotent_http_boundary_v1 :=
  @MPRDSignedRegistryServeIdempotentHttpBoundary.succeeded_reachable_states_require_signed_registry_serve_idempotent_http_boundary
