/- 
  MPRD_SignedRegistryServeBoundary.lean

  A lightweight top-level model for the shipped signed-registry `mprd serve`
  path:

    executing through the production serve path requires validated registry and
    state anchors, explicit policy selection, production verifier binding,
    ready-bridge invocation, the signed-registry bridge facts, and the concrete
    execution guards before side effects can occur.
-/

namespace MPRDSignedRegistryServeBoundary

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
                                s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ReadyRebuiltImpliesSignedRegistryServeBoundary (s : State) : Prop :=
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
                              s.executorOk = true

def ExecutedImpliesSignedRegistryServeBoundary (s : State) : Prop :=
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
                                s.executorOk = true

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
      s.readyRebuilt = false ->
      s.exec = .skipped ->
      Step s { s with readyRebuilt := true }
  | execute_success (s : State) :
      s.readyRebuilt = true ->
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

theorem initial_ready_rebuilt_implies_signed_registry_serve_boundary {s : State}
    (hInit : Initial s) : ReadyRebuiltImpliesSignedRegistryServeBoundary s := by
  intro hReady
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge,
      _hResolved, _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed,
      _hReplay, _hBinding, _hExecutor, hReady0, _hExec⟩
  cases hReady.symm.trans hReady0

theorem step_preserves_ready_rebuilt_implies_signed_registry_serve_boundary
    {s t : State} (hStep : Step s t)
    (hInv : ReadyRebuiltImpliesSignedRegistryServeBoundary s) :
    ReadyRebuiltImpliesSignedRegistryServeBoundary t := by
  intro hReady
  cases hStep with
  | validate_registry_anchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨rfl, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | validate_state_anchor _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, _hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, rfl, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | select_policy hRegistryAnchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, _hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, rfl, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | bind_production_verifier hRegistryAnchor _ _ =>
      rcases hInv hReady with
        ⟨_hRegistryAnchor, hStateAnchor, hPolicy, _hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, rfl, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | invoke_ready_bridge hStateAnchor hPolicy hVerifier _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, rfl, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | set_registry_resolved hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, rfl,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
        hBinding, hExecutor⟩
  | bind_checkpoint hBridge hResolved _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          _hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        rfl, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor⟩
  | bind_execution_authorization hBridge hResolved _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, _hResolved,
          hCheckpoint, _hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, rfl, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor⟩
  | align_governance hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, _hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, rfl, hVerified, hAllowed, hReplay, hBinding,
        hExecutor⟩
  | set_verified hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, _hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, rfl, hAllowed, hReplay, hBinding,
        hExecutor⟩
  | set_allowed hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, _hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, rfl, hReplay, hBinding,
        hExecutor⟩
  | set_replay_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, _hReplay,
          hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, rfl, hBinding,
        hExecutor⟩
  | set_binding_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          _hBinding, hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, rfl,
        hExecutor⟩
  | set_executor_ok hBridge _ _ =>
      rcases hInv hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, _hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, _hExecutor⟩
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        rfl⟩
  | rebuild_ready hRegistryAnchor hStateAnchor hPolicy hVerifier hBridge hResolved
      hCheckpoint hAuth hGovernance hVerified hAllowed hReplay hBinding hExecutor _ _ =>
      exact ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
        hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding,
        hExecutor⟩
  | execute_success hReady0 _ =>
      exact hInv hReady0
  | execute_failed hReady0 _ =>
      exact hInv hReady0
  | stutter =>
      exact hInv hReady

theorem reachable_ready_rebuilt_states_require_signed_registry_serve_boundary :
    ∀ {s : State}, Reachable s -> ReadyRebuiltImpliesSignedRegistryServeBoundary s
  | _, .init hInit =>
      initial_ready_rebuilt_implies_signed_registry_serve_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_ready_rebuilt_implies_signed_registry_serve_boundary hStep
        (reachable_ready_rebuilt_states_require_signed_registry_serve_boundary hReach)

theorem initial_executed_implies_signed_registry_serve_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesSignedRegistryServeBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier, _hBridge, _hResolved,
      _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed, _hReplay,
      _hBinding, _hExecutor, _hReady, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_signed_registry_serve_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesSignedRegistryServeBoundary s) :
    ExecutedImpliesSignedRegistryServeBoundary t := by
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
  | rebuild_ready _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hReady _ =>
      rcases reachable_ready_rebuilt_states_require_signed_registry_serve_boundary hReach hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
        hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
        hReplay, hBinding, hExecutor⟩
  | execute_failed hReady _ =>
      rcases reachable_ready_rebuilt_states_require_signed_registry_serve_boundary hReach hReady with
        ⟨hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge, hResolved,
          hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay,
          hBinding, hExecutor⟩
      exact ⟨hReady, hRegistryAnchor, hStateAnchor, hPolicy, hVerifier, hBridge,
        hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed,
        hReplay, hBinding, hExecutor⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_signed_registry_serve_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesSignedRegistryServeBoundary s
  | _, .init hInit =>
      initial_executed_implies_signed_registry_serve_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_signed_registry_serve_boundary hStep hReach
        (reachable_executed_states_require_signed_registry_serve_boundary hReach)

theorem executed_reachable_states_require_signed_registry_serve_boundary
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
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
                                s.executorOk = true := by
  exact reachable_executed_states_require_signed_registry_serve_boundary hReach hExec

end MPRDSignedRegistryServeBoundary

abbrev executed_reachable_states_require_signed_registry_serve_boundary_v1 :=
  @MPRDSignedRegistryServeBoundary.executed_reachable_states_require_signed_registry_serve_boundary
