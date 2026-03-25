/- 
  MPRD_SignedRegistryExecutionBoundary.lean

  A lightweight joined boundary model for the shipped signed-registry path:

    executing through the concrete signed-registry runtime path requires
    the signed-registry bridge facts plus the concrete execution guards
    (verified, allowed, replay, binding, executor).
-/

namespace MPRDSignedRegistryExecutionBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
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

def ReadyRebuiltImpliesSignedRegistryExecutionBoundary (s : State) : Prop :=
  s.readyRebuilt = true ->
    s.registryResolved = true ∧
      s.checkpointBound = true ∧
        s.executionAuthorizationBound = true ∧
          s.governanceAligned = true ∧
            s.verified = true ∧
              s.allowed = true ∧
                s.replayOk = true ∧
                  s.bindingOk = true ∧
                    s.executorOk = true

def ExecutedImpliesSignedRegistryExecutionBoundary (s : State) : Prop :=
  Executed s ->
    s.readyRebuilt = true ∧
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
  | set_registry_resolved (s : State) :
      s.registryResolved = false ->
      s.exec = .skipped ->
      Step s { s with registryResolved := true }
  | bind_checkpoint (s : State) :
      s.registryResolved = true ->
      s.checkpointBound = false ->
      s.exec = .skipped ->
      Step s { s with checkpointBound := true }
  | bind_execution_authorization (s : State) :
      s.registryResolved = true ->
      s.executionAuthorizationBound = false ->
      s.exec = .skipped ->
      Step s { s with executionAuthorizationBound := true }
  | align_governance (s : State) :
      s.governanceAligned = false ->
      s.exec = .skipped ->
      Step s { s with governanceAligned := true }
  | set_verified (s : State) :
      s.verified = false ->
      s.exec = .skipped ->
      Step s { s with verified := true }
  | set_allowed (s : State) :
      s.allowed = false ->
      s.exec = .skipped ->
      Step s { s with allowed := true }
  | set_replay_ok (s : State) :
      s.replayOk = false ->
      s.exec = .skipped ->
      Step s { s with replayOk := true }
  | set_binding_ok (s : State) :
      s.bindingOk = false ->
      s.exec = .skipped ->
      Step s { s with bindingOk := true }
  | set_executor_ok (s : State) :
      s.executorOk = false ->
      s.exec = .skipped ->
      Step s { s with executorOk := true }
  | rebuild_ready (s : State) :
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

theorem initial_ready_rebuilt_implies_signed_registry_execution_boundary {s : State}
    (hInit : Initial s) : ReadyRebuiltImpliesSignedRegistryExecutionBoundary s := by
  intro hReady
  rcases hInit with
    ⟨_hResolved, _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed,
      _hReplay, _hBinding, _hExecutor, hReady0, _hExec⟩
  cases hReady.symm.trans hReady0

theorem step_preserves_ready_rebuilt_implies_signed_registry_execution_boundary
    {s t : State} (hStep : Step s t)
    (hInv : ReadyRebuiltImpliesSignedRegistryExecutionBoundary s) :
    ReadyRebuiltImpliesSignedRegistryExecutionBoundary t := by
  intro hReady
  cases hStep with
  | set_registry_resolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨rfl, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | bind_checkpoint hResolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, _hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, rfl, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | bind_execution_authorization hResolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, hCheckpoint, _hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, rfl, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | align_governance _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, _hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, rfl, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | set_verified _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, _hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, rfl, hAllowed, hReplay, hBinding, hExecutor⟩
  | set_allowed _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, _hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, rfl, hReplay, hBinding, hExecutor⟩
  | set_replay_ok _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, _hReplay, hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, rfl, hBinding, hExecutor⟩
  | set_binding_ok _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, _hBinding, hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, rfl, hExecutor⟩
  | set_executor_ok _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, _hExecutor⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, rfl⟩
  | rebuild_ready hResolved hCheckpoint hAuth hGovernance hVerified hAllowed hReplay hBinding hExecutor _ _ =>
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | execute_success hReady0 _ =>
      exact hInv hReady0
  | execute_failed hReady0 _ =>
      exact hInv hReady0
  | stutter =>
      exact hInv hReady

theorem reachable_ready_rebuilt_states_require_signed_registry_execution_boundary :
    ∀ {s : State}, Reachable s -> ReadyRebuiltImpliesSignedRegistryExecutionBoundary s
  | _, .init hInit =>
      initial_ready_rebuilt_implies_signed_registry_execution_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_ready_rebuilt_implies_signed_registry_execution_boundary hStep
        (reachable_ready_rebuilt_states_require_signed_registry_execution_boundary hReach)

theorem initial_executed_implies_signed_registry_execution_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesSignedRegistryExecutionBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hResolved, _hCheckpoint, _hAuth, _hGovernance, _hVerified, _hAllowed,
      _hReplay, _hBinding, _hExecutor, _hReady, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_signed_registry_execution_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesSignedRegistryExecutionBoundary s) :
    ExecutedImpliesSignedRegistryExecutionBoundary t := by
  intro hExecuted
  cases hStep with
  | set_registry_resolved _ hExec
  | bind_checkpoint _ _ hExec
  | bind_execution_authorization _ _ hExec
  | align_governance _ hExec
  | set_verified _ hExec
  | set_allowed _ hExec
  | set_replay_ok _ hExec
  | set_binding_ok _ hExec
  | set_executor_ok _ hExec
  | rebuild_ready _ _ _ _ _ _ _ _ _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hReady _ =>
      rcases reachable_ready_rebuilt_states_require_signed_registry_execution_boundary hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hReady, hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | execute_failed hReady _ =>
      rcases reachable_ready_rebuilt_states_require_signed_registry_execution_boundary hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
      exact ⟨hReady, hResolved, hCheckpoint, hAuth, hGovernance, hVerified, hAllowed, hReplay, hBinding, hExecutor⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_signed_registry_execution_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesSignedRegistryExecutionBoundary s
  | _, .init hInit =>
      initial_executed_implies_signed_registry_execution_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_signed_registry_execution_boundary hStep hReach
        (reachable_executed_states_require_signed_registry_execution_boundary hReach)

theorem executed_reachable_states_require_signed_registry_execution_boundary
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
    s.readyRebuilt = true ∧
      s.registryResolved = true ∧
        s.checkpointBound = true ∧
          s.executionAuthorizationBound = true ∧
            s.governanceAligned = true ∧
              s.verified = true ∧
                s.allowed = true ∧
                  s.replayOk = true ∧
                    s.bindingOk = true ∧
                      s.executorOk = true := by
  exact reachable_executed_states_require_signed_registry_execution_boundary hReach hExec

end MPRDSignedRegistryExecutionBoundary

abbrev executed_reachable_states_require_signed_registry_execution_boundary_v1 :=
  @MPRDSignedRegistryExecutionBoundary.executed_reachable_states_require_signed_registry_execution_boundary
