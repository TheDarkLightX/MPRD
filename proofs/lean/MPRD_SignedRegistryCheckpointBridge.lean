/- 
  MPRD_SignedRegistryCheckpointBridge.lean

  A lightweight bridge model for the current signed-registry execution path:

    on the signed-registry path, rebuilding the live ready bundle requires
    registry resolution, exact checkpoint binding, execution-authorization
    binding, and governance alignment before execution can occur.
-/

namespace MPRDSignedRegistryCheckpointBridge

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
  readyRebuilt : Bool
  verified : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.registryResolved = false ∧
    s.checkpointBound = false ∧
      s.executionAuthorizationBound = false ∧
        s.governanceAligned = false ∧
          s.readyRebuilt = false ∧
            s.verified = false ∧
              s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ReadyRebuiltImpliesBridgeSources (s : State) : Prop :=
  s.readyRebuilt = true ->
    s.registryResolved = true ∧
      s.checkpointBound = true ∧
        s.executionAuthorizationBound = true ∧
          s.governanceAligned = true

def ExecutedImpliesBridgeSources (s : State) : Prop :=
  Executed s ->
    s.readyRebuilt = true ∧
      s.verified = true ∧
        s.registryResolved = true ∧
          s.checkpointBound = true ∧
            s.executionAuthorizationBound = true ∧
              s.governanceAligned = true

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
  | rebuild_ready (s : State) :
      s.registryResolved = true ->
      s.checkpointBound = true ->
      s.executionAuthorizationBound = true ->
      s.governanceAligned = true ->
      s.readyRebuilt = false ->
      s.exec = .skipped ->
      Step s { s with readyRebuilt := true }
  | set_verified (s : State) :
      s.readyRebuilt = true ->
      s.verified = false ->
      s.exec = .skipped ->
      Step s { s with verified := true }
  | execute_success (s : State) :
      s.readyRebuilt = true ->
      s.verified = true ->
      s.exec = .skipped ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.readyRebuilt = true ->
      s.verified = true ->
      s.exec = .skipped ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_ready_rebuilt_implies_bridge_sources {s : State}
    (hInit : Initial s) : ReadyRebuiltImpliesBridgeSources s := by
  intro hReady
  rcases hInit with ⟨_hResolved, _hCheckpoint, _hAuth, _hGovernance, hReady0, _hVerified, _hExec⟩
  cases hReady.symm.trans hReady0

theorem step_preserves_ready_rebuilt_implies_bridge_sources
    {s t : State} (hStep : Step s t) (hInv : ReadyRebuiltImpliesBridgeSources s) :
    ReadyRebuiltImpliesBridgeSources t := by
  intro hReady
  cases hStep with
  | set_registry_resolved _ _ =>
      rcases hInv hReady with ⟨_hResolved, hCheckpoint, hAuth, hGovernance⟩
      exact ⟨rfl, hCheckpoint, hAuth, hGovernance⟩
  | bind_checkpoint hResolved _ _ =>
      rcases hInv hReady with ⟨_hResolved, _hCheckpoint, hAuth, hGovernance⟩
      exact ⟨hResolved, rfl, hAuth, hGovernance⟩
  | bind_execution_authorization hResolved _ _ =>
      rcases hInv hReady with ⟨_hResolved, hCheckpoint, _hAuth, hGovernance⟩
      exact ⟨hResolved, hCheckpoint, rfl, hGovernance⟩
  | align_governance _ _ =>
      rcases hInv hReady with ⟨hResolved, hCheckpoint, hAuth, _hGovernance⟩
      exact ⟨hResolved, hCheckpoint, hAuth, rfl⟩
  | rebuild_ready hResolved hCheckpoint hAuth hGovernance _ _ =>
      exact ⟨hResolved, hCheckpoint, hAuth, hGovernance⟩
  | set_verified _ _ _ =>
      exact hInv hReady
  | execute_success _ _ _ =>
      exact hInv hReady
  | execute_failed _ _ _ =>
      exact hInv hReady
  | stutter =>
      exact hInv hReady

theorem reachable_ready_rebuilt_states_require_bridge_sources :
    ∀ {s : State}, Reachable s -> ReadyRebuiltImpliesBridgeSources s
  | _, .init hInit =>
      initial_ready_rebuilt_implies_bridge_sources hInit
  | _, .step hReach hStep =>
      step_preserves_ready_rebuilt_implies_bridge_sources hStep
        (reachable_ready_rebuilt_states_require_bridge_sources hReach)

theorem initial_executed_implies_bridge_sources {s : State}
    (hInit : Initial s) : ExecutedImpliesBridgeSources s := by
  intro hExecuted
  rcases hInit with ⟨_hResolved, _hCheckpoint, _hAuth, _hGovernance, _hReady, _hVerified, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_bridge_sources
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesBridgeSources s) :
    ExecutedImpliesBridgeSources t := by
  intro hExecuted
  cases hStep with
  | set_registry_resolved _ hExec
  | bind_checkpoint _ _ hExec
  | bind_execution_authorization _ _ hExec
  | align_governance _ hExec
  | rebuild_ready _ _ _ _ _ hExec
  | set_verified _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hReady hVerified _ =>
      rcases reachable_ready_rebuilt_states_require_bridge_sources hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance⟩
      exact ⟨hReady, hVerified, hResolved, hCheckpoint, hAuth, hGovernance⟩
  | execute_failed hReady hVerified _ =>
      rcases reachable_ready_rebuilt_states_require_bridge_sources hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hGovernance⟩
      exact ⟨hReady, hVerified, hResolved, hCheckpoint, hAuth, hGovernance⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_bridge_sources :
    ∀ {s : State}, Reachable s -> ExecutedImpliesBridgeSources s
  | _, .init hInit =>
      initial_executed_implies_bridge_sources hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_bridge_sources hStep hReach
        (reachable_executed_states_require_bridge_sources hReach)

theorem executed_reachable_states_require_signed_registry_bridge
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
    s.readyRebuilt = true ∧
      s.verified = true ∧
        s.registryResolved = true ∧
          s.checkpointBound = true ∧
            s.executionAuthorizationBound = true ∧
              s.governanceAligned = true := by
  exact reachable_executed_states_require_bridge_sources hReach hExec

end MPRDSignedRegistryCheckpointBridge

abbrev executed_reachable_states_require_signed_registry_bridge_v1 :=
  @MPRDSignedRegistryCheckpointBridge.executed_reachable_states_require_signed_registry_bridge
