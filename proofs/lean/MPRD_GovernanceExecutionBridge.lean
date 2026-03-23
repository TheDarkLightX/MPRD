/- 
  MPRD_GovernanceExecutionBridge.lean

  A lightweight cross-slice bridge model for MPRD:

    execution-time governance_ok may only become true after both a live policy
    has been resolved and the local governance update has been admitted.
-/

namespace MPRDGovernanceExecutionBridge

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  policyResolved : Bool
  governanceAdmitted : Bool
  governanceOk : Bool
  verified : Bool
  allowed : Bool
  replayOk : Bool
  bindingOk : Bool
  executorOk : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.policyResolved = false ∧
    s.governanceAdmitted = false ∧
      s.governanceOk = false ∧
        s.verified = false ∧
          s.allowed = false ∧
            s.replayOk = false ∧
              s.bindingOk = false ∧
                s.executorOk = false ∧
                  s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def GovernanceOkImpliesBridgeSources (s : State) : Prop :=
  s.governanceOk = true ->
    s.policyResolved = true ∧ s.governanceAdmitted = true

def ExecutedImpliesBridgeSources (s : State) : Prop :=
  Executed s ->
    s.governanceOk = true ∧
      s.policyResolved = true ∧
        s.governanceAdmitted = true

inductive Step : State -> State -> Prop
  | set_policy_resolved (s : State) :
      s.policyResolved = false ->
      s.exec = .skipped ->
      Step s { s with policyResolved := true }
  | set_governance_admitted (s : State) :
      s.governanceAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with governanceAdmitted := true }
  | bridge_governance_ok (s : State) :
      s.policyResolved = true ->
      s.governanceAdmitted = true ->
      s.governanceOk = false ->
      s.exec = .skipped ->
      Step s { s with governanceOk := true }
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
  | execute_success (s : State) :
      s.exec = .skipped ->
      s.governanceOk = true ->
      s.verified = true ->
      s.allowed = true ->
      s.replayOk = true ->
      s.bindingOk = true ->
      s.executorOk = true ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.exec = .skipped ->
      s.governanceOk = true ->
      s.verified = true ->
      s.allowed = true ->
      s.replayOk = true ->
      s.bindingOk = true ->
      s.executorOk = true ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_governance_ok_implies_bridge_sources {s : State}
    (hInit : Initial s) : GovernanceOkImpliesBridgeSources s := by
  intro hGov
  rcases hInit with ⟨_hResolved, _hAdmitted, hGov0, _hVerified, _hAllowed,
    _hReplay, _hBinding, _hExecutor, _hExec⟩
  cases hGov.symm.trans hGov0

theorem step_preserves_governance_ok_implies_bridge_sources
    {s t : State} (hStep : Step s t) (hInv : GovernanceOkImpliesBridgeSources s) :
    GovernanceOkImpliesBridgeSources t := by
  intro hGov
  cases hStep with
  | set_policy_resolved _ _ =>
      rcases hInv hGov with ⟨_hResolved, hAdmitted⟩
      exact ⟨rfl, hAdmitted⟩
  | set_governance_admitted _ _ =>
      rcases hInv hGov with ⟨hResolved, _hAdmitted⟩
      exact ⟨hResolved, rfl⟩
  | bridge_governance_ok hResolved hAdmitted _hGovFalse _hExec =>
      exact ⟨hResolved, hAdmitted⟩
  | set_verified _ _ =>
      exact hInv hGov
  | set_allowed _ _ =>
      exact hInv hGov
  | set_replay_ok _ _ =>
      exact hInv hGov
  | set_binding_ok _ _ =>
      exact hInv hGov
  | set_executor_ok _ _ =>
      exact hInv hGov
  | execute_success _ _ _ _ _ _ _ =>
      exact hInv hGov
  | execute_failed _ _ _ _ _ _ _ =>
      exact hInv hGov
  | stutter =>
      exact hInv hGov

theorem reachable_governance_ok_states_require_bridge_sources :
    ∀ {s : State}, Reachable s -> GovernanceOkImpliesBridgeSources s
  | _, .init hInit =>
      initial_governance_ok_implies_bridge_sources hInit
  | _, .step hReach hStep =>
      step_preserves_governance_ok_implies_bridge_sources hStep
        (reachable_governance_ok_states_require_bridge_sources hReach)

theorem initial_executed_implies_bridge_sources {s : State}
    (hInit : Initial s) : ExecutedImpliesBridgeSources s := by
  intro hExecuted
  rcases hInit with ⟨_hResolved, _hAdmitted, _hGov, _hVerified, _hAllowed,
    _hReplay, _hBinding, _hExecutor, hExec⟩
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
  | set_policy_resolved _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_governance_admitted _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | bridge_governance_ok _ _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_verified _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_allowed _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_replay_ok _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_binding_ok _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_executor_ok _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success _ hGov _hVerified _hAllowed _hReplay _hBinding _hExecutor =>
      rcases reachable_governance_ok_states_require_bridge_sources hReach hGov with
        ⟨hResolved, hAdmitted⟩
      exact ⟨hGov, hResolved, hAdmitted⟩
  | execute_failed _ hGov _hVerified _hAllowed _hReplay _hBinding _hExecutor =>
      rcases reachable_governance_ok_states_require_bridge_sources hReach hGov with
        ⟨hResolved, hAdmitted⟩
      exact ⟨hGov, hResolved, hAdmitted⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_bridge_sources :
    ∀ {s : State}, Reachable s -> ExecutedImpliesBridgeSources s
  | _, .init hInit =>
      initial_executed_implies_bridge_sources hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_bridge_sources hStep hReach
        (reachable_executed_states_require_bridge_sources hReach)

theorem governance_ok_reachable_states_require_bridge_sources
    {s : State} (hReach : Reachable s) :
    s.governanceOk = true -> s.policyResolved = true ∧ s.governanceAdmitted = true :=
  reachable_governance_ok_states_require_bridge_sources hReach

theorem executed_reachable_states_require_governance_bridge
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.governanceOk = true ∧
        s.policyResolved = true ∧
          s.governanceAdmitted = true :=
  reachable_executed_states_require_bridge_sources hReach

end MPRDGovernanceExecutionBridge

abbrev executed_reachable_states_require_governance_bridge_v1 :=
  @MPRDGovernanceExecutionBridge.executed_reachable_states_require_governance_bridge
