/- 
  MPRD_SelectorContractBinding.lean

  A lightweight selector-binding model for MPRD:

    execution requires the selected action to stay bound to both the
    chosen_index and the chosen_action_preimage, so runtime effects cannot
    drift to a different allowed action.
-/

namespace MPRDSelectorContractBinding

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  verified : Bool
  allowed : Bool
  governanceOk : Bool
  replayOk : Bool
  selectorIndexBindingOk : Bool
  selectorPreimageBindingOk : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.verified = false ∧
    s.allowed = false ∧
      s.governanceOk = false ∧
        s.replayOk = false ∧
          s.selectorIndexBindingOk = false ∧
            s.selectorPreimageBindingOk = false ∧
              s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ExecutedImpliesSelectorBoundary (s : State) : Prop :=
  Executed s ->
    s.verified = true ∧
      s.allowed = true ∧
        s.governanceOk = true ∧
          s.replayOk = true ∧
            s.selectorIndexBindingOk = true ∧
              s.selectorPreimageBindingOk = true

inductive Step : State -> State -> Prop
  | set_verified (s : State) :
      s.verified = false ->
      s.exec = .skipped ->
      Step s { s with verified := true }
  | set_allowed (s : State) :
      s.allowed = false ->
      s.exec = .skipped ->
      Step s { s with allowed := true }
  | set_governance_ok (s : State) :
      s.governanceOk = false ->
      s.exec = .skipped ->
      Step s { s with governanceOk := true }
  | set_replay_ok (s : State) :
      s.replayOk = false ->
      s.exec = .skipped ->
      Step s { s with replayOk := true }
  | set_selector_index_binding_ok (s : State) :
      s.selectorIndexBindingOk = false ->
      s.exec = .skipped ->
      Step s { s with selectorIndexBindingOk := true }
  | set_selector_preimage_binding_ok (s : State) :
      s.selectorPreimageBindingOk = false ->
      s.exec = .skipped ->
      Step s { s with selectorPreimageBindingOk := true }
  | execute_success (s : State) :
      s.exec = .skipped ->
      s.verified = true ->
      s.allowed = true ->
      s.governanceOk = true ->
      s.replayOk = true ->
      s.selectorIndexBindingOk = true ->
      s.selectorPreimageBindingOk = true ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.exec = .skipped ->
      s.verified = true ->
      s.allowed = true ->
      s.governanceOk = true ->
      s.replayOk = true ->
      s.selectorIndexBindingOk = true ->
      s.selectorPreimageBindingOk = true ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_selector_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesSelectorBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hVerified, _hAllowed, _hGovernance, _hReplay, _hSelectorIndex,
      _hSelectorPreimage, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_selector_boundary
    {s t : State} (hStep : Step s t) (hInv : ExecutedImpliesSelectorBoundary s) :
    ExecutedImpliesSelectorBoundary t := by
  intro hExecuted
  cases hStep with
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
  | set_governance_ok _ hExec =>
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
  | set_selector_index_binding_ok _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | set_selector_preimage_binding_ok _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success _ hVerified hAllowed hGovernance hReplay hSelectorIndex hSelectorPreimage =>
      exact ⟨hVerified, hAllowed, hGovernance, hReplay, hSelectorIndex, hSelectorPreimage⟩
  | execute_failed _ hVerified hAllowed hGovernance hReplay hSelectorIndex hSelectorPreimage =>
      exact ⟨hVerified, hAllowed, hGovernance, hReplay, hSelectorIndex, hSelectorPreimage⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_selector_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesSelectorBoundary s
  | _, .init hInit =>
      initial_executed_implies_selector_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_selector_boundary hStep
        (reachable_executed_states_require_selector_boundary hReach)

theorem executed_reachable_states_require_selector_bindings
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.selectorIndexBindingOk = true ∧ s.selectorPreimageBindingOk = true := by
  intro hExecuted
  exact
    ⟨(reachable_executed_states_require_selector_boundary hReach hExecuted).2.2.2.2.1,
      (reachable_executed_states_require_selector_boundary hReach hExecuted).2.2.2.2.2⟩

end MPRDSelectorContractBinding

abbrev executed_reachable_states_require_selector_bindings_v1 :=
  @MPRDSelectorContractBinding.executed_reachable_states_require_selector_bindings
