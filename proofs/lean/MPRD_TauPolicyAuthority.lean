/-
  MPRD_TauPolicyAuthority.lean

  A lightweight model of the architectural split:

    models propose, Tau decides, selector chooses, execution follows only
    the Tau-allowed choice.
-/

namespace MPRDTauPolicyAuthority

def proof_bundle_version : String := "mprd-leanproofs-v6"

inductive TauVerdict where
  | pending
  | allowed
  | denied
  deriving Repr, DecidableEq

inductive ExecStatus where
  | skipped
  | executed
  deriving Repr, DecidableEq

structure State where
  proposed : Bool
  tauVerdict : TauVerdict
  selected : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.proposed = false ∧ s.tauVerdict = .pending ∧ s.selected = false ∧ s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .executed

def ExecutedImpliesTauAuthority (s : State) : Prop :=
  Executed s ->
    s.proposed = true ∧
      s.tauVerdict = .allowed ∧
      s.selected = true

inductive Step : State -> State -> Prop
  | idle :
      Step
        { proposed := false, tauVerdict := .pending, selected := false, exec := .skipped }
        { proposed := false, tauVerdict := .pending, selected := false, exec := .skipped }
  | propose :
      Step
        { proposed := false, tauVerdict := .pending, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .pending, selected := false, exec := .skipped }
  | tau_pending_stay :
      Step
        { proposed := true, tauVerdict := .pending, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .pending, selected := false, exec := .skipped }
  | tau_allow :
      Step
        { proposed := true, tauVerdict := .pending, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .allowed, selected := false, exec := .skipped }
  | tau_deny :
      Step
        { proposed := true, tauVerdict := .pending, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .denied, selected := false, exec := .skipped }
  | tau_allowed_stay :
      Step
        { proposed := true, tauVerdict := .allowed, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .allowed, selected := false, exec := .skipped }
  | select_allowed :
      Step
        { proposed := true, tauVerdict := .allowed, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .allowed, selected := true, exec := .skipped }
  | tau_denied_stay :
      Step
        { proposed := true, tauVerdict := .denied, selected := false, exec := .skipped }
        { proposed := true, tauVerdict := .denied, selected := false, exec := .skipped }
  | execute_selected :
      Step
        { proposed := true, tauVerdict := .allowed, selected := true, exec := .skipped }
        { proposed := true, tauVerdict := .allowed, selected := true, exec := .executed }
  | executed_stay :
      Step
        { proposed := true, tauVerdict := .allowed, selected := true, exec := .executed }
        { proposed := true, tauVerdict := .allowed, selected := true, exec := .executed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_tau_authority {s : State} (hInit : Initial s) :
    ExecutedImpliesTauAuthority s := by
  intro hExecuted
  rcases hInit with ⟨hProposed, _hVerdict, hSelected, hExec⟩
  cases hExecuted.symm.trans hExec

theorem step_preserves_executed_implies_tau_authority {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesTauAuthority s) :
    ExecutedImpliesTauAuthority t := by
  intro hExecuted
  cases hStep with
  | idle =>
      cases hExecuted
  | propose =>
      cases hExecuted
  | tau_pending_stay =>
      cases hExecuted
  | tau_allow =>
      cases hExecuted
  | tau_deny =>
      cases hExecuted
  | tau_allowed_stay =>
      cases hExecuted
  | select_allowed =>
      cases hExecuted
  | tau_denied_stay =>
      cases hExecuted
  | execute_selected =>
      exact ⟨rfl, rfl, rfl⟩
  | executed_stay =>
      exact hInv hExecuted
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_tau_authority :
    ∀ {s : State}, Reachable s -> ExecutedImpliesTauAuthority s
  | _, .init hInit =>
      initial_executed_implies_tau_authority hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_tau_authority hStep
        (reachable_executed_states_require_tau_authority hReach)

theorem executed_reachable_states_require_tau_authority
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.proposed = true ∧
      s.tauVerdict = .allowed ∧
      s.selected = true :=
  reachable_executed_states_require_tau_authority hReach

end MPRDTauPolicyAuthority

abbrev executed_reachable_states_require_tau_authority_v1 :=
  @MPRDTauPolicyAuthority.executed_reachable_states_require_tau_authority
