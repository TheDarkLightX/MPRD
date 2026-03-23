/-
  MPRD_GovernedPolicySource.lean

  A lightweight registry-bound model of the production rule:

    if Tau source bytes are the governed policy source-of-truth, a compiled
    execution artifact is admissible only when the verifier-trusted registry
    pins policy_ref, authorizes policy_hash, routes the allowed exec artifact,
    and carries a source-hash mapping.
-/

namespace MPRDGovernedPolicySource

def proof_bundle_version : String := "mprd-leanproofs-v7"

inductive ExecStatus where
  | skipped
  | executed
  deriving Repr, DecidableEq

structure State where
  tauSourceGoverned : Bool
  policyRefPinned : Bool
  policyAuthorized : Bool
  imageRouted : Bool
  sourceMapped : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.tauSourceGoverned = false ∧
    s.policyRefPinned = false ∧
      s.policyAuthorized = false ∧
        s.imageRouted = false ∧
          s.sourceMapped = false ∧
            s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .executed

def ExecutedImpliesRegistryBoundSourceGuard (s : State) : Prop :=
  Executed s ->
    s.policyRefPinned = true ∧
      s.policyAuthorized = true ∧
        s.imageRouted = true ∧
          (s.tauSourceGoverned = true -> s.sourceMapped = true)

inductive Step : State -> State -> Prop
  | choose_tau_source :
      Step
        { tauSourceGoverned := false, policyRefPinned := false, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := false, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
  | pin_plain_policy_ref :
      Step
        { tauSourceGoverned := false, policyRefPinned := false, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
  | pin_tau_policy_ref :
      Step
        { tauSourceGoverned := true, policyRefPinned := false, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
  | authorize_plain_policy :
      Step
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := true,
          imageRouted := false, sourceMapped := false, exec := .skipped }
  | authorize_tau_policy :
      Step
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := false,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := false, sourceMapped := false, exec := .skipped }
  | route_plain_image :
      Step
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := true,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := false, exec := .skipped }
  | route_tau_image :
      Step
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := false, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := false, exec := .skipped }
  | attach_tau_source_mapping :
      Step
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := true, exec := .skipped }
  | execute_plain :
      Step
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := false, exec := .skipped }
        { tauSourceGoverned := false, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := false, exec := .executed }
  | execute_tau :
      Step
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := true, exec := .skipped }
        { tauSourceGoverned := true, policyRefPinned := true, policyAuthorized := true,
          imageRouted := true, sourceMapped := true, exec := .executed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_registry_bound_source_guard {s : State} (hInit : Initial s) :
    ExecutedImpliesRegistryBoundSourceGuard s := by
  intro hExecuted
  rcases hInit with ⟨_hTau, hRef, _hAuth, _hImage, _hMap, hExec⟩
  cases hExecuted.symm.trans hExec

theorem step_preserves_executed_implies_registry_bound_source_guard {s t : State}
    (hStep : Step s t)
    (hInv : ExecutedImpliesRegistryBoundSourceGuard s) :
    ExecutedImpliesRegistryBoundSourceGuard t := by
  intro hExecuted
  cases hStep with
  | choose_tau_source =>
      cases hExecuted
  | pin_plain_policy_ref =>
      cases hExecuted
  | pin_tau_policy_ref =>
      cases hExecuted
  | authorize_plain_policy =>
      cases hExecuted
  | authorize_tau_policy =>
      cases hExecuted
  | route_plain_image =>
      cases hExecuted
  | route_tau_image =>
      cases hExecuted
  | attach_tau_source_mapping =>
      cases hExecuted
  | execute_plain =>
      exact ⟨rfl, rfl, rfl, by intro hTau; cases hTau⟩
  | execute_tau =>
      exact ⟨rfl, rfl, rfl, by intro _hTau; rfl⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_registry_bound_source_guard :
    ∀ {s : State}, Reachable s -> ExecutedImpliesRegistryBoundSourceGuard s
  | _, .init hInit =>
      initial_executed_implies_registry_bound_source_guard hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_registry_bound_source_guard hStep
        (reachable_executed_states_require_registry_bound_source_guard hReach)

theorem executed_reachable_states_require_registry_bound_source_guard
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.policyRefPinned = true ∧
        s.policyAuthorized = true ∧
          s.imageRouted = true ∧
            (s.tauSourceGoverned = true -> s.sourceMapped = true) :=
  reachable_executed_states_require_registry_bound_source_guard hReach

end MPRDGovernedPolicySource

abbrev executed_reachable_states_require_registry_bound_source_guard_v1 :=
  @MPRDGovernedPolicySource.executed_reachable_states_require_registry_bound_source_guard
