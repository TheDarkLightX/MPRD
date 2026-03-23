/- 
  MPRD_GovernedSourceIntentBoundary.lean

  A lightweight model of the selected registry-bound / deploy strict boundary:

    declaring Tau as the intended source kind is not itself a governed-source
    proof. Until explicit source mapping exists, Tau-declared artifacts stay
    non-executable at the boundary.
-/

namespace MPRDGovernedSourceIntentBoundary

def proof_bundle_version : String := "mprd-leanproofs-v8"

inductive ExecStatus where
  | skipped
  | executed
  deriving Repr, DecidableEq

structure State where
  tauSourceIntentDeclared : Bool
  tauSourceGoverned : Bool
  policyRefPinned : Bool
  policyAuthorized : Bool
  imageRouted : Bool
  sourceMapped : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.tauSourceIntentDeclared = false ∧
    s.tauSourceGoverned = false ∧
      s.policyRefPinned = false ∧
        s.policyAuthorized = false ∧
          s.imageRouted = false ∧
            s.sourceMapped = false ∧
              s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .executed

def ExecutedImpliesIntentAwareRegistryBoundSourceGuard (s : State) : Prop :=
  Executed s ->
    s.policyRefPinned = true ∧
      s.policyAuthorized = true ∧
        s.imageRouted = true ∧
          (s.tauSourceGoverned = true -> s.tauSourceIntentDeclared = true) ∧
            (s.tauSourceGoverned = true -> s.sourceMapped = true) ∧
              (s.tauSourceIntentDeclared = true -> s.sourceMapped = true)

def TauGovernedImpliesTauIntent (s : State) : Prop :=
  s.tauSourceGoverned = true -> s.tauSourceIntentDeclared = true

inductive Step : State -> State -> Prop
  | declare_tau_intent (s : State) :
      s.tauSourceIntentDeclared = false ->
      s.exec = .skipped ->
      Step s { s with tauSourceIntentDeclared := true }
  | pin_policy_ref (s : State) :
      s.policyRefPinned = false ->
      s.exec = .skipped ->
      Step s { s with policyRefPinned := true }
  | authorize_policy (s : State) :
      s.policyRefPinned = true ->
      s.policyAuthorized = false ->
      s.exec = .skipped ->
      Step s { s with policyAuthorized := true }
  | route_image (s : State) :
      s.policyAuthorized = true ->
      s.imageRouted = false ->
      s.exec = .skipped ->
      Step s { s with imageRouted := true }
  | attach_tau_source_mapping (s : State) :
      s.tauSourceIntentDeclared = true ->
      s.imageRouted = true ->
      s.sourceMapped = false ->
      s.exec = .skipped ->
      Step s { s with tauSourceGoverned := true, sourceMapped := true }
  | execute_plain (s : State) :
      s.tauSourceIntentDeclared = false ->
      s.tauSourceGoverned = false ->
      s.policyRefPinned = true ->
      s.policyAuthorized = true ->
      s.imageRouted = true ->
      s.exec = .skipped ->
      Step s { s with exec := .executed }
  | execute_tau_intent_mapped (s : State) :
      s.tauSourceIntentDeclared = true ->
      s.tauSourceGoverned = true ->
      s.policyRefPinned = true ->
      s.policyAuthorized = true ->
      s.imageRouted = true ->
      s.sourceMapped = true ->
      s.exec = .skipped ->
      Step s { s with exec := .executed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_intent_aware_registry_bound_source_guard {s : State}
    (hInit : Initial s) : ExecutedImpliesIntentAwareRegistryBoundSourceGuard s := by
  intro hExecuted
  rcases hInit with ⟨_hIntent, _hGov, hRef, _hAuth, _hImage, _hMap, hExec⟩
  cases hExecuted.symm.trans hExec

theorem step_preserves_executed_implies_intent_aware_registry_bound_source_guard
    {s t : State} (hStep : Step s t)
    (hInv : ExecutedImpliesIntentAwareRegistryBoundSourceGuard s) :
    ExecutedImpliesIntentAwareRegistryBoundSourceGuard t := by
  intro hExecuted
  cases hStep with
  | declare_tau_intent hIntent hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | pin_policy_ref hRef hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | authorize_policy hRef hAuth hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | route_image hAuth hImage hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | attach_tau_source_mapping hIntent hImage hMap hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | execute_plain hIntent hGov hRef hAuth hImage hPending =>
      have hIntentFalse : ({ s with exec := .executed }).tauSourceIntentDeclared = false := by
        simpa using hIntent
      have hGovFalse : ({ s with exec := .executed }).tauSourceGoverned = false := by
        simpa using hGov
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa using hRef
      · simpa using hAuth
      · simpa using hImage
      · intro hGovTrue
        cases hGovFalse.symm.trans hGovTrue
      · intro hGovTrue
        cases hGovFalse.symm.trans hGovTrue
      · intro hIntentTrue
        cases hIntentFalse.symm.trans hIntentTrue
  | execute_tau_intent_mapped hIntent hGov hRef hAuth hImage hMap hPending =>
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa using hRef
      · simpa using hAuth
      · simpa using hImage
      · intro hGovTrue
        simpa using hIntent
      · intro hGovTrue
        simpa using hMap
      · intro hIntentTrue
        simpa using hMap
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_intent_aware_registry_bound_source_guard :
    ∀ {s : State}, Reachable s -> ExecutedImpliesIntentAwareRegistryBoundSourceGuard s
  | _, .init hInit =>
      initial_executed_implies_intent_aware_registry_bound_source_guard hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_intent_aware_registry_bound_source_guard hStep
        (reachable_executed_states_require_intent_aware_registry_bound_source_guard hReach)

theorem initial_tau_governed_implies_tau_intent {s : State} (hInit : Initial s) :
    TauGovernedImpliesTauIntent s := by
  intro hGov
  rcases hInit with ⟨_hIntent, hGoverned, _hRef, _hAuth, _hImage, _hMap, _hExec⟩
  cases hGoverned.symm.trans hGov

theorem step_preserves_tau_governed_implies_tau_intent {s t : State}
    (hStep : Step s t) (hInv : TauGovernedImpliesTauIntent s) :
    TauGovernedImpliesTauIntent t := by
  intro hGov
  cases hStep with
  | declare_tau_intent hIntent hPending =>
      rfl
  | pin_policy_ref hRef hPending =>
      simpa using hInv hGov
  | authorize_policy hRef hAuth hPending =>
      simpa using hInv hGov
  | route_image hAuth hImage hPending =>
      simpa using hInv hGov
  | attach_tau_source_mapping hIntent hImage hMap hPending =>
      simpa using hIntent
  | execute_plain hIntent hGovFalse hRef hAuth hImage hPending =>
      have : ({ s with exec := .executed }).tauSourceGoverned = false := by
        simpa using hGovFalse
      cases this.symm.trans hGov
  | execute_tau_intent_mapped hIntent hGovState hRef hAuth hImage hMap hPending =>
      simpa using hIntent
  | stutter =>
      exact hInv hGov

theorem reachable_tau_governed_states_require_tau_intent :
    ∀ {s : State}, Reachable s -> TauGovernedImpliesTauIntent s
  | _, .init hInit =>
      initial_tau_governed_implies_tau_intent hInit
  | _, .step hReach hStep =>
      step_preserves_tau_governed_implies_tau_intent hStep
        (reachable_tau_governed_states_require_tau_intent hReach)

theorem executed_reachable_states_require_intent_aware_registry_bound_source_guard
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.policyRefPinned = true ∧
        s.policyAuthorized = true ∧
          s.imageRouted = true ∧
            (s.tauSourceGoverned = true -> s.tauSourceIntentDeclared = true) ∧
              (s.tauSourceGoverned = true -> s.sourceMapped = true) ∧
                (s.tauSourceIntentDeclared = true -> s.sourceMapped = true) :=
  reachable_executed_states_require_intent_aware_registry_bound_source_guard hReach

theorem tau_governed_reachable_states_require_tau_intent
    {s : State} (hReach : Reachable s) :
    s.tauSourceGoverned = true -> s.tauSourceIntentDeclared = true :=
  reachable_tau_governed_states_require_tau_intent hReach

theorem reachable_tau_declared_without_mapping_states_stay_skipped
    {s : State} (hReach : Reachable s)
    (hIntent : s.tauSourceIntentDeclared = true)
    (hUnmapped : s.sourceMapped = false) :
    s.exec = .skipped := by
  cases hExec : s.exec with
  | skipped =>
      simp
  | executed =>
      have hGuard :=
        executed_reachable_states_require_intent_aware_registry_bound_source_guard hReach hExec
      rcases hGuard with ⟨_hRef, _hAuth, _hImage, _hGovIntent, _hGovMap, hIntentMap⟩
      have hMapped : s.sourceMapped = true := hIntentMap hIntent
      cases hUnmapped.symm.trans hMapped

end MPRDGovernedSourceIntentBoundary

abbrev executed_reachable_states_require_intent_aware_registry_bound_source_guard_v1 :=
  @MPRDGovernedSourceIntentBoundary.executed_reachable_states_require_intent_aware_registry_bound_source_guard

abbrev reachable_tau_declared_without_mapping_states_stay_skipped_v1 :=
  @MPRDGovernedSourceIntentBoundary.reachable_tau_declared_without_mapping_states_stay_skipped
