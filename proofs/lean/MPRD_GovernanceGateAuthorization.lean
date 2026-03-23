/- 
  MPRD_GovernanceGateAuthorization.lean

  A lightweight model of the prepared governance gate boundary:

    governance admission is only allowed after a typed one-hot lane has been
    prepared, link_ok is true, and the matching profile thresholds hold for the
    chosen governance lane.
-/

namespace MPRDGovernanceGateAuthorization

def proof_bundle_version : String := "mprd-leanproofs-v10"

inductive GateResult where
  | pending
  | accepted
  | rejected
  deriving Repr, DecidableEq

structure State where
  isPolicyTweak : Bool
  isSafetyChange : Bool
  isCapExpand : Bool
  profileAppOk : Bool
  profileSafetyOk : Bool
  linkOk : Bool
  result : GateResult
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.isPolicyTweak = false ∧
    s.isSafetyChange = false ∧
      s.isCapExpand = false ∧
        s.profileAppOk = false ∧
          s.profileSafetyOk = false ∧
            s.linkOk = false ∧
              s.result = .pending

def Accepted (s : State) : Prop :=
  s.result = .accepted

def PreparedOneHot (s : State) : Prop :=
  (s.isPolicyTweak = true ∧ s.isSafetyChange = false ∧ s.isCapExpand = false) ∨
    (s.isPolicyTweak = false ∧ s.isSafetyChange = true ∧ s.isCapExpand = false) ∨
      (s.isPolicyTweak = false ∧ s.isSafetyChange = false ∧ s.isCapExpand = true)

def AcceptedImpliesPreparedGovernanceGuard (s : State) : Prop :=
  Accepted s ->
    PreparedOneHot s ∧
      s.linkOk = true ∧
        (s.isPolicyTweak = true -> s.profileAppOk = true) ∧
          (s.isSafetyChange = true -> s.profileSafetyOk = true) ∧
            (s.isCapExpand = true -> s.profileAppOk = true ∧ s.profileSafetyOk = true)

inductive Step : State -> State -> Prop
  | prepare_policy_tweak (s : State) :
      s.isPolicyTweak = false ->
      s.isSafetyChange = false ->
      s.isCapExpand = false ->
      s.result = .pending ->
      Step s { s with isPolicyTweak := true }
  | prepare_safety_change (s : State) :
      s.isPolicyTweak = false ->
      s.isSafetyChange = false ->
      s.isCapExpand = false ->
      s.result = .pending ->
      Step s { s with isSafetyChange := true }
  | prepare_cap_expand (s : State) :
      s.isPolicyTweak = false ->
      s.isSafetyChange = false ->
      s.isCapExpand = false ->
      s.result = .pending ->
      Step s { s with isCapExpand := true }
  | set_app_ok (s : State) :
      s.profileAppOk = false ->
      s.result = .pending ->
      Step s { s with profileAppOk := true }
  | set_safety_ok (s : State) :
      s.profileSafetyOk = false ->
      s.result = .pending ->
      Step s { s with profileSafetyOk := true }
  | set_link_ok (s : State) :
      s.linkOk = false ->
      s.result = .pending ->
      Step s { s with linkOk := true }
  | accept_policy_tweak (s : State) :
      s.isPolicyTweak = true ->
      s.isSafetyChange = false ->
      s.isCapExpand = false ->
      s.profileAppOk = true ->
      s.linkOk = true ->
      s.result = .pending ->
      Step s { s with result := .accepted }
  | accept_safety_change (s : State) :
      s.isPolicyTweak = false ->
      s.isSafetyChange = true ->
      s.isCapExpand = false ->
      s.profileSafetyOk = true ->
      s.linkOk = true ->
      s.result = .pending ->
      Step s { s with result := .accepted }
  | accept_cap_expand (s : State) :
      s.isPolicyTweak = false ->
      s.isSafetyChange = false ->
      s.isCapExpand = true ->
      s.profileAppOk = true ->
      s.profileSafetyOk = true ->
      s.linkOk = true ->
      s.result = .pending ->
      Step s { s with result := .accepted }
  | reject_invalid (s : State) :
      s.result = .pending ->
      ¬ PreparedOneHot s ->
      Step s { s with result := .rejected }
  | reject_missing_requirements (s : State) :
      s.result = .pending ->
      PreparedOneHot s ->
      s.linkOk = false ∨
        (s.isPolicyTweak = true ∧ s.profileAppOk = false) ∨
          (s.isSafetyChange = true ∧ s.profileSafetyOk = false) ∨
            (s.isCapExpand = true ∧
              (s.profileAppOk = false ∨ s.profileSafetyOk = false)) ->
      Step s { s with result := .rejected }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_accepted_implies_prepared_governance_guard {s : State}
    (hInit : Initial s) : AcceptedImpliesPreparedGovernanceGuard s := by
  intro hAccepted
  rcases hInit with ⟨_hPolicy, _hSafety, _hCap, _hApp, _hSafetyOk, _hLink, hResult⟩
  cases hAccepted.symm.trans hResult

theorem step_preserves_accepted_implies_prepared_governance_guard
    {s t : State} (hStep : Step s t) (hInv : AcceptedImpliesPreparedGovernanceGuard s) :
    AcceptedImpliesPreparedGovernanceGuard t := by
  intro hAccepted
  cases hStep with
  | prepare_policy_tweak _hPolicy _hSafety _hCap hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | prepare_safety_change _hPolicy _hSafety _hCap hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | prepare_cap_expand _hPolicy _hSafety _hCap hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | set_app_ok _hApp hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | set_safety_ok _hSafety hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | set_link_ok _hLink hPending =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | accept_policy_tweak hPolicy hSafety hCap hApp hLink hPending =>
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · exact Or.inl ⟨by simpa using hPolicy, by simpa using hSafety, by simpa using hCap⟩
      · simpa using hLink
      · intro _hPolicyTrue
        simpa using hApp
      · intro hSafetyTrue
        cases hSafety.symm.trans hSafetyTrue
      · intro hCapTrue
        cases hCap.symm.trans hCapTrue
  | accept_safety_change hPolicy hSafety hCap hSafetyOk hLink hPending =>
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · exact Or.inr <| Or.inl ⟨by simpa using hPolicy, by simpa using hSafety, by simpa using hCap⟩
      · simpa using hLink
      · intro hPolicyTrue
        cases hPolicy.symm.trans hPolicyTrue
      · intro _hSafetyTrue
        simpa using hSafetyOk
      · intro hCapTrue
        cases hCap.symm.trans hCapTrue
  | accept_cap_expand hPolicy hSafety hCap hApp hSafetyOk hLink hPending =>
      refine ⟨?_, ?_, ?_, ?_, ?_⟩
      · exact Or.inr <| Or.inr ⟨by simpa using hPolicy, by simpa using hSafety, by simpa using hCap⟩
      · simpa using hLink
      · intro hPolicyTrue
        cases hPolicy.symm.trans hPolicyTrue
      · intro hSafetyTrue
        cases hSafety.symm.trans hSafetyTrue
      · intro _hCapTrue
        exact ⟨by simpa using hApp, by simpa using hSafetyOk⟩
  | reject_invalid hPending _hNotOneHot =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | reject_missing_requirements hPending _hOneHot _hMissing =>
      have : s.result = .accepted := by
        simpa [Accepted] using hAccepted
      cases hPending.symm.trans this
  | stutter =>
      exact hInv hAccepted

theorem reachable_accepted_states_require_prepared_governance_guard :
    ∀ {s : State}, Reachable s -> AcceptedImpliesPreparedGovernanceGuard s
  | _, .init hInit =>
      initial_accepted_implies_prepared_governance_guard hInit
  | _, .step hReach hStep =>
      step_preserves_accepted_implies_prepared_governance_guard hStep
        (reachable_accepted_states_require_prepared_governance_guard hReach)

theorem accepted_reachable_states_require_prepared_governance_guard
    {s : State} (hReach : Reachable s) :
    Accepted s ->
      PreparedOneHot s ∧
        s.linkOk = true ∧
          (s.isPolicyTweak = true -> s.profileAppOk = true) ∧
            (s.isSafetyChange = true -> s.profileSafetyOk = true) ∧
              (s.isCapExpand = true -> s.profileAppOk = true ∧ s.profileSafetyOk = true) :=
  reachable_accepted_states_require_prepared_governance_guard hReach

theorem accepted_reachable_states_require_link_ok
    {s : State} (hReach : Reachable s) :
    Accepted s -> s.linkOk = true := by
  intro hAccepted
  exact (accepted_reachable_states_require_prepared_governance_guard hReach hAccepted).2.1

theorem reachable_unprepared_states_are_not_accepted
    {s : State} (hReach : Reachable s) :
    ¬ PreparedOneHot s -> s.result ≠ .accepted := by
  intro hNotPrepared hAccepted
  have hGuard :=
    accepted_reachable_states_require_prepared_governance_guard hReach (by simpa [Accepted] using hAccepted)
  exact hNotPrepared hGuard.1

end MPRDGovernanceGateAuthorization

abbrev accepted_reachable_states_require_prepared_governance_guard_v1 :=
  @MPRDGovernanceGateAuthorization.accepted_reachable_states_require_prepared_governance_guard
