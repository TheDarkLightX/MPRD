/- 
  MPRD_GovernanceStateLinkage.lean

  A lightweight model of the governance-state linkage boundary:

    applying a rules or committee update requires threshold authorization plus
    the concrete previous-hash and monotone-sequence linkage checks used by
    GovernanceState::{apply_rules_update,apply_committee_update}.
-/

namespace MPRDGovernanceStateLinkage

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive UpdateTrack where
  | none
  | rules
  | committee
  deriving Repr, DecidableEq

inductive ApplyResult where
  | pending
  | applied
  | rejected
  deriving Repr, DecidableEq

structure State where
  track : UpdateTrack
  thresholdOk : Bool
  rulesHashLinked : Bool
  rulesSeqMonotone : Bool
  committeeHashLinked : Bool
  committeeSeqMonotone : Bool
  result : ApplyResult
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.track = .none ∧
    s.thresholdOk = false ∧
      s.rulesHashLinked = false ∧
        s.rulesSeqMonotone = false ∧
          s.committeeHashLinked = false ∧
            s.committeeSeqMonotone = false ∧
              s.result = .pending

def Applied (s : State) : Prop :=
  s.result = .applied

def LinkedUpdateSurface (s : State) : Prop :=
  (s.track = .rules -> s.rulesHashLinked = true ∧ s.rulesSeqMonotone = true) ∧
    (s.track = .committee -> s.committeeHashLinked = true ∧ s.committeeSeqMonotone = true)

def AppliedImpliesLinkedGovernanceState (s : State) : Prop :=
  Applied s ->
    s.thresholdOk = true ∧
      s.track ≠ .none ∧
      LinkedUpdateSurface s

inductive Step : State -> State -> Prop
  | choose_rules (s : State) :
      s.track = .none ->
      s.result = .pending ->
      Step s { s with track := .rules }
  | choose_committee (s : State) :
      s.track = .none ->
      s.result = .pending ->
      Step s { s with track := .committee }
  | set_threshold_ok (s : State) :
      s.thresholdOk = false ->
      s.result = .pending ->
      Step s { s with thresholdOk := true }
  | set_rules_hash_linked (s : State) :
      s.track = .rules ->
      s.rulesHashLinked = false ->
      s.result = .pending ->
      Step s { s with rulesHashLinked := true }
  | set_rules_seq_monotone (s : State) :
      s.track = .rules ->
      s.rulesSeqMonotone = false ->
      s.result = .pending ->
      Step s { s with rulesSeqMonotone := true }
  | set_committee_hash_linked (s : State) :
      s.track = .committee ->
      s.committeeHashLinked = false ->
      s.result = .pending ->
      Step s { s with committeeHashLinked := true }
  | set_committee_seq_monotone (s : State) :
      s.track = .committee ->
      s.committeeSeqMonotone = false ->
      s.result = .pending ->
      Step s { s with committeeSeqMonotone := true }
  | apply_rules (s : State) :
      s.track = .rules ->
      s.thresholdOk = true ->
      s.rulesHashLinked = true ->
      s.rulesSeqMonotone = true ->
      s.result = .pending ->
      Step s { s with result := .applied }
  | apply_committee (s : State) :
      s.track = .committee ->
      s.thresholdOk = true ->
      s.committeeHashLinked = true ->
      s.committeeSeqMonotone = true ->
      s.result = .pending ->
      Step s { s with result := .applied }
  | reject_missing_requirements (s : State) :
      s.result = .pending ->
      s.track ≠ .none ->
      (s.thresholdOk = false ∨
        (s.track = .rules ∧ (s.rulesHashLinked = false ∨ s.rulesSeqMonotone = false)) ∨
        (s.track = .committee ∧
          (s.committeeHashLinked = false ∨ s.committeeSeqMonotone = false))) ->
      Step s { s with result := .rejected }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_applied_implies_linked_governance_state {s : State} (hInit : Initial s) :
    AppliedImpliesLinkedGovernanceState s := by
  intro hApplied
  rcases hInit with ⟨_hTrack, _hThreshold, _hRulesHash, _hRulesSeq, _hCommitteeHash, _hCommitteeSeq, hResult⟩
  cases hApplied.symm.trans hResult

theorem step_preserves_applied_implies_linked_governance_state
    {s t : State} (hStep : Step s t) (hInv : AppliedImpliesLinkedGovernanceState s) :
    AppliedImpliesLinkedGovernanceState t := by
  intro hApplied
  cases hStep with
  | choose_rules hTrack hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | choose_committee hTrack hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | set_threshold_ok hThreshold hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | set_rules_hash_linked hTrack hRulesHash hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | set_rules_seq_monotone hTrack hRulesSeq hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | set_committee_hash_linked hTrack hCommitteeHash hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | set_committee_seq_monotone hTrack hCommitteeSeq hPending =>
      have : s.result = .applied := by simpa [Applied] using hApplied
      cases hPending.symm.trans this
  | apply_rules hTrack hThreshold hRulesHash hRulesSeq hPending =>
      refine ⟨hThreshold, ?_, ?_⟩
      · intro hNone
        cases hTrack.symm.trans hNone
      · refine ⟨?_, ?_⟩
        · intro hRules
          exact ⟨hRulesHash, hRulesSeq⟩
        · intro hCommittee
          cases hTrack.symm.trans hCommittee
  | apply_committee hTrack hThreshold hCommitteeHash hCommitteeSeq hPending =>
      refine ⟨hThreshold, ?_, ?_⟩
      · intro hNone
        cases hTrack.symm.trans hNone
      · refine ⟨?_, ?_⟩
        · intro hRules
          cases hTrack.symm.trans hRules
        · intro hCommittee
          exact ⟨hCommitteeHash, hCommitteeSeq⟩
  | reject_missing_requirements hPending hTrack hMissing =>
      simp [Applied] at hApplied
  | stutter =>
      exact hInv hApplied

theorem reachable_applied_states_require_linked_governance_state :
    ∀ {s : State}, Reachable s -> AppliedImpliesLinkedGovernanceState s
  | _, .init hInit =>
      initial_applied_implies_linked_governance_state hInit
  | _, .step hReach hStep =>
      step_preserves_applied_implies_linked_governance_state hStep
        (reachable_applied_states_require_linked_governance_state hReach)

theorem applied_reachable_states_require_linked_governance_state
    {s : State} (hReach : Reachable s) :
    Applied s ->
      s.thresholdOk = true ∧
        s.track ≠ .none ∧
        ((s.track = .rules -> s.rulesHashLinked = true ∧ s.rulesSeqMonotone = true) ∧
          (s.track = .committee ->
            s.committeeHashLinked = true ∧ s.committeeSeqMonotone = true)) :=
  reachable_applied_states_require_linked_governance_state hReach

theorem applied_rules_updates_require_hash_link_and_monotone_seq
    {s : State} (hReach : Reachable s) :
    Applied s -> s.track = .rules -> s.rulesHashLinked = true ∧ s.rulesSeqMonotone = true := by
  intro hApplied hRules
  exact (applied_reachable_states_require_linked_governance_state hReach hApplied).2.2.1 hRules

theorem applied_committee_updates_require_hash_link_and_monotone_seq
    {s : State} (hReach : Reachable s) :
    Applied s -> s.track = .committee -> s.committeeHashLinked = true ∧ s.committeeSeqMonotone = true := by
  intro hApplied hCommittee
  exact (applied_reachable_states_require_linked_governance_state hReach hApplied).2.2.2 hCommittee

end MPRDGovernanceStateLinkage

abbrev applied_reachable_states_require_linked_governance_state_v1 :=
  @MPRDGovernanceStateLinkage.applied_reachable_states_require_linked_governance_state
