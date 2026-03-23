/- 
  MPRD_GovernedSourceArtifactWitness.lean

  A lightweight model of the deploy/runtime admission witness:

    exact artifact validation is useful, but it is still weaker than governed
    provenance on Tau-declared carriers. A Tau-declared artifact remains
    non-executable until both source mapping and artifact validation are present.
-/

namespace MPRDGovernedSourceArtifactWitness

def proof_bundle_version : String := "mprd-leanproofs-v9"

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
  artifactValidated : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.tauSourceIntentDeclared = false ∧
    s.tauSourceGoverned = false ∧
      s.policyRefPinned = false ∧
        s.policyAuthorized = false ∧
          s.imageRouted = false ∧
            s.sourceMapped = false ∧
              s.artifactValidated = false ∧
                s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .executed

def ArtifactWitnessReady (s : State) : Prop :=
  s.sourceMapped = true ∧ s.artifactValidated = true

def ExecutedImpliesArtifactWitnessGuard (s : State) : Prop :=
  Executed s ->
    s.policyRefPinned = true ∧
      s.policyAuthorized = true ∧
        s.imageRouted = true ∧
          s.artifactValidated = true ∧
            (s.tauSourceGoverned = true -> ArtifactWitnessReady s) ∧
              (s.tauSourceIntentDeclared = true -> ArtifactWitnessReady s)

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
  | validate_artifact (s : State) :
      s.imageRouted = true ->
      s.artifactValidated = false ->
      s.exec = .skipped ->
      Step s { s with artifactValidated := true }
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
      s.artifactValidated = true ->
      s.exec = .skipped ->
      Step s { s with exec := .executed }
  | execute_tau_witness_ready (s : State) :
      s.tauSourceIntentDeclared = true ->
      s.tauSourceGoverned = true ->
      s.policyRefPinned = true ->
      s.policyAuthorized = true ->
      s.imageRouted = true ->
      s.sourceMapped = true ->
      s.artifactValidated = true ->
      s.exec = .skipped ->
      Step s { s with exec := .executed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_executed_implies_artifact_witness_guard {s : State}
    (hInit : Initial s) : ExecutedImpliesArtifactWitnessGuard s := by
  intro hExecuted
  rcases hInit with ⟨_hIntent, _hGov, hRef, _hAuth, _hImage, _hMap, _hArtifact, hExec⟩
  cases hExecuted.symm.trans hExec

theorem step_preserves_executed_implies_artifact_witness_guard
    {s t : State} (hStep : Step s t) (hInv : ExecutedImpliesArtifactWitnessGuard s) :
    ExecutedImpliesArtifactWitnessGuard t := by
  intro hExecuted
  cases hStep with
  | declare_tau_intent _hIntent hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | pin_policy_ref _hRef hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | authorize_policy _hRef _hAuth hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | route_image _hAuth _hImage hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | validate_artifact _hImage _hArtifact hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | attach_tau_source_mapping _hIntent _hImage _hMap hPending =>
      have : s.exec = .executed := by
        simpa [Executed] using hExecuted
      cases hPending.symm.trans this
  | execute_plain hIntent hGov hRef hAuth hImage hArtifact hPending =>
      have hIntentFalse : ({ s with exec := .executed }).tauSourceIntentDeclared = false := by
        simpa using hIntent
      have hGovFalse : ({ s with exec := .executed }).tauSourceGoverned = false := by
        simpa using hGov
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa using hRef
      · simpa using hAuth
      · simpa using hImage
      · simpa using hArtifact
      · intro hGovTrue
        cases hGovFalse.symm.trans hGovTrue
      · intro hIntentTrue
        cases hIntentFalse.symm.trans hIntentTrue
  | execute_tau_witness_ready hIntent hGov hRef hAuth hImage hMap hArtifact hPending =>
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · simpa using hRef
      · simpa using hAuth
      · simpa using hImage
      · simpa using hArtifact
      · intro _hGovTrue
        exact ⟨by simpa using hMap, by simpa using hArtifact⟩
      · intro _hIntentTrue
        exact ⟨by simpa using hMap, by simpa using hArtifact⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_artifact_witness_guard :
    ∀ {s : State}, Reachable s -> ExecutedImpliesArtifactWitnessGuard s
  | _, .init hInit =>
      initial_executed_implies_artifact_witness_guard hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_artifact_witness_guard hStep
        (reachable_executed_states_require_artifact_witness_guard hReach)

theorem executed_reachable_states_require_artifact_witness_guard
    {s : State} (hReach : Reachable s) :
    Executed s ->
      s.policyRefPinned = true ∧
        s.policyAuthorized = true ∧
          s.imageRouted = true ∧
            s.artifactValidated = true ∧
              (s.tauSourceGoverned = true -> ArtifactWitnessReady s) ∧
                (s.tauSourceIntentDeclared = true -> ArtifactWitnessReady s) :=
  reachable_executed_states_require_artifact_witness_guard hReach

theorem executed_tau_governed_reachable_states_require_artifact_witness_ready
    {s : State} (hReach : Reachable s) :
    Executed s -> s.tauSourceGoverned = true -> ArtifactWitnessReady s := by
  intro hExecuted hTau
  exact (executed_reachable_states_require_artifact_witness_guard hReach hExecuted).2.2.2.2.1 hTau

theorem reachable_tau_declared_validated_without_mapping_states_stay_skipped
    {s : State} (hReach : Reachable s) :
    s.tauSourceIntentDeclared = true ->
      s.artifactValidated = true ->
        s.sourceMapped = false ->
          s.exec = .skipped := by
  intro hIntent _hArtifact hUnmapped
  cases hExec : s.exec with
  | skipped =>
      rfl
  | executed =>
      have hGuard :=
        executed_reachable_states_require_artifact_witness_guard hReach (by simpa [Executed] using hExec)
      have hWitness := hGuard.2.2.2.2.2 hIntent
      rcases hWitness with ⟨hMapped, _hArtifactReady⟩
      cases hUnmapped.symm.trans hMapped

end MPRDGovernedSourceArtifactWitness

abbrev executed_reachable_states_require_artifact_witness_guard_v1 :=
  @MPRDGovernedSourceArtifactWitness.executed_reachable_states_require_artifact_witness_guard
