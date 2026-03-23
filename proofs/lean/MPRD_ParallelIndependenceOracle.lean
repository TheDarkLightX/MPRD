/- 
  MPRD_ParallelIndependenceOracle.lean

  A lightweight local theorem for pre/post-condition-guided parallelization:

    speculative evaluation and cache refresh may run in parallel because they
    commute and preserve the serial authority/commit barrier, while final
    commit remains fail-closed on registry freshness, replay clearance,
    selector binding, source binding, and (for private deployments) Mode C
    key admission.
-/

namespace MPRDParallelIndependenceOracle

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive CommitResult where
  | pending
  | committed
  | rejected
  deriving Repr, DecidableEq

structure State where
  evalDone : Bool
  cacheDone : Bool
  registryFresh : Bool
  replayClear : Bool
  selectorBound : Bool
  sourceBound : Bool
  privateMode : Bool
  modeCKeyAllowed : Bool
  result : CommitResult
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.evalDone = false ∧
    s.cacheDone = false ∧
      s.registryFresh = false ∧
        s.replayClear = false ∧
          s.selectorBound = false ∧
            s.sourceBound = false ∧
              s.privateMode = false ∧
                s.modeCKeyAllowed = false ∧
                  s.result = .pending

def Committed (s : State) : Prop :=
  s.result = .committed

def AuthorityProjection (s : State) :
    Bool × Bool × Bool × Bool × Bool × Bool :=
  (s.registryFresh, s.replayClear, s.selectorBound, s.sourceBound, s.privateMode, s.modeCKeyAllowed)

def EvalStep (s : State) : State :=
  { s with evalDone := true }

def CacheStep (s : State) : State :=
  { s with cacheDone := true }

def CommitReady (s : State) : Prop :=
  s.evalDone = true ∧
    s.cacheDone = true ∧
      s.registryFresh = true ∧
        s.replayClear = true ∧
          s.selectorBound = true ∧
            s.sourceBound = true ∧
              (s.privateMode = false ∨ s.modeCKeyAllowed = true)

def CommittedImpliesCommitReady (s : State) : Prop :=
  Committed s -> CommitReady s

inductive Step : State -> State -> Prop
  | eval_candidates (s : State) :
      s.evalDone = false ->
      s.result = .pending ->
      Step s (EvalStep s)
  | refresh_cache (s : State) :
      s.cacheDone = false ->
      s.result = .pending ->
      Step s (CacheStep s)
  | refresh_registry (s : State) :
      s.registryFresh = false ->
      s.result = .pending ->
      Step s { s with registryFresh := true }
  | clear_replay (s : State) :
      s.replayClear = false ->
      s.result = .pending ->
      Step s { s with replayClear := true }
  | bind_selector (s : State) :
      s.selectorBound = false ->
      s.result = .pending ->
      Step s { s with selectorBound := true }
  | bind_source (s : State) :
      s.sourceBound = false ->
      s.result = .pending ->
      Step s { s with sourceBound := true }
  | enable_private_mode (s : State) :
      s.privateMode = false ->
      s.result = .pending ->
      Step s { s with privateMode := true }
  | approve_mode_c_key (s : State) :
      s.privateMode = true ->
      s.modeCKeyAllowed = false ->
      s.result = .pending ->
      Step s { s with modeCKeyAllowed := true }
  | commit (s : State) :
      CommitReady s ->
      s.result = .pending ->
      Step s { s with result := .committed }
  | reject_missing_requirements (s : State) :
      s.result = .pending ->
      ¬ CommitReady s ->
      Step s { s with result := .rejected }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem eval_cache_commute (s : State) :
    CacheStep (EvalStep s) = EvalStep (CacheStep s) := by
  cases s <;> rfl

theorem eval_preserves_authority_projection (s : State) :
    AuthorityProjection (EvalStep s) = AuthorityProjection s := by
  cases s <;> rfl

theorem cache_preserves_authority_projection (s : State) :
    AuthorityProjection (CacheStep s) = AuthorityProjection s := by
  cases s <;> rfl

theorem initial_committed_implies_commit_ready {s : State} (hInit : Initial s) :
    CommittedImpliesCommitReady s := by
  intro hCommitted
  rcases hInit with
    ⟨_hEval, _hCache, _hRegistry, _hReplay, _hSelector, _hSource, _hPrivate, _hKey, hResult⟩
  cases hCommitted.symm.trans hResult

theorem step_preserves_committed_implies_commit_ready
    {s t : State} (hStep : Step s t) (hInv : CommittedImpliesCommitReady s) :
    CommittedImpliesCommitReady t := by
  intro hCommitted
  cases hStep with
  | eval_candidates hEval hPending =>
      have : s.result = .committed := by simpa [Committed, EvalStep] using hCommitted
      cases hPending.symm.trans this
  | refresh_cache hCache hPending =>
      have : s.result = .committed := by simpa [Committed, CacheStep] using hCommitted
      cases hPending.symm.trans this
  | refresh_registry hRegistry hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | clear_replay hReplay hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | bind_selector hSelector hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | bind_source hSource hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | enable_private_mode hPrivate hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | approve_mode_c_key hPrivate hKey hPending =>
      have : s.result = .committed := by simpa [Committed] using hCommitted
      cases hPending.symm.trans this
  | commit hReady hPending =>
      simpa [Committed]
        using hReady
  | reject_missing_requirements hPending hNotReady =>
      simp [Committed] at hCommitted
  | stutter =>
      exact hInv hCommitted

theorem reachable_committed_states_require_commit_ready :
    ∀ {s : State}, Reachable s -> CommittedImpliesCommitReady s
  | _, .init hInit =>
      initial_committed_implies_commit_ready hInit
  | _, .step hReach hStep =>
      step_preserves_committed_implies_commit_ready hStep
        (reachable_committed_states_require_commit_ready hReach)

theorem committed_reachable_states_require_commit_ready
    {s : State} (hReach : Reachable s) :
    Committed s -> CommitReady s :=
  reachable_committed_states_require_commit_ready hReach

theorem committed_private_states_require_mode_c_key
    {s : State} (hReach : Reachable s) :
    Committed s -> s.privateMode = true -> s.modeCKeyAllowed = true := by
  intro hCommitted hPrivate
  have hReady := committed_reachable_states_require_commit_ready hReach hCommitted
  rcases hReady with
    ⟨_hEval, _hCache, _hRegistry, _hReplay, _hSelector, _hSource, hPrivateGuard⟩
  cases hPrivateGuard with
  | inl hNotPrivate =>
      rw [hPrivate] at hNotPrivate
      cases hNotPrivate
  | inr hKey =>
      exact hKey

theorem speculative_steps_do_not_change_authority_projection
    (s : State) :
    AuthorityProjection (EvalStep s) = AuthorityProjection (CacheStep s) ->
      AuthorityProjection (EvalStep s) = AuthorityProjection s := by
  intro _hEq
  exact eval_preserves_authority_projection s

end MPRDParallelIndependenceOracle

abbrev committed_reachable_states_require_commit_ready_v1 :=
  @MPRDParallelIndependenceOracle.committed_reachable_states_require_commit_ready
