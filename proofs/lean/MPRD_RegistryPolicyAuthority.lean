/- 
  MPRD_RegistryPolicyAuthority.lean

  A lightweight model of the registry-backed policy admission boundary:

    resolving a live policy requires a selected registry authority mode,
    successful checkpoint authority validation, manifest verification, exact
    policy_ref alignment, policy authorization, and image routing.
-/

namespace MPRDRegistryPolicyAuthority

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive AuthorityMode where
  | none
  | single
  | quorum
  | weighted
  deriving Repr, DecidableEq

inductive ResolveResult where
  | pending
  | resolved
  | rejected
  deriving Repr, DecidableEq

structure State where
  mode : AuthorityMode
  authorityOk : Bool
  manifestOk : Bool
  policyRefAligned : Bool
  policyHashAuthorized : Bool
  imageRoutable : Bool
  result : ResolveResult
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.mode = .none ∧
    s.authorityOk = false ∧
      s.manifestOk = false ∧
        s.policyRefAligned = false ∧
          s.policyHashAuthorized = false ∧
            s.imageRoutable = false ∧
              s.result = .pending

def Resolved (s : State) : Prop :=
  s.result = .resolved

def ResolvedImpliesRegistryAuthorityBoundary (s : State) : Prop :=
  Resolved s ->
    s.mode ≠ .none ∧
      s.authorityOk = true ∧
        s.manifestOk = true ∧
          s.policyRefAligned = true ∧
            s.policyHashAuthorized = true ∧
              s.imageRoutable = true

inductive Step : State -> State -> Prop
  | choose_single (s : State) :
      s.mode = .none ->
      s.result = .pending ->
      Step s { s with mode := .single }
  | choose_quorum (s : State) :
      s.mode = .none ->
      s.result = .pending ->
      Step s { s with mode := .quorum }
  | choose_weighted (s : State) :
      s.mode = .none ->
      s.result = .pending ->
      Step s { s with mode := .weighted }
  | set_authority_ok (s : State) :
      s.mode ≠ .none ->
      s.authorityOk = false ->
      s.result = .pending ->
      Step s { s with authorityOk := true }
  | set_manifest_ok (s : State) :
      s.manifestOk = false ->
      s.result = .pending ->
      Step s { s with manifestOk := true }
  | set_policy_ref_aligned (s : State) :
      s.policyRefAligned = false ->
      s.result = .pending ->
      Step s { s with policyRefAligned := true }
  | set_policy_hash_authorized (s : State) :
      s.policyHashAuthorized = false ->
      s.result = .pending ->
      Step s { s with policyHashAuthorized := true }
  | set_image_routable (s : State) :
      s.imageRoutable = false ->
      s.result = .pending ->
      Step s { s with imageRoutable := true }
  | resolve_policy (s : State) :
      s.mode ≠ .none ->
      s.authorityOk = true ->
      s.manifestOk = true ->
      s.policyRefAligned = true ->
      s.policyHashAuthorized = true ->
      s.imageRoutable = true ->
      s.result = .pending ->
      Step s { s with result := .resolved }
  | reject_missing_requirements (s : State) :
      s.result = .pending ->
      s.mode ≠ .none ->
      (s.authorityOk = false ∨
        s.manifestOk = false ∨
        s.policyRefAligned = false ∨
        s.policyHashAuthorized = false ∨
        s.imageRoutable = false) ->
      Step s { s with result := .rejected }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_resolved_implies_registry_authority_boundary {s : State} (hInit : Initial s) :
    ResolvedImpliesRegistryAuthorityBoundary s := by
  intro hResolved
  rcases hInit with
    ⟨_hMode, _hAuthority, _hManifest, _hAligned, _hAuthorized, _hRoutable, hResult⟩
  cases hResolved.symm.trans hResult

theorem step_preserves_resolved_implies_registry_authority_boundary
    {s t : State} (hStep : Step s t) (hInv : ResolvedImpliesRegistryAuthorityBoundary s) :
    ResolvedImpliesRegistryAuthorityBoundary t := by
  intro hResolved
  cases hStep with
  | choose_single hMode hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | choose_quorum hMode hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | choose_weighted hMode hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | set_authority_ok hMode hAuthority hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | set_manifest_ok hManifest hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | set_policy_ref_aligned hAligned hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | set_policy_hash_authorized hAuthorized hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | set_image_routable hRoutable hPending =>
      have : s.result = .resolved := by simpa [Resolved] using hResolved
      cases hPending.symm.trans this
  | resolve_policy hMode hAuthority hManifest hAligned hAuthorized hRoutable hPending =>
      exact ⟨hMode, hAuthority, hManifest, hAligned, hAuthorized, hRoutable⟩
  | reject_missing_requirements hPending hMode hMissing =>
      simp [Resolved] at hResolved
  | stutter =>
      exact hInv hResolved

theorem reachable_resolved_states_require_registry_authority_boundary :
    ∀ {s : State}, Reachable s -> ResolvedImpliesRegistryAuthorityBoundary s
  | _, .init hInit =>
      initial_resolved_implies_registry_authority_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_resolved_implies_registry_authority_boundary hStep
        (reachable_resolved_states_require_registry_authority_boundary hReach)

theorem resolved_reachable_states_require_registry_authority_boundary
    {s : State} (hReach : Reachable s) :
    Resolved s ->
      s.mode ≠ .none ∧
        s.authorityOk = true ∧
          s.manifestOk = true ∧
            s.policyRefAligned = true ∧
              s.policyHashAuthorized = true ∧
                s.imageRoutable = true :=
  reachable_resolved_states_require_registry_authority_boundary hReach

theorem resolved_states_require_trusted_registry_authority
    {s : State} (hReach : Reachable s) :
    Resolved s -> s.mode ≠ .none ∧ s.authorityOk = true := by
  intro hResolved
  exact
    ⟨(resolved_reachable_states_require_registry_authority_boundary hReach hResolved).1,
      (resolved_reachable_states_require_registry_authority_boundary hReach hResolved).2.1⟩

theorem resolved_states_require_manifest_and_policy_alignment
    {s : State} (hReach : Reachable s) :
    Resolved s -> s.manifestOk = true ∧ s.policyRefAligned = true := by
  intro hResolved
  exact
    ⟨(resolved_reachable_states_require_registry_authority_boundary hReach hResolved).2.2.1,
      (resolved_reachable_states_require_registry_authority_boundary hReach hResolved).2.2.2.1⟩

theorem resolved_states_require_policy_authorization_and_routing
    {s : State} (hReach : Reachable s) :
    Resolved s -> s.policyHashAuthorized = true ∧ s.imageRoutable = true := by
  intro hResolved
  exact
    ⟨(resolved_reachable_states_require_registry_authority_boundary hReach hResolved).2.2.2.2.1,
      (resolved_reachable_states_require_registry_authority_boundary hReach hResolved).2.2.2.2.2⟩

end MPRDRegistryPolicyAuthority

abbrev resolved_reachable_states_require_registry_authority_boundary_v1 :=
  @MPRDRegistryPolicyAuthority.resolved_reachable_states_require_registry_authority_boundary
