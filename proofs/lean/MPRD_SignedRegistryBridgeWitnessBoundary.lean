/- 
  MPRD_SignedRegistryBridgeWitnessBoundary.lean

  A lightweight boundary model for the current signed-registry bridge-witness path:

    executing through the concrete signed-registry runtime path requires
    registry resolution, exact checkpoint binding, execution-authorization
    binding, registry-authorization hash binding, governance alignment, and
    preservation of the concrete bridge witness into the rebuilt ready bundle.
-/

namespace MPRDSignedRegistryBridgeWitnessBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  registryResolved : Bool
  checkpointBound : Bool
  executionAuthorizationBound : Bool
  registryAuthorizationHashBound : Bool
  governanceAligned : Bool
  bridgeWitnessPreserved : Bool
  readyRebuilt : Bool
  verified : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.registryResolved = false ∧
    s.checkpointBound = false ∧
      s.executionAuthorizationBound = false ∧
        s.registryAuthorizationHashBound = false ∧
          s.governanceAligned = false ∧
            s.bridgeWitnessPreserved = false ∧
              s.readyRebuilt = false ∧
                s.verified = false ∧
                  s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def ReadyRebuiltImpliesBridgeWitnessBoundary (s : State) : Prop :=
  s.readyRebuilt = true ->
    s.registryResolved = true ∧
      s.checkpointBound = true ∧
        s.executionAuthorizationBound = true ∧
          s.registryAuthorizationHashBound = true ∧
            s.governanceAligned = true ∧
              s.bridgeWitnessPreserved = true

def ExecutedImpliesBridgeWitnessBoundary (s : State) : Prop :=
  Executed s ->
    s.readyRebuilt = true ∧
      s.verified = true ∧
        s.registryResolved = true ∧
          s.checkpointBound = true ∧
            s.executionAuthorizationBound = true ∧
              s.registryAuthorizationHashBound = true ∧
                s.governanceAligned = true ∧
                  s.bridgeWitnessPreserved = true

inductive Step : State -> State -> Prop
  | set_registry_resolved (s : State) :
      s.registryResolved = false ->
      s.exec = .skipped ->
      Step s { s with registryResolved := true }
  | bind_checkpoint (s : State) :
      s.registryResolved = true ->
      s.checkpointBound = false ->
      s.exec = .skipped ->
      Step s { s with checkpointBound := true }
  | bind_execution_authorization (s : State) :
      s.registryResolved = true ->
      s.executionAuthorizationBound = false ->
      s.exec = .skipped ->
      Step s { s with executionAuthorizationBound := true }
  | bind_registry_authorization_hash (s : State) :
      s.registryResolved = true ->
      s.registryAuthorizationHashBound = false ->
      s.exec = .skipped ->
      Step s { s with registryAuthorizationHashBound := true }
  | align_governance (s : State) :
      s.governanceAligned = false ->
      s.exec = .skipped ->
      Step s { s with governanceAligned := true }
  | preserve_bridge_witness (s : State) :
      s.registryResolved = true ->
      s.checkpointBound = true ->
      s.executionAuthorizationBound = true ->
      s.registryAuthorizationHashBound = true ->
      s.governanceAligned = true ->
      s.bridgeWitnessPreserved = false ->
      s.exec = .skipped ->
      Step s { s with bridgeWitnessPreserved := true }
  | rebuild_ready (s : State) :
      s.registryResolved = true ->
      s.checkpointBound = true ->
      s.executionAuthorizationBound = true ->
      s.registryAuthorizationHashBound = true ->
      s.governanceAligned = true ->
      s.bridgeWitnessPreserved = true ->
      s.readyRebuilt = false ->
      s.exec = .skipped ->
      Step s { s with readyRebuilt := true }
  | set_verified (s : State) :
      s.readyRebuilt = true ->
      s.verified = false ->
      s.exec = .skipped ->
      Step s { s with verified := true }
  | execute_success (s : State) :
      s.readyRebuilt = true ->
      s.verified = true ->
      s.exec = .skipped ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.readyRebuilt = true ->
      s.verified = true ->
      s.exec = .skipped ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_ready_rebuilt_implies_bridge_witness_boundary {s : State}
    (hInit : Initial s) : ReadyRebuiltImpliesBridgeWitnessBoundary s := by
  intro hReady
  rcases hInit with
    ⟨_hResolved, _hCheckpoint, _hAuth, _hResolutionHash, _hGovernance,
      _hBridgeWitness, hReady0, _hVerified, _hExec⟩
  cases hReady.symm.trans hReady0

theorem step_preserves_ready_rebuilt_implies_bridge_witness_boundary
    {s t : State} (hStep : Step s t) (hInv : ReadyRebuiltImpliesBridgeWitnessBoundary s) :
    ReadyRebuiltImpliesBridgeWitnessBoundary t := by
  intro hReady
  cases hStep with
  | set_registry_resolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨rfl, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
  | bind_checkpoint hResolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, _hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨hResolved, rfl, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
  | bind_execution_authorization hResolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, hCheckpoint, _hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨hResolved, hCheckpoint, rfl, hResolutionHash, hGovernance, hBridgeWitness⟩
  | bind_registry_authorization_hash hResolved _ _ =>
      rcases hInv hReady with
        ⟨_hResolved, hCheckpoint, hAuth, _hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨hResolved, hCheckpoint, hAuth, rfl, hGovernance, hBridgeWitness⟩
  | align_governance _ _ =>
      rcases hInv hReady with
        ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, _hGovernance, hBridgeWitness⟩
      exact ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, rfl, hBridgeWitness⟩
  | preserve_bridge_witness hResolved hCheckpoint hAuth hResolutionHash hGovernance _ _ =>
      exact ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, rfl⟩
  | rebuild_ready hResolved hCheckpoint hAuth hResolutionHash hGovernance hBridgeWitness _ _ =>
      exact ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
  | set_verified _ _ _ =>
      exact hInv hReady
  | execute_success _ _ _ =>
      exact hInv hReady
  | execute_failed _ _ _ =>
      exact hInv hReady
  | stutter =>
      exact hInv hReady

theorem reachable_ready_rebuilt_states_require_bridge_witness_boundary :
    ∀ {s : State}, Reachable s -> ReadyRebuiltImpliesBridgeWitnessBoundary s
  | _, .init hInit =>
      initial_ready_rebuilt_implies_bridge_witness_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_ready_rebuilt_implies_bridge_witness_boundary hStep
        (reachable_ready_rebuilt_states_require_bridge_witness_boundary hReach)

theorem initial_executed_implies_bridge_witness_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesBridgeWitnessBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hResolved, _hCheckpoint, _hAuth, _hResolutionHash, _hGovernance,
      _hBridgeWitness, _hReady, _hVerified, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_bridge_witness_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesBridgeWitnessBoundary s) :
    ExecutedImpliesBridgeWitnessBoundary t := by
  intro hExecuted
  cases hStep with
  | set_registry_resolved _ hExec
  | bind_checkpoint _ _ hExec
  | bind_execution_authorization _ _ hExec
  | bind_registry_authorization_hash _ _ hExec
  | align_governance _ hExec
  | preserve_bridge_witness _ _ _ _ _ _ hExec
  | rebuild_ready _ _ _ _ _ _ _ hExec
  | set_verified _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hReady hVerified _ =>
      rcases reachable_ready_rebuilt_states_require_bridge_witness_boundary hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨hReady, hVerified, hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
  | execute_failed hReady hVerified _ =>
      rcases reachable_ready_rebuilt_states_require_bridge_witness_boundary hReach hReady with
        ⟨hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
      exact ⟨hReady, hVerified, hResolved, hCheckpoint, hAuth, hResolutionHash, hGovernance, hBridgeWitness⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_bridge_witness_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesBridgeWitnessBoundary s
  | _, .init hInit =>
      initial_executed_implies_bridge_witness_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_bridge_witness_boundary hStep hReach
        (reachable_executed_states_require_bridge_witness_boundary hReach)

theorem executed_reachable_states_require_signed_registry_bridge_witness
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
    s.readyRebuilt = true ∧
      s.verified = true ∧
        s.registryResolved = true ∧
          s.checkpointBound = true ∧
            s.executionAuthorizationBound = true ∧
              s.registryAuthorizationHashBound = true ∧
                s.governanceAligned = true ∧
                  s.bridgeWitnessPreserved = true := by
  exact reachable_executed_states_require_bridge_witness_boundary hReach hExec

end MPRDSignedRegistryBridgeWitnessBoundary

abbrev executed_reachable_states_require_signed_registry_bridge_witness_v1 :=
  @MPRDSignedRegistryBridgeWitnessBoundary.executed_reachable_states_require_signed_registry_bridge_witness
