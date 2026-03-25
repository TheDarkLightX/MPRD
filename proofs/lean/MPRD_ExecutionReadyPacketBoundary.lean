/-
  MPRD_ExecutionReadyPacketBoundary.lean

  A lightweight local theorem for the grouped `ExecutionReadyPacketV1`
  runtime boundary:

    executing through the current live `execute_ready` packet requires the
    concrete execution-boundary witness, execution authorization, signed-registry
    bridge facts, and executor-side signature/state-provenance/replay admission
    to be grouped into one constructor-gated packet before execution can occur.
-/

namespace MPRDExecutionReadyPacketBoundary

def proof_bundle_version : String := "mprd-leanproofs-v1"

inductive ExecStatus where
  | skipped
  | succeeded
  | failed
  deriving Repr, DecidableEq

structure State where
  boundaryAdmitted : Bool
  authorizationAdmitted : Bool
  bridgeAdmitted : Bool
  signatureAdmitted : Bool
  stateProvenanceAdmitted : Bool
  replayAdmitted : Bool
  packetGrouped : Bool
  readyVisible : Bool
  exec : ExecStatus
  deriving Repr, DecidableEq

def Initial (s : State) : Prop :=
  s.boundaryAdmitted = false ∧
    s.authorizationAdmitted = false ∧
      s.bridgeAdmitted = false ∧
        s.signatureAdmitted = false ∧
          s.stateProvenanceAdmitted = false ∧
            s.replayAdmitted = false ∧
              s.packetGrouped = false ∧
                s.readyVisible = false ∧
                  s.exec = .skipped

def Executed (s : State) : Prop :=
  s.exec = .succeeded ∨ s.exec = .failed

def PacketGroupedImpliesFullBoundary (s : State) : Prop :=
  s.packetGrouped = true ->
    s.boundaryAdmitted = true ∧
      s.authorizationAdmitted = true ∧
        s.bridgeAdmitted = true ∧
          s.signatureAdmitted = true ∧
            s.stateProvenanceAdmitted = true ∧
              s.replayAdmitted = true

def ExecutedImpliesFullBoundary (s : State) : Prop :=
  Executed s ->
    s.packetGrouped = true ∧
      s.readyVisible = true ∧
        s.boundaryAdmitted = true ∧
          s.authorizationAdmitted = true ∧
            s.bridgeAdmitted = true ∧
              s.signatureAdmitted = true ∧
                s.stateProvenanceAdmitted = true ∧
                  s.replayAdmitted = true

inductive Step : State -> State -> Prop
  | admit_boundary (s : State) :
      s.boundaryAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with boundaryAdmitted := true }
  | admit_authorization (s : State) :
      s.boundaryAdmitted = true ->
      s.authorizationAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with authorizationAdmitted := true }
  | admit_bridge (s : State) :
      s.authorizationAdmitted = true ->
      s.bridgeAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with bridgeAdmitted := true }
  | admit_signature (s : State) :
      s.boundaryAdmitted = true ->
      s.signatureAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with signatureAdmitted := true }
  | admit_state_provenance (s : State) :
      s.boundaryAdmitted = true ->
      s.stateProvenanceAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with stateProvenanceAdmitted := true }
  | admit_replay (s : State) :
      s.boundaryAdmitted = true ->
      s.replayAdmitted = false ->
      s.exec = .skipped ->
      Step s { s with replayAdmitted := true }
  | group_packet (s : State) :
      s.boundaryAdmitted = true ->
      s.authorizationAdmitted = true ->
      s.bridgeAdmitted = true ->
      s.signatureAdmitted = true ->
      s.stateProvenanceAdmitted = true ->
      s.replayAdmitted = true ->
      s.packetGrouped = false ->
      s.exec = .skipped ->
      Step s { s with packetGrouped := true }
  | expose_ready (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = false ->
      s.exec = .skipped ->
      Step s { s with readyVisible := true }
  | execute_success (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = true ->
      s.exec = .skipped ->
      Step s { s with exec := .succeeded }
  | execute_failed (s : State) :
      s.packetGrouped = true ->
      s.readyVisible = true ->
      s.exec = .skipped ->
      Step s { s with exec := .failed }
  | stutter (s : State) :
      Step s s

inductive Reachable : State -> Prop
  | init {s : State} : Initial s -> Reachable s
  | step {s t : State} : Reachable s -> Step s t -> Reachable t

theorem initial_packet_grouped_implies_full_boundary {s : State}
    (hInit : Initial s) : PacketGroupedImpliesFullBoundary s := by
  intro hGrouped
  rcases hInit with
    ⟨_hBoundary, _hAuth, _hBridge, _hSignature, _hStateProv, _hReplay,
      hGrouped0, _hReady, _hExec⟩
  cases hGrouped.symm.trans hGrouped0

theorem step_preserves_packet_grouped_implies_full_boundary
    {s t : State} (hStep : Step s t) (hInv : PacketGroupedImpliesFullBoundary s) :
    PacketGroupedImpliesFullBoundary t := by
  intro hGrouped
  cases hStep with
  | admit_boundary _ _ =>
      rcases hInv hGrouped with
        ⟨_hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
      exact ⟨rfl, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
  | admit_authorization hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨_hBoundary, _hAuth, hBridge, hSignature, hStateProv, hReplay⟩
      exact ⟨hBoundary, rfl, hBridge, hSignature, hStateProv, hReplay⟩
  | admit_bridge hAuth _ _ =>
      rcases hInv hGrouped with
        ⟨hBoundary, _hAuth, _hBridge, hSignature, hStateProv, hReplay⟩
      exact ⟨hBoundary, hAuth, rfl, hSignature, hStateProv, hReplay⟩
  | admit_signature hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨_hBoundary, hAuth, hBridge, _hSignature, hStateProv, hReplay⟩
      exact ⟨hBoundary, hAuth, hBridge, rfl, hStateProv, hReplay⟩
  | admit_state_provenance hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨_hBoundary, hAuth, hBridge, hSignature, _hStateProv, hReplay⟩
      exact ⟨hBoundary, hAuth, hBridge, hSignature, rfl, hReplay⟩
  | admit_replay hBoundary _ _ =>
      rcases hInv hGrouped with
        ⟨_hBoundary, hAuth, hBridge, hSignature, hStateProv, _hReplay⟩
      exact ⟨hBoundary, hAuth, hBridge, hSignature, hStateProv, rfl⟩
  | group_packet hBoundary hAuth hBridge hSignature hStateProv hReplay _ _ =>
      exact ⟨hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
  | expose_ready hPacket _ _ =>
      exact hInv hPacket
  | execute_success hPacket _ _ =>
      exact hInv hPacket
  | execute_failed hPacket _ _ =>
      exact hInv hPacket
  | stutter =>
      exact hInv hGrouped

theorem reachable_packet_grouped_states_require_full_boundary :
    ∀ {s : State}, Reachable s -> PacketGroupedImpliesFullBoundary s
  | _, .init hInit =>
      initial_packet_grouped_implies_full_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_packet_grouped_implies_full_boundary hStep
        (reachable_packet_grouped_states_require_full_boundary hReach)

theorem initial_executed_implies_full_boundary {s : State}
    (hInit : Initial s) : ExecutedImpliesFullBoundary s := by
  intro hExecuted
  rcases hInit with
    ⟨_hBoundary, _hAuth, _hBridge, _hSignature, _hStateProv, _hReplay,
      _hGrouped, _hReady, hExec⟩
  cases hExecuted with
  | inl hSuccess =>
      cases hSuccess.symm.trans hExec
  | inr hFailure =>
      cases hFailure.symm.trans hExec

theorem step_preserves_executed_implies_full_boundary
    {s t : State} (hStep : Step s t) (hReach : Reachable s)
    (hInv : ExecutedImpliesFullBoundary s) :
    ExecutedImpliesFullBoundary t := by
  intro hExecuted
  cases hStep with
  | admit_boundary _ hExec
  | admit_authorization _ _ hExec
  | admit_bridge _ _ hExec
  | admit_signature _ _ hExec
  | admit_state_provenance _ _ hExec
  | admit_replay _ _ hExec
  | group_packet _ _ _ _ _ _ _ hExec
  | expose_ready _ _ hExec =>
      cases hExecuted with
      | inl hSuccess =>
          cases hSuccess.symm.trans hExec
      | inr hFailure =>
          cases hFailure.symm.trans hExec
  | execute_success hPacket hReady hExec0 =>
      rcases reachable_packet_grouped_states_require_full_boundary hReach hPacket with
        ⟨hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
      exact ⟨hPacket, hReady, hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
  | execute_failed hPacket hReady hExec0 =>
      rcases reachable_packet_grouped_states_require_full_boundary hReach hPacket with
        ⟨hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
      exact ⟨hPacket, hReady, hBoundary, hAuth, hBridge, hSignature, hStateProv, hReplay⟩
  | stutter =>
      exact hInv hExecuted

theorem reachable_executed_states_require_full_boundary :
    ∀ {s : State}, Reachable s -> ExecutedImpliesFullBoundary s
  | _, .init hInit =>
      initial_executed_implies_full_boundary hInit
  | _, .step hReach hStep =>
      step_preserves_executed_implies_full_boundary hStep hReach
        (reachable_executed_states_require_full_boundary hReach)

theorem executed_reachable_states_require_execution_ready_packet_boundary
    {s : State} (hReach : Reachable s) (hExec : Executed s) :
    s.packetGrouped = true ∧
      s.readyVisible = true ∧
        s.boundaryAdmitted = true ∧
          s.authorizationAdmitted = true ∧
            s.bridgeAdmitted = true ∧
              s.signatureAdmitted = true ∧
                s.stateProvenanceAdmitted = true ∧
                  s.replayAdmitted = true := by
  exact reachable_executed_states_require_full_boundary hReach hExec

end MPRDExecutionReadyPacketBoundary

abbrev executed_reachable_states_require_execution_ready_packet_boundary_v1 :=
  @MPRDExecutionReadyPacketBoundary.executed_reachable_states_require_execution_ready_packet_boundary
