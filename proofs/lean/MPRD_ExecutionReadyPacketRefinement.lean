/- 
  MPRD_ExecutionReadyPacketRefinement.lean

  A lightweight witness-gated refinement bridge between:

    * the grouped local `ExecutionReadyPacketV1` runtime boundary, and
    * the abstract `MPRD_ExecutionBoundary` theorem.

  This is intentionally narrower than a full end-to-end refinement proof. It
  states that once a constructor-gated refinement witness materializes the
  abstract verdict/governance/binding/executor facts, executed grouped-packet
  states refine into a reachable abstract execution-boundary state.
-/

import MPRD_ExecutionBoundary
import MPRD_ExecutionReadyPacketBoundary

namespace MPRDExecutionReadyPacketRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State

structure RefinementWitness where
  verdict : MPRDExecutionBoundary.Verdict
  governanceOk : Bool
  bindings : MPRDExecutionBoundary.BindingVector
  executorGate : MPRDExecutionBoundary.ExecutorGate
  deriving Repr, DecidableEq

def RefinementWitnessHolds (w : RefinementWitness) : Prop :=
  w.verdict = MPRDExecutionBoundary.Verdict.allowed ∧
    w.governanceOk = true ∧
      MPRDExecutionBoundary.ConcreteBindingsHold w.bindings ∧
        MPRDExecutionBoundary.ExecutorGateHold w.executorGate

def refineContext (s : PacketState) (w : RefinementWitness) :
    MPRDExecutionBoundary.Context :=
  { verdict := w.verdict
    governanceOk := w.governanceOk
    replayOk := s.replayAdmitted
    bindings := w.bindings
    executorGate := w.executorGate }

def refineSuccessState (s : PacketState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .succeeded
    ctx := refineContext s w }

def refineFailedState (s : PacketState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .failed
    ctx := refineContext s w }

theorem executed_execution_ready_packet_states_refine_to_execution_boundary
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {w : RefinementWitness}
    (hWitness : RefinementWitnessHolds w) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = w.bindings ∧
        t.ctx.executorGate = w.executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  rcases
      MPRDExecutionReadyPacketBoundary.executed_reachable_states_require_execution_ready_packet_boundary
        hReach hExec with
    ⟨_hPacket, _hReady, _hBoundary, _hAuth, _hBridge, _hSignature, _hStateProv, hReplay⟩
  rcases hWitness with ⟨hVerdict, hGovernance, hBindings, hExecutorGate⟩
  let c := refineContext s w
  have hVerdictCtx : c.verdict = MPRDExecutionBoundary.Verdict.allowed := by
    simpa [c, refineContext] using hVerdict
  have hGovernanceCtx : c.governanceOk = true := by
    simpa [c, refineContext] using hGovernance
  have hReplayCtx : c.replayOk = true := by
    simpa [c, refineContext] using hReplay
  have hPendingInit :
      MPRDExecutionBoundary.Initial
        { proof := .pending, exec := .skipped, ctx := c } := by
    exact ⟨rfl, rfl⟩
  have hPendingReach :
      MPRDExecutionBoundary.Reachable
        { proof := .pending, exec := .skipped, ctx := c } :=
    MPRDExecutionBoundary.Reachable.init hPendingInit
  have hVerifiedReach :
      MPRDExecutionBoundary.Reachable
        { proof := .verified, exec := .skipped, ctx := c } :=
    MPRDExecutionBoundary.Reachable.step hPendingReach
      (MPRDExecutionBoundary.Step.proof_pending_verify c)
  cases hExec with
  | inl hSuccess =>
      let t := refineSuccessState s w
      have hReachT : MPRDExecutionBoundary.Reachable t := by
        exact MPRDExecutionBoundary.Reachable.step hVerifiedReach
          (MPRDExecutionBoundary.Step.exec_skipped_to_success c hVerdictCtx hGovernanceCtx
            hReplayCtx hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inl rfl
      have hBoundaryT :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundaryT⟩
  | inr hFailure =>
      let t := refineFailedState s w
      have hReachT : MPRDExecutionBoundary.Reachable t := by
        exact MPRDExecutionBoundary.Reachable.step hVerifiedReach
          (MPRDExecutionBoundary.Step.exec_skipped_to_failed c hVerdictCtx hGovernanceCtx
            hReplayCtx hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inr rfl
      have hBoundaryT :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundaryT⟩

end MPRDExecutionReadyPacketRefinement

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_v1 :=
  @MPRDExecutionReadyPacketRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
