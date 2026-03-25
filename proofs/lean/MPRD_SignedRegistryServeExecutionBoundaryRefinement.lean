/- 
  MPRD_SignedRegistryServeExecutionBoundaryRefinement.lean

  A lightweight witness-gated refinement bridge between:

    * the shipped signed-registry `mprd serve` path after
      `ExecutionReadyPacketV1` grouping, and
    * the abstract `MPRD_ExecutionBoundary` theorem.

  This is intentionally narrower than a full end-to-end refinement proof. It
  states that once a constructor-gated refinement witness materializes the
  detailed commitment/executor bindings, executed states on the shipped serve
  path refine into a reachable abstract execution-boundary state.
-/

import MPRD_ExecutionBoundary
import MPRD_SignedRegistryServeReadyPacketBoundary

namespace MPRDSignedRegistryServeExecutionBoundaryRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeReadyPacketBoundary.State

structure RefinementWitness where
  bindings : MPRDExecutionBoundary.BindingVector
  executorGate : MPRDExecutionBoundary.ExecutorGate
  deriving Repr, DecidableEq

def RefinementWitnessHolds (w : RefinementWitness) : Prop :=
  MPRDExecutionBoundary.ConcreteBindingsHold w.bindings ∧
    MPRDExecutionBoundary.ExecutorGateHold w.executorGate

def refineContext (s : ServeState) (w : RefinementWitness) :
    MPRDExecutionBoundary.Context :=
  { verdict :=
      if s.allowed = true then
        MPRDExecutionBoundary.Verdict.allowed
      else
        MPRDExecutionBoundary.Verdict.denied
    governanceOk := s.governanceAligned
    replayOk := s.replayAdmitted
    bindings := w.bindings
    executorGate := w.executorGate }

def refineSuccessState (s : ServeState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .succeeded
    ctx := refineContext s w }

def refineFailedState (s : ServeState) (w : RefinementWitness) :
    MPRDExecutionBoundary.State :=
  { proof := .verified
    exec := .failed
    ctx := refineContext s w }

theorem executed_signed_registry_serve_states_refine_to_execution_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s)
    {w : RefinementWitness}
    (hWitness : RefinementWitnessHolds w) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings = w.bindings ∧
        t.ctx.executorGate = w.executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨_hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, _hAuth, hGovernance, hVerified,
      hAllowed, _hBinding, _hExecutor, _hBoundary, _hSignature, _hStateProv,
      hReplay⟩
  rcases hWitness with ⟨hBindings, hExecutorGate⟩
  let c := refineContext s w
  have hVerdict : c.verdict = MPRDExecutionBoundary.Verdict.allowed := by
    simp [c, refineContext, hAllowed]
  have hGovernanceOk : c.governanceOk = true := by
    simpa [c, refineContext] using hGovernance
  have hReplayOk : c.replayOk = true := by
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
          (MPRDExecutionBoundary.Step.exec_skipped_to_success c hVerdict hGovernanceOk hReplayOk
            hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inl rfl
      have hBoundary :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundary⟩
  | inr hFailure =>
      let t := refineFailedState s w
      have hReachT : MPRDExecutionBoundary.Reachable t := by
        exact MPRDExecutionBoundary.Reachable.step hVerifiedReach
          (MPRDExecutionBoundary.Step.exec_skipped_to_failed c hVerdict hGovernanceOk hReplayOk
            hBindings hExecutorGate)
      have hExecT : MPRDExecutionBoundary.Executed t := by
        exact Or.inr rfl
      have hBoundary :=
        MPRDExecutionBoundary.reachable_executed_states_require_full_boundary_gate hReachT
      exact ⟨t, rfl, rfl, hReachT, hExecT, hBoundary⟩

end MPRDSignedRegistryServeExecutionBoundaryRefinement

abbrev executed_signed_registry_serve_states_refine_to_execution_boundary_v1 :=
  @MPRDSignedRegistryServeExecutionBoundaryRefinement.executed_signed_registry_serve_states_refine_to_execution_boundary
