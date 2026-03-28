/- 
  MPRD_ExecutionReadyRuntimeRefinement.lean

  A lightweight composed refinement bridge for the grouped runtime
  execute-ready refinement witness:

    executed `ExecutionReadyPacketV1` states refine into the abstract
    `MPRD_ExecutionBoundary` theorem once a constructor-gated runtime
    refinement witness holds.

  This narrows the proof lane by removing the extra abstract refinement-witness
  premise at this step. It is still narrower than the top-level concrete
  runtime refinement theorem, because discharging the runtime witness from
  shipped Rust objects remains a separate step.
-/

import MPRD_ExecutionReadyPacketRefinement
import MPRD_ExecutionReadyRefinementWitnessCompiler

namespace MPRDExecutionReadyRuntimeRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev RuntimeWitness :=
  MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness

theorem executed_execution_ready_packet_states_refine_to_execution_boundary
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {w : RuntimeWitness}
    (hRuntime :
      MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds w) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings =
          (MPRDExecutionReadyRefinementWitnessCompiler.compileWitness w).bindings ∧
        t.ctx.executorGate =
            (MPRDExecutionReadyRefinementWitnessCompiler.compileWitness w).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  have hWitness :
      MPRDExecutionReadyPacketRefinement.RefinementWitnessHolds
        (MPRDExecutionReadyRefinementWitnessCompiler.compileWitness w) :=
    MPRDExecutionReadyRefinementWitnessCompiler.compiled_witness_holds hRuntime
  simpa using
    MPRDExecutionReadyPacketRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
      hReach hExec hWitness

end MPRDExecutionReadyRuntimeRefinement

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_via_runtime_witness_v1 :=
  @MPRDExecutionReadyRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
