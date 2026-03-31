/- 
  MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement.lean

  A lightweight composed refinement bridge from the exact signed-registry
  execution packet language into the abstract `MPRD_ExecutionBoundary`
  theorem, via the grouped runtime execute-ready witness lane.

  This remains narrower than a top-level runtime-to-formal refinement theorem.
  It only removes one more auxiliary premise: once the exact signed-registry
  packet language holds, executed grouped `ExecutionReadyPacketV1` states no
  longer need a separate runtime-witness parameter for this refinement step.
-/

import MPRD_ExecutionReadyRuntimeRefinement
import MPRD_SignedRegistryExecutionExactPacketWitnessCompiler

namespace MPRDSignedRegistryExecutionExactPacketRuntimeRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev ExactPacket :=
  MPRDSignedRegistryExecutionExactPacketWitnessCompiler.SignedRegistryExecutionExactPacket

theorem executed_execution_ready_packet_states_refine_to_execution_boundary
    {s : PacketState}
    (hReach : MPRDExecutionReadyPacketBoundary.Reachable s)
    (hExec : MPRDExecutionReadyPacketBoundary.Executed s)
    {p : ExactPacket}
    (hExact :
      MPRDSignedRegistryExecutionExactPacketWitnessCompiler.executionWitnessRelevantHolds p) :
    ∃ t : MPRDExecutionBoundary.State,
      t.ctx.bindings =
          (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness p).bindings ∧
        t.ctx.executorGate =
            (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness p).executorGate ∧
          MPRDExecutionBoundary.Reachable t ∧
            MPRDExecutionBoundary.Executed t ∧
              MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t := by
  have hRuntime :
      MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
        (MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compileRuntimeWitness p) :=
    MPRDSignedRegistryExecutionExactPacketWitnessCompiler.compiled_runtime_witness_holds hExact
  simpa using
    MPRDExecutionReadyRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
      hReach hExec hRuntime

end MPRDSignedRegistryExecutionExactPacketRuntimeRefinement

abbrev executed_execution_ready_packet_states_refine_to_execution_boundary_from_exact_signed_registry_packet_v1 :=
  @MPRDSignedRegistryExecutionExactPacketRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
