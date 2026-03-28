/- 
  MPRD_ExecutionReadyRefinementWitnessCompiler.lean

  A lightweight local compiler from the grouped runtime execute-ready
  refinement witness language into the abstract `ExecutionReadyPacket`
  refinement witness language.

  This is intentionally narrower than the top-level runtime refinement theorem.
  It captures one exact step: once the runtime has simultaneously admitted
  governance, signature, provenance, replay, the concrete binding vector, and
  the executor gate, there is one canonical abstract witness shape for the next
  proof lane.
-/

import MPRD_ExecutionReadyPacketRefinement

namespace MPRDExecutionReadyRefinementWitnessCompiler

def proof_bundle_version : String := "mprd-leanproofs-v1"

structure RuntimeRefinementWitness where
  governanceAdmitted : Bool
  signatureAdmitted : Bool
  stateProvenanceAdmitted : Bool
  replayAdmitted : Bool
  bindings : MPRDExecutionBoundary.BindingVector
  executorGate : MPRDExecutionBoundary.ExecutorGate
  deriving Repr, DecidableEq

def RuntimeRefinementWitnessHolds (w : RuntimeRefinementWitness) : Prop :=
  w.governanceAdmitted = true ∧
    w.signatureAdmitted = true ∧
      w.stateProvenanceAdmitted = true ∧
        w.replayAdmitted = true ∧
          MPRDExecutionBoundary.ConcreteBindingsHold w.bindings ∧
            MPRDExecutionBoundary.ExecutorGateHold w.executorGate

def compileWitness (w : RuntimeRefinementWitness) :
    MPRDExecutionReadyPacketRefinement.RefinementWitness :=
  { verdict := MPRDExecutionBoundary.Verdict.allowed
    governanceOk := w.governanceAdmitted
    bindings := w.bindings
    executorGate := w.executorGate }

theorem compiled_witness_holds
    {w : RuntimeRefinementWitness}
    (h : RuntimeRefinementWitnessHolds w) :
    MPRDExecutionReadyPacketRefinement.RefinementWitnessHolds
      (compileWitness w) := by
  rcases h with ⟨hGovernance, _hSignature, _hStateProv, _hReplay, hBindings, hExecutorGate⟩
  simp [compileWitness, MPRDExecutionReadyPacketRefinement.RefinementWitnessHolds,
    hGovernance, hBindings, hExecutorGate]

end MPRDExecutionReadyRefinementWitnessCompiler

abbrev execution_ready_runtime_refinement_witness_compiles_v1 :=
  @MPRDExecutionReadyRefinementWitnessCompiler.compiled_witness_holds
