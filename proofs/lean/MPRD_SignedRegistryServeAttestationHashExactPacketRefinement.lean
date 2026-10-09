/- 
  MPRD_SignedRegistryServeAttestationHashExactPacketRefinement.lean

  A lightweight top-level refinement bridge for the richer signed-registry
  `mprd serve` path after both:

    * the attestation-hash tightening, and
    * the grouped exact ready-packet admissions.

  This composes the richer shipped-path model through the grouped
  signed-registry execution artifact lane and then reaches the abstract
  `MPRD_ExecutionBoundary` theorem without a separate witness premise at this
  top-level model.
-/

import MPRD_SignedRegistryExecutionArtifactRuntimeRefinement
import MPRD_SignedRegistryServeAttestationHashArtifactBoundary
import MPRD_SignedRegistryServeAttestationHashReadyPacketBoundary
import MPRD_SignedRegistryServeEndToEndRefinement

namespace MPRDSignedRegistryServeAttestationHashExactPacketRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.State
abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev mapServeExec :=
  MPRDSignedRegistryServeAttestationHashArtifactBoundary.mapServeExec

abbrev packetViewOfServeState :=
  MPRDSignedRegistryServeAttestationHashArtifactBoundary.packetViewOfServeState

abbrev artifactOfServeState :=
  MPRDSignedRegistryServeAttestationHashArtifactBoundary.artifactOfServeState

theorem executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeAttestationHashReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings =
              (MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness
                (artifactOfServeState s)).bindings ∧
            t.ctx.executorGate =
              (MPRDSignedRegistryExecutionArtifactRuntimeRefinement.compileRuntimeWitness
                (artifactOfServeState s)).executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  have hArtifact :
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.ArtifactHolds
        (artifactOfServeState s) := by
    exact
      MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_artifact_boundary
        hReach hExec
  rcases
      MPRDSignedRegistryServeAttestationHashArtifactBoundary.executed_reachable_states_require_signed_registry_serve_attestation_hash_packet_view
        hReach hExec with
    ⟨hPacketReach, hPacketExec⟩
  rcases
      MPRDSignedRegistryExecutionArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
        hPacketReach hPacketExec hArtifact with
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
  exact ⟨hPacketReach, hPacketExec,
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩⟩

end MPRDSignedRegistryServeAttestationHashExactPacketRefinement

abbrev executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary_via_exact_packet_v1 :=
  @MPRDSignedRegistryServeAttestationHashExactPacketRefinement.executed_signed_registry_serve_attestation_hash_states_refine_to_execution_boundary
