import Lake
open Lake DSL

package «MPRDLeanProofs» where
  -- Keep it lightweight: Lean core only (no Mathlib dependency)
  moreLeanArgs := #["-DautoImplicit=false", "-Dlinter.missingDocs=false"]

@[default_target]
lean_lib MPRDLeanProofs where
  roots := #[
    `MPRDLeanProofs,
    `MPRD_Theorem,
    `MPRD_Alignment_Combined,
    `MPRD_ExecutionLifecycle,
    `MPRD_ExecutionGate,
    `MPRD_ExecutionCommitmentBindings,
    `MPRD_ExecutionBoundary,
    `MPRD_ExecutionReadyPacketBoundary,
    `MPRD_ExecutionReadyPacketRefinement,
    `MPRD_ExecutionReadyRefinementWitnessCompiler,
    `MPRD_ExecutionReadyRuntimeRefinement,
    `MPRD_ExecutionBindingVectorPacketBoundary,
    `MPRD_ExecutionBoundaryRefinementPacketBoundary,
    `MPRD_AttestationReadyExecutionAuthorizationBoundary,
    `MPRD_ExecutionAuthorizationMetadataPacketBoundary,
    `MPRD_ExecutionAuthorizationWitnessProjection,
    `MPRD_ExecutionRegistryBridgeWitnessProjection,
    `MPRD_SelectorContractBinding,
    `MPRD_TauPolicyAuthority,
    `MPRD_GovernedPolicySource,
    `MPRD_GovernedSourceIntentBoundary,
    `MPRD_GovernedSourceArtifactWitness,
    `MPRD_GovernanceGateAuthorization,
    `MPRD_GovernanceStateLinkage,
    `MPRD_GovernanceExecutionBridge,
    `MPRD_SignedRegistryCheckpointBridge,
    `MPRD_SignedRegistryBridgeMetadataPacketBoundary,
    `MPRD_SignedRegistryExecutionBoundaryRefinement,
    `MPRD_SignedRegistryExecutionMetadataPacketBoundary,
    `MPRD_SignedRegistryExecutionRefinementPacketBoundary,
    `MPRD_SignedRegistryExecutionRefinementWitnessCompiler,
    `MPRD_SignedRegistryExecutionExactPacketWitnessCompiler,
    `MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement,
    `MPRD_SignedRegistryExecutionArtifactRuntimeRefinement,
    `MPRD_SignedRegistryBridgeWitnessBoundary,
    `MPRD_SignedRegistryExecutionBoundary,
    `MPRD_SignedRegistryServeEndToEndRefinement,
    `MPRD_SignedRegistryServeExecutionBoundaryRefinement,
    `MPRD_SignedRegistryServeBoundary,
    `MPRD_SignedRegistryServeReadyPacketBoundary,
    `MPRD_SignedRegistryServeAttestationHashBoundary,
    `MPRD_SignedRegistryServeAttestationHashReadyPacketBoundary,
    `MPRD_SignedRegistryServeAttestationHashRefinement,
    `MPRD_SignedRegistryServeAttestationHashArtifactBoundary,
    `MPRD_SignedRegistryServeAttestationHashExactPacketRefinement,
    `MPRD_SignedRegistryServeIdempotentFileBoundary,
    `MPRD_SignedRegistryServeIdempotentHttpBoundary,
    `MPRD_RegistryPolicyAuthority,
    `MPRD_ParallelIndependenceOracle,
    `TauTables_SelectSet
  ]
