# MPRD Lean Proofs (Public)

This directory contains a **small, self-contained Lean 4** proof bundle for the
core MPRD safety invariant and its abstract composition with an economic forcing
assumption.

## What is included

- `MPRD_Theorem.lean`: the core safety invariant (contract-based).
- `MPRD_Alignment_Combined.lean`: composition lemma (explicitly states assumptions).
- `MPRD_ExecutionLifecycle.lean`: a lightweight reachable-state proof of the decision lifecycle invariants mirrored by the checked-in TLA+ model.
- `MPRD_ExecutionGate.lean`: a guarded reachable-state proof that executed states require verification, an allowed verdict, governance authorization, replay clearance, and binding integrity.
- `MPRD_ExecutionCommitmentBindings.lean`: a stronger reachable-state proof that expands binding integrity into the concrete commitment checks used by the journal verifier: journal-allowed, limits hash, decision commitment recomputation, policy/state/candidate/action matches, and nonce binding.
- `MPRD_ExecutionBoundary.lean`: a composed reachable-state proof that joins the journal/request commitment vector with the executor preimage/schema gate, so execution requires both verifier-side and executor-side bindings.
- `MPRD_ExecutionReadyPacketBoundary.lean`: a lightweight local theorem for the grouped `ExecutionReadyPacketV1` runtime boundary: executed states require the concrete execution-boundary witness, execution authorization, signed-registry bridge facts, and executor-side signature/state-provenance/replay admission to be grouped into one constructor-gated packet before execution can occur.
- `MPRD_ExecutionReadyPacketRefinement.lean`: a lightweight witness-gated refinement bridge from the grouped local `ExecutionReadyPacketV1` runtime boundary into the abstract `MPRD_ExecutionBoundary` theorem: once the abstract verdict/governance/binding/executor witness materializes, executed grouped-packet states refine into a reachable abstract execution-boundary state.
- `MPRD_ExecutionReadyRefinementWitnessCompiler.lean`: a lightweight local compiler theorem for the grouped runtime execute-ready refinement witness: once runtime has simultaneously admitted governance, signature, provenance, replay, the concrete binding vector, and the executor gate, there is one canonical abstract `ExecutionReadyPacket` refinement witness shape for the next proof step.
- `MPRD_ExecutionReadyRuntimeRefinement.lean`: a lightweight composed theorem for the grouped runtime execute-ready refinement witness: once that constructor-gated runtime witness holds, executed grouped-packet states refine directly into the abstract `MPRD_ExecutionBoundary` theorem without a separate abstract witness premise at this step.
- `MPRD_ExecutionBindingVectorPacketBoundary.lean`: a lightweight local theorem for the grouped binding-vector packet: the grouped `ExecutionBindingVectorPacketV1` language is extensionally equal to a separate loose field-language carrying the same binding inputs used by `execution_binding_vector_hash_v1(...)`.
- `MPRD_ExecutionBoundaryRefinementPacketBoundary.lean`: a lightweight local theorem for the grouped refinement packet: the grouped `ExecutionBoundaryRefinementPacketV1` language is extensionally equal to a separate loose two-field language carrying the same `execution_ready_packet_hash` and `attestation_metadata_hash` inputs used by `execution_boundary_refinement_hash_v1(...)`.
- `MPRD_AttestationReadyExecutionAuthorizationBoundary.lean`: a lightweight local theorem for the attestation-ready refactor boundary: once `prepare_attestation_ready(...)` succeeds, the grouped execution-authorization packet carried by `AttestationReadyBundle` is extensionally equal to the old loose policy/state/governance tuple used for attestation stamping.
- `MPRD_ExecutionAuthorizationMetadataPacketBoundary.lean`: a lightweight local theorem for the grouped execution-authorization metadata packet: the grouped `ExecutionAuthorizationMetadataPacketV1` language is extensionally equal to a separate loose two-field language carrying the exact authorization attestation packet plus the canonical `execution_authorization_hash_v1` value reconstructed from metadata.
- `MPRD_ExecutionAuthorizationWitnessProjection.lean`: a lightweight local theorem for the live execute-path authorization refactor: projecting `ExecutionAuthorizationWitnessV1` into the grouped attestation packet is extensionally equal to the old loose policy/state/governance stamping language.
- `MPRD_ExecutionRegistryBridgeWitnessProjection.lean`: a lightweight local theorem for the live signed-registry bridge refactor: projecting `ExecutionRegistryBridgeWitnessV1` into the grouped bridge attestation packet is extensionally equal to the old loose registry tuple plus optional checkpoint language.
- `MPRD_SelectorContractBinding.lean`: a lightweight reachable-state proof that execution also requires the selector-specific chosen-index and chosen-action-preimage bindings, so runtime effects cannot drift to a different allowed action.
- `MPRD_TauPolicyAuthority.lean`: a small reachable-state proof of the architectural split: models propose, Tau decides, the selector chooses from the Tau-allowed set, and execution follows only that choice.
- `MPRD_GovernedPolicySource.lean`: a lightweight registry-bound proof that if Tau source bytes are the governed rule surface, execution through a compiled artifact still requires pinned policy authorization, routed image selection, and explicit source mapping.
- `MPRD_GovernedSourceIntentBoundary.lean`: a lightweight proof of the stricter selected boundary: signed Tau intent is weaker than governed mapping, so Tau-declared artifacts stay skipped until source mapping appears.
- `MPRD_GovernedSourceArtifactWitness.lean`: a lightweight proof of the next deploy/runtime boundary: exact artifact validation is still weaker than governed provenance, so Tau-declared validated artifacts stay skipped until mapping appears, while executed Tau-governed states require a full source-plus-artifact witness.
- `MPRD_GovernanceGateAuthorization.lean`: a lightweight proof of the prepared governance gate boundary: accepted governance updates require a one-hot prepared lane, `link_ok`, and the lane-matching profile thresholds.
- `MPRD_GovernanceStateLinkage.lean`: a lightweight proof of the concrete governance-state linkage boundary: applied rules and committee updates require threshold authorization plus previous-hash linkage and monotone sequence continuity.
- `MPRD_GovernanceExecutionBridge.lean`: a lightweight cross-slice proof that execution-time `governance_ok` requires both a resolved live policy and an admitted governance update before execution can occur.
- `MPRD_SignedRegistryCheckpointBridge.lean`: a lightweight proof of the stricter signed-registry execution path: rebuilding the live ready bundle, and therefore executing, requires registry resolution, exact checkpoint binding, execution-authorization binding, and governance alignment.
- `MPRD_SignedRegistryBridgeMetadataPacketBoundary.lean`: a lightweight local theorem for the grouped signed-registry bridge metadata packet: the grouped `SignedRegistryBridgeMetadataPacketV1` language is extensionally equal to a separate loose two-field language carrying the exact registry-authorization attestation packet plus the optional signed-registry checkpoint attestation hash reconstructed from metadata.
- `MPRD_SignedRegistryExecutionBoundaryRefinement.lean`: a lightweight no-witness refinement bridge from the concrete signed-registry execution-boundary model into the abstract `MPRD_ExecutionBoundary` theorem.
- `MPRD_SignedRegistryExecutionMetadataPacketBoundary.lean`: a lightweight local theorem for the grouped signed-registry execution metadata packet: the grouped `SignedRegistryExecutionMetadataPacketV1` language is extensionally equal to a separate loose two-field language carrying the exact execution-authorization metadata packet plus the exact signed-registry bridge metadata packet.
- `MPRD_SignedRegistryExecutionRefinementPacketBoundary.lean`: a lightweight local theorem for the grouped signed-registry execution refinement packet: the grouped `SignedRegistryExecutionRefinementPacketV1` language is extensionally equal to a separate loose four-field language carrying the exact grouped ready packet, binding-vector packet, refinement packet, and signed-registry execution metadata packet.
- `MPRD_SignedRegistryExecutionRefinementWitnessCompiler.lean`: a lightweight local compiler theorem for the grouped signed-registry execution refinement packet: once that grouped packet language exists, there is one canonical abstract `ExecutionReadyPacket` refinement witness shape for the next proof step.
- `MPRD_SignedRegistryExecutionExactPacketWitnessCompiler.lean`: a lightweight exact-packet compiler theorem for the signed-registry runtime lane: once the exact grouped `ExecutionReadyPacketV1` admissions and exact binding-vector presence exist together, there is one canonical grouped runtime refinement-witness shape for the next proof step; this is the preferred witness-language lane over the older hash-oriented signed-registry refinement packet.
- `MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement.lean`: a lightweight composed refinement bridge for that exact packet lane: once the exact signed-registry packet language holds, executed grouped `ExecutionReadyPacketV1` states refine into the abstract `MPRD_ExecutionBoundary` theorem without a separate runtime-witness premise at this step.
- `MPRD_SignedRegistryExecutionArtifactRuntimeRefinement.lean`: a lightweight grouped-artifact compiler/refinement bridge for the signed-registry runtime lane: once the shipped grouped execution artifact exists and its grouped `ExecutionReadyPacketV1` admissions hold, there is one canonical exact signed-registry packet for the next proof step, and executed grouped `ExecutionReadyPacketV1` states refine through that artifact lane without manually reconstructing the exact packet.
- `MPRD_SignedRegistryBridgeWitnessBoundary.lean`: a lightweight proof of the next stricter signed-registry boundary: executed states require the registry-authorization hash binding and preservation of the concrete bridge witness into the rebuilt ready bundle, in addition to the signed-registry bridge facts.
- `MPRD_SignedRegistryExecutionBoundary.lean`: a lightweight joined boundary proof for the shipped signed-registry path: executed states require the signed-registry bridge facts plus the concrete execution guards (verified, allowed, replay, binding, executor).
- `MPRD_SignedRegistryServeEndToEndRefinement.lean`: a lightweight top-level composed refinement bridge for the shipped signed-registry `mprd serve` path: executed serve states refine through the grouped local `ExecutionReadyPacketV1` boundary and then into the abstract `MPRD_ExecutionBoundary` theorem, and the proof now composes through the grouped runtime execute-ready refinement witness instead of bypassing that lane with only the older abstract witness shape.
- `MPRD_SignedRegistryServeExecutionBoundaryRefinement.lean`: a lightweight witness-gated refinement bridge from the shipped signed-registry serve path into the abstract `MPRD_ExecutionBoundary` theorem: once a detailed commitment/executor witness materializes, executed serve states refine into a reachable abstract execution-boundary state.
- `MPRD_SignedRegistryServeBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path: executed states require validated registry and state anchors, explicit policy selection, production verifier binding, ready-bridge invocation, the signed-registry bridge facts, and the concrete execution guards.
- `MPRD_SignedRegistryServeReadyPacketBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path after `ExecutionReadyPacketV1` grouping: executed states require the signed-registry serve-boundary facts and the grouped ready-packet admissions together before the live `execute_ready` boundary can fire.
- `MPRD_SignedRegistryServeAttestationHashBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path after the concrete attestation-hash tightening: executed states require exact checkpoint-attestation, execution-authorization-hash, and registry-authorization-hash binding plus preservation of the concrete bridge witness, in addition to the signed-registry serve-boundary facts and concrete execution guards.
- `MPRD_SignedRegistryServeAttestationHashReadyPacketBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path after both the attestation-hash tightening and grouped `ExecutionReadyPacketV1` admissions: executed states require those richer signed-registry serve facts plus the grouped boundary/signature/state-provenance/replay admissions together before the live ready boundary can fire.
- `MPRD_SignedRegistryServeAttestationHashRefinement.lean`: a lightweight top-level refinement bridge for that richer signed-registry attestation-hash serve model: once those exact hash-bound serve facts hold on an executed state, the state now composes through the concrete signed-registry execution-boundary model and then into a reachable abstract `MPRD_ExecutionBoundary` state without an extra witness premise at that top-level model.
- `MPRD_SignedRegistryServeAttestationHashArtifactBoundary.lean`: a lightweight top-level boundary theorem package for the stronger attestation-hash-plus-ready-packet serve model: once those richer signed-registry serve facts and exact grouped ready-packet admissions hold on an executed state, the state must first materialize a grouped signed-registry execution artifact, and it also has a named executed ready-packet view theorem, before the exact signed-registry packet lane can be used.
- `MPRD_SignedRegistryServeAttestationHashExactPacketRefinement.lean`: a lightweight top-level refinement bridge for the stronger attestation-hash-plus-ready-packet serve model: once those richer signed-registry serve facts and exact grouped ready-packet admissions hold on an executed state, the state composes through the grouped signed-registry execution artifact lane, then the exact signed-registry packet runtime-refinement lane, and then into a reachable abstract `MPRD_ExecutionBoundary` state without an extra witness premise at that top-level model.
- `MPRD_SignedRegistryServeAttestationHashIdempotentHttpComposition.lean`: a lightweight concrete composition theorem for the strongest shipped remote-effect lane: when the attestation-hash-strengthened signed-registry serve path and the shipped `idempotent_http` sink are modeling the same successful execution, the combined state requires both the stronger serve attestation-hash facts and the concrete pending/committed HTTP barrier facts.
- `MPRD_SignedRegistryServeIdempotentFileBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path when the side-effect sink is `idempotent_file`: successful local execution requires the signed-registry serve-boundary facts, explicit `idempotent_file` selection, configured audit-file binding, and a durable local file barrier before success.
- `MPRD_SignedRegistryServeIdempotentHttpBoundary.lean`: a lightweight top-level proof for the shipped production `mprd serve` path when the side-effect sink is `idempotent_http`: successful remote execution requires the signed-registry serve-boundary facts, explicit `idempotent_http` selection, configured effect-journal binding, a pending-barrier check, and a committed local effect barrier before success.
- `MPRD_RegistryPolicyAuthority.lean`: a lightweight proof of the registry-backed policy admission boundary: a node only resolves a live policy after a selected trusted authority mode, manifest verification, exact `policy_ref` alignment, policy authorization, and image routing.
- `MPRD_ParallelIndependenceOracle.lean`: a lightweight local theorem for pre/post-condition-guided parallelization: speculative evaluation and cache refresh commute and preserve the serial authority barrier, while committed states still require all existing commit guards and private committed states additionally require Mode C key admission.

## How to typecheck

From the repo root:

```bash
cd proofs/lean
lake build
```

Or typecheck individual files:

```bash
cd proofs/lean
lake env lean MPRD_Theorem.lean
lake env lean MPRD_Alignment_Combined.lean
lake env lean MPRD_ExecutionLifecycle.lean
lake env lean MPRD_ExecutionGate.lean
lake env lean MPRD_ExecutionCommitmentBindings.lean
lake env lean MPRD_ExecutionBoundary.lean
lake env lean MPRD_ExecutionReadyPacketBoundary.lean
lake env lean MPRD_ExecutionReadyPacketRefinement.lean
lake env lean MPRD_ExecutionReadyRefinementWitnessCompiler.lean
lake env lean MPRD_ExecutionReadyRuntimeRefinement.lean
lake env lean MPRD_ExecutionBindingVectorPacketBoundary.lean
lake env lean MPRD_ExecutionBoundaryRefinementPacketBoundary.lean
lake env lean MPRD_AttestationReadyExecutionAuthorizationBoundary.lean
lake env lean MPRD_ExecutionAuthorizationMetadataPacketBoundary.lean
lake env lean MPRD_ExecutionAuthorizationWitnessProjection.lean
lake env lean MPRD_ExecutionRegistryBridgeWitnessProjection.lean
lake env lean MPRD_SelectorContractBinding.lean
lake env lean MPRD_TauPolicyAuthority.lean
lake env lean MPRD_GovernedPolicySource.lean
lake env lean MPRD_GovernedSourceIntentBoundary.lean
lake env lean MPRD_GovernedSourceArtifactWitness.lean
lake env lean MPRD_GovernanceGateAuthorization.lean
lake env lean MPRD_GovernanceStateLinkage.lean
lake env lean MPRD_GovernanceExecutionBridge.lean
lake env lean MPRD_SignedRegistryCheckpointBridge.lean
lake env lean MPRD_SignedRegistryBridgeMetadataPacketBoundary.lean
lake env lean MPRD_SignedRegistryExecutionBoundaryRefinement.lean
lake env lean MPRD_SignedRegistryExecutionMetadataPacketBoundary.lean
lake env lean MPRD_SignedRegistryExecutionRefinementPacketBoundary.lean
lake env lean MPRD_SignedRegistryExecutionRefinementWitnessCompiler.lean
lake env lean MPRD_SignedRegistryExecutionExactPacketWitnessCompiler.lean
lake env lean MPRD_SignedRegistryExecutionExactPacketRuntimeRefinement.lean
lake env lean MPRD_SignedRegistryExecutionArtifactRuntimeRefinement.lean
lake env lean MPRD_SignedRegistryBridgeWitnessBoundary.lean
lake env lean MPRD_SignedRegistryExecutionBoundary.lean
lake env lean MPRD_SignedRegistryServeEndToEndRefinement.lean
lake env lean MPRD_SignedRegistryServeExecutionBoundaryRefinement.lean
lake env lean MPRD_SignedRegistryServeBoundary.lean
lake env lean MPRD_SignedRegistryServeReadyPacketBoundary.lean
lake env lean MPRD_SignedRegistryServeAttestationHashBoundary.lean
lake env lean MPRD_SignedRegistryServeAttestationHashReadyPacketBoundary.lean
lake env lean MPRD_SignedRegistryServeAttestationHashRefinement.lean
lake env lean MPRD_SignedRegistryServeAttestationHashArtifactBoundary.lean
lake env lean MPRD_SignedRegistryServeAttestationHashExactPacketRefinement.lean
lake env lean MPRD_SignedRegistryServeAttestationHashIdempotentHttpComposition.lean
lake env lean MPRD_SignedRegistryServeIdempotentFileBoundary.lean
lake env lean MPRD_SignedRegistryServeIdempotentHttpBoundary.lean
lake env lean MPRD_RegistryPolicyAuthority.lean
lake env lean MPRD_ParallelIndependenceOracle.lean
```

## Notes

- These proofs are **Lean core only** (no Mathlib dependency) to keep builds fast.
- The economics → “ethical policy selection” step is intentionally modeled as an
  **explicit axiom** in `MPRD_Alignment_Combined.lean`; this file is a *bridge*
  lemma, not a full economic development.
