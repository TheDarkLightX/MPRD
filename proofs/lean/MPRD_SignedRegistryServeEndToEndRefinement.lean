/- 
  MPRD_SignedRegistryServeEndToEndRefinement.lean

  A lightweight composed refinement bridge for the shipped signed-registry
  `mprd serve` path:

    executed signed-registry serve states refine through the grouped local
    `ExecutionReadyPacketV1` boundary and then into the abstract
    `MPRD_ExecutionBoundary` theorem.

  This still remains witness-gated. It narrows the RC1 blocker from "there is
  no top-level theorem through the grouped packet" to "the remaining gap is
  discharging the refinement witness from concrete runtime objects without an
  extra premise".
-/

import MPRD_ExecutionReadyArtifactRuntimeRefinement
import MPRD_ExecutionReadyPacketRefinement
import MPRD_ExecutionReadyRuntimeRefinement
import MPRD_SignedRegistryServeReadyPacketBoundary

namespace MPRDSignedRegistryServeEndToEndRefinement

def proof_bundle_version : String := "mprd-leanproofs-v1"

abbrev ServeState := MPRDSignedRegistryServeReadyPacketBoundary.State
abbrev PacketState := MPRDExecutionReadyPacketBoundary.State
abbrev ExecutionReadyArtifact :=
  MPRDExecutionReadyArtifactRuntimeRefinement.ExecutionReadyArtifact

def refinementWitnessOfServeState (s : ServeState) :
    MPRDExecutionReadyPacketRefinement.RefinementWitness :=
  { verdict := if s.allowed then MPRDExecutionBoundary.Verdict.allowed
      else MPRDExecutionBoundary.Verdict.denied
    governanceOk := s.governanceAligned
    bindings :=
      { journalAllowed := s.bindingOk
        limitsHashMatches := s.bindingOk
        decisionCommitmentValid := s.bindingOk
        policyHashMatches := s.bindingOk
        policyEpochMatches := s.bindingOk
        registryRootMatches := s.bindingOk
        stateSourceMatches := s.bindingOk
        stateEpochMatches := s.bindingOk
        stateAttestationMatches := s.bindingOk
        stateHashMatches := s.bindingOk
        candidateSetHashMatches := s.bindingOk
        chosenActionHashMatches := s.bindingOk
        nonceMatches := s.bindingOk }
    executorGate :=
      { preimagePresent := s.executorOk
        limitsBytesBindingOk := s.executorOk
        actionPreimageHashMatches := s.executorOk
        schemaValid := s.executorOk } }

def runtimeRefinementWitnessOfServeState (s : ServeState) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitness :=
  { governanceAdmitted := s.governanceAligned
    signatureAdmitted := s.signatureAdmitted
    stateProvenanceAdmitted := s.stateProvenanceAdmitted
    replayAdmitted := s.replayAdmitted
    bindings :=
      { journalAllowed := s.bindingOk
        limitsHashMatches := s.bindingOk
        decisionCommitmentValid := s.bindingOk
        policyHashMatches := s.bindingOk
        policyEpochMatches := s.bindingOk
        registryRootMatches := s.bindingOk
        stateSourceMatches := s.bindingOk
        stateEpochMatches := s.bindingOk
        stateAttestationMatches := s.bindingOk
        stateHashMatches := s.bindingOk
        candidateSetHashMatches := s.bindingOk
        chosenActionHashMatches := s.bindingOk
        nonceMatches := s.bindingOk }
    executorGate :=
      { preimagePresent := s.executorOk
        limitsBytesBindingOk := s.executorOk
        actionPreimageHashMatches := s.executorOk
        schemaValid := s.executorOk } }

def mapServeExec :
    MPRDSignedRegistryServeReadyPacketBoundary.ExecStatus ->
      MPRDExecutionReadyPacketBoundary.ExecStatus
  | .skipped => .skipped
  | .succeeded => .succeeded
  | .failed => .failed

def packetViewOfServeState (s : ServeState) : PacketState :=
  { boundaryAdmitted := s.boundaryAdmitted
    authorizationAdmitted := s.executionAuthorizationBound
    bridgeAdmitted := s.checkpointBound
    signatureAdmitted := s.signatureAdmitted
    stateProvenanceAdmitted := s.stateProvenanceAdmitted
    replayAdmitted := s.replayAdmitted
    packetGrouped := s.packetGrouped
    readyVisible := s.readyVisible
    exec := mapServeExec s.exec }

def groupedPacketReadySkipped : PacketState :=
  { boundaryAdmitted := true
    authorizationAdmitted := true
    bridgeAdmitted := true
    signatureAdmitted := true
    stateProvenanceAdmitted := true
    replayAdmitted := true
    packetGrouped := true
    readyVisible := true
    exec := .skipped }

def groupedPacketSuccess : PacketState :=
  { groupedPacketReadySkipped with exec := .succeeded }

def groupedPacketFailure : PacketState :=
  { groupedPacketReadySkipped with exec := .failed }

def executionReadyArtifactOfServeState (s : ServeState) : ExecutionReadyArtifact :=
  { executionBindingVector :=
      if s.bindingOk = true then
        some
          { decisionCommitment := 1
            policyHash := 1
            policyRef := { policyEpoch := 1, registryRoot := 1 }
            stateRef :=
              { stateSourceId := 1
                stateEpoch := 1
                stateAttestationHash := 1 }
            stateHash := 1
            candidateSetHash := 1
            chosenActionHash := 1
            nonceOrTxHash := 1
            limitsHash := 1 }
      else
        none
    executionBoundaryRefinement :=
      if s.packetGrouped = true ∧ s.executionAuthorizationBound = true then
        some
          { executionReadyPacketHash := 1
            attestationMetadataHash := 1 }
      else
        none
    executionAuthorizationMetadata :=
      if s.executionAuthorizationBound = true ∧ s.governanceAligned = true then
        some
          { executionAuthorization :=
              { policyHash := 1
                policyRef := { policyEpoch := 1, registryRoot := 1 }
                stateHash := 1
                stateRef :=
                  { stateSourceId := 1
                    stateEpoch := 1
                    stateAttestationHash := 1 }
                governance :=
                  some
                    { updateKind := .policyTweak
                      profileAppOk := true
                      profileSafetyOk := true
                      linkOk := true } }
            executionAuthorizationHash := 1 }
      else
        none }

theorem reachable_grouped_packet_ready_skipped :
    MPRDExecutionReadyPacketBoundary.Reachable groupedPacketReadySkipped := by
  let s0 : PacketState :=
    { boundaryAdmitted := false
      authorizationAdmitted := false
      bridgeAdmitted := false
      signatureAdmitted := false
      stateProvenanceAdmitted := false
      replayAdmitted := false
      packetGrouped := false
      readyVisible := false
      exec := .skipped }
  have h0 : MPRDExecutionReadyPacketBoundary.Initial s0 := by
    simp [s0, MPRDExecutionReadyPacketBoundary.Initial]
  have hReach0 : MPRDExecutionReadyPacketBoundary.Reachable s0 :=
    MPRDExecutionReadyPacketBoundary.Reachable.init h0
  have hReach1 :
      MPRDExecutionReadyPacketBoundary.Reachable { s0 with boundaryAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach0
      (MPRDExecutionReadyPacketBoundary.Step.admit_boundary s0 rfl rfl)
  have hReach2 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach1
      (MPRDExecutionReadyPacketBoundary.Step.admit_authorization
        { s0 with boundaryAdmitted := true } rfl rfl rfl)
  have hReach3 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
            with bridgeAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach2
      (MPRDExecutionReadyPacketBoundary.Step.admit_bridge
        { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
        rfl rfl rfl)
  have hReach4 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
              with bridgeAdmitted := true } with signatureAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach3
      (MPRDExecutionReadyPacketBoundary.Step.admit_signature
        { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
            with bridgeAdmitted := true }
        rfl rfl rfl)
  have hReach5 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                with bridgeAdmitted := true } with signatureAdmitted := true }
            with stateProvenanceAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach4
      (MPRDExecutionReadyPacketBoundary.Step.admit_state_provenance
        { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
              with bridgeAdmitted := true } with signatureAdmitted := true }
        rfl rfl rfl)
  have hReach6 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                  with bridgeAdmitted := true } with signatureAdmitted := true }
              with stateProvenanceAdmitted := true } with replayAdmitted := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach5
      (MPRDExecutionReadyPacketBoundary.Step.admit_replay
        { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                with bridgeAdmitted := true } with signatureAdmitted := true }
            with stateProvenanceAdmitted := true }
        rfl rfl rfl)
  have hReach7 :
      MPRDExecutionReadyPacketBoundary.Reachable
        { { { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                    with bridgeAdmitted := true } with signatureAdmitted := true }
                with stateProvenanceAdmitted := true } with replayAdmitted := true }
            with packetGrouped := true } :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach6
      (MPRDExecutionReadyPacketBoundary.Step.group_packet
        { { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                  with bridgeAdmitted := true } with signatureAdmitted := true }
              with stateProvenanceAdmitted := true } with replayAdmitted := true }
        rfl rfl rfl rfl rfl rfl rfl rfl)
  have hReach8 :
      MPRDExecutionReadyPacketBoundary.Reachable groupedPacketReadySkipped :=
    MPRDExecutionReadyPacketBoundary.Reachable.step hReach7
      (MPRDExecutionReadyPacketBoundary.Step.expose_ready
        { { { { { { { s0 with boundaryAdmitted := true } with authorizationAdmitted := true }
                    with bridgeAdmitted := true } with signatureAdmitted := true }
                with stateProvenanceAdmitted := true } with replayAdmitted := true }
            with packetGrouped := true }
        rfl rfl rfl)
  simpa [groupedPacketReadySkipped] using hReach8

theorem reachable_grouped_packet_success :
    MPRDExecutionReadyPacketBoundary.Reachable groupedPacketSuccess := by
  exact MPRDExecutionReadyPacketBoundary.Reachable.step
    reachable_grouped_packet_ready_skipped
    (MPRDExecutionReadyPacketBoundary.Step.execute_success groupedPacketReadySkipped
      rfl rfl rfl)

theorem reachable_grouped_packet_failure :
    MPRDExecutionReadyPacketBoundary.Reachable groupedPacketFailure := by
  exact MPRDExecutionReadyPacketBoundary.Reachable.step
    reachable_grouped_packet_ready_skipped
    (MPRDExecutionReadyPacketBoundary.Step.execute_failed groupedPacketReadySkipped
      rfl rfl rfl)

theorem executed_signed_registry_serve_states_reach_execution_ready_packet
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨hPacket, hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, hCheckpoint, hAuth, _hGovernance, _hVerified,
      _hAllowed, _hBinding, _hExecutor, hBoundary, hSignature, hStateProv,
      hReplay⟩
  cases hExec with
  | inl hSuccess =>
      have hPacketEq : packetViewOfServeState s = groupedPacketSuccess := by
        simp [packetViewOfServeState, mapServeExec, groupedPacketSuccess,
          groupedPacketReadySkipped, hBoundary, hAuth, hCheckpoint, hSignature,
          hStateProv, hReplay, hPacket, hReady, hSuccess]
      exact ⟨by simpa [hPacketEq] using reachable_grouped_packet_success,
        by simpa [hPacketEq] using
          (Or.inl rfl : MPRDExecutionReadyPacketBoundary.Executed groupedPacketSuccess)⟩
  | inr hFailure =>
      have hPacketEq : packetViewOfServeState s = groupedPacketFailure := by
        simp [packetViewOfServeState, mapServeExec, groupedPacketFailure,
          groupedPacketReadySkipped, hBoundary, hAuth, hCheckpoint, hSignature,
          hStateProv, hReplay, hPacket, hReady, hFailure]
      exact ⟨by simpa [hPacketEq] using reachable_grouped_packet_failure,
        by simpa [hPacketEq] using
          (Or.inr rfl : MPRDExecutionReadyPacketBoundary.Executed groupedPacketFailure)⟩

theorem executionReadyArtifactOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyArtifactRuntimeRefinement.ArtifactHolds
      (executionReadyArtifactOfServeState s) := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, hAuth, hGovernance, _hVerified,
      _hAllowed, hBinding, _hExecutor, _hBoundary, _hSignature, _hStateProv,
      _hReplay⟩
  refine ⟨?_, ?_, ?_⟩
  · simp [executionReadyArtifactOfServeState, hBinding]
  · simp [executionReadyArtifactOfServeState, hPacket, hAuth]
  · refine ⟨?_, ?_, ?_⟩
    · exact
        { executionAuthorization :=
            { policyHash := 1
              policyRef := { policyEpoch := 1, registryRoot := 1 }
              stateHash := 1
              stateRef :=
                { stateSourceId := 1
                  stateEpoch := 1
                  stateAttestationHash := 1 }
              governance :=
                some
                  { updateKind := .policyTweak
                    profileAppOk := true
                    profileSafetyOk := true
                    linkOk := true } }
          executionAuthorizationHash := 1 }
    · simp [executionReadyArtifactOfServeState, hAuth, hGovernance]
    · simp

theorem executionReadyArtifactOfServeState_compiles_runtime_witness_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
        (packetViewOfServeState s) (executionReadyArtifactOfServeState s) =
      runtimeRefinementWitnessOfServeState s := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, hAuth, hGovernance, _hVerified,
      _hAllowed, hBinding, hExecutor, hBoundary, hSignature, hStateProv,
      hReplay⟩
  simp [MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness,
    MPRDExecutionReadyArtifactRuntimeRefinement.compileBindings,
    MPRDExecutionReadyArtifactRuntimeRefinement.compileExecutorGate,
    MPRDExecutionReadyArtifactRuntimeRefinement.canonicalBindings,
    MPRDExecutionReadyArtifactRuntimeRefinement.canonicalExecutorGate,
    executionReadyArtifactOfServeState, packetViewOfServeState,
    runtimeRefinementWitnessOfServeState, hPacket, hAuth, hGovernance, hBinding,
    hBoundary, hSignature, hStateProv, hReplay, hExecutor]

theorem executed_signed_registry_serve_states_refine_via_execution_ready_packet
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s)
    {w : MPRDExecutionReadyPacketRefinement.RefinementWitness}
    (hWitness : MPRDExecutionReadyPacketRefinement.RefinementWitnessHolds w) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings = w.bindings ∧
            t.ctx.executorGate = w.executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  rcases executed_signed_registry_serve_states_reach_execution_ready_packet hReach hExec with
    ⟨hPacketReach, hPacketExec⟩
  rcases
      MPRDExecutionReadyPacketRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary
        hPacketReach hPacketExec hWitness with
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
  exact ⟨hPacketReach, hPacketExec, ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩⟩

theorem refinementWitnessOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketRefinement.RefinementWitnessHolds
      (refinementWitnessOfServeState s) := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨_hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, _hAuth, hGovernance, _hVerified,
      hAllowed, hBinding, hExecutor, _hBoundary, _hSignature, _hStateProv, _hReplay⟩
  constructor
  · simp [refinementWitnessOfServeState, hAllowed]
  constructor
  · simpa [refinementWitnessOfServeState] using hGovernance
  constructor
  · simp [MPRDExecutionBoundary.ConcreteBindingsHold, refinementWitnessOfServeState, hBinding]
  · simp [MPRDExecutionBoundary.ExecutorGateHold, refinementWitnessOfServeState, hExecutor]

theorem runtimeRefinementWitnessOfServeState_holds_for_executed_states
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyRefinementWitnessCompiler.RuntimeRefinementWitnessHolds
      (runtimeRefinementWitnessOfServeState s) := by
  rcases
      MPRDSignedRegistryServeReadyPacketBoundary.executed_reachable_states_require_signed_registry_serve_ready_packet_boundary
        hReach hExec with
    ⟨_hPacket, _hReady, _hRegistryAnchor, _hStateAnchor, _hPolicy, _hVerifier,
      _hBridge, _hResolved, _hCheckpoint, _hAuth, hGovernance, _hVerified,
      _hAllowed, hBinding, hExecutor, _hBoundary, hSignature, hStateProv, hReplay⟩
  constructor
  · simpa [runtimeRefinementWitnessOfServeState] using hGovernance
  constructor
  · simpa [runtimeRefinementWitnessOfServeState] using hSignature
  constructor
  · simpa [runtimeRefinementWitnessOfServeState] using hStateProv
  constructor
  · simpa [runtimeRefinementWitnessOfServeState] using hReplay
  constructor
  · simp [MPRDExecutionBoundary.ConcreteBindingsHold, runtimeRefinementWitnessOfServeState, hBinding]
  · simp [MPRDExecutionBoundary.ExecutorGateHold, runtimeRefinementWitnessOfServeState, hExecutor]

theorem executed_signed_registry_serve_states_refine_to_execution_boundary_via_runtime_witness
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings =
              (runtimeRefinementWitnessOfServeState s).bindings ∧
            t.ctx.executorGate =
              (runtimeRefinementWitnessOfServeState s).executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  let a := executionReadyArtifactOfServeState s
  have hArtifact :
      MPRDExecutionReadyArtifactRuntimeRefinement.ArtifactHolds a := by
    simpa [a] using executionReadyArtifactOfServeState_holds_for_executed_states hReach hExec
  rcases executed_signed_registry_serve_states_reach_execution_ready_packet hReach hExec with
    ⟨hPacketReach, hPacketExec⟩
  rcases
      MPRDExecutionReadyArtifactRuntimeRefinement.executed_execution_ready_packet_states_refine_to_execution_boundary_from_artifact
        hPacketReach hPacketExec hArtifact with
    ⟨t, hBindings, hExecutorGate, hAbsReach, hAbsExec, hAbsBoundary⟩
  have hCompileEq :
      MPRDExecutionReadyArtifactRuntimeRefinement.compileRuntimeWitness
          (packetViewOfServeState s) a =
        runtimeRefinementWitnessOfServeState s := by
    simpa [a] using
      executionReadyArtifactOfServeState_compiles_runtime_witness_for_executed_states hReach hExec
  have hBindings' :
      t.ctx.bindings = (runtimeRefinementWitnessOfServeState s).bindings := by
    simpa [hCompileEq] using hBindings
  have hExecutorGate' :
      t.ctx.executorGate = (runtimeRefinementWitnessOfServeState s).executorGate := by
    simpa [hCompileEq] using hExecutorGate
  exact ⟨hPacketReach, hPacketExec,
    ⟨t, hBindings', hExecutorGate', hAbsReach, hAbsExec, hAbsBoundary⟩⟩

theorem executed_signed_registry_serve_states_refine_to_execution_boundary
    {s : ServeState}
    (hReach : MPRDSignedRegistryServeReadyPacketBoundary.Reachable s)
    (hExec : MPRDSignedRegistryServeReadyPacketBoundary.Executed s) :
    MPRDExecutionReadyPacketBoundary.Reachable (packetViewOfServeState s) ∧
      MPRDExecutionReadyPacketBoundary.Executed (packetViewOfServeState s) ∧
        (∃ t : MPRDExecutionBoundary.State,
          t.ctx.bindings =
              (refinementWitnessOfServeState s).bindings ∧
            t.ctx.executorGate =
              (refinementWitnessOfServeState s).executorGate ∧
              MPRDExecutionBoundary.Reachable t ∧
                MPRDExecutionBoundary.Executed t ∧
                  MPRDExecutionBoundary.ExecutedImpliesFullBoundaryGate t) := by
  have hRuntime :=
    executed_signed_registry_serve_states_refine_to_execution_boundary_via_runtime_witness
      hReach hExec
  simpa [runtimeRefinementWitnessOfServeState, refinementWitnessOfServeState] using hRuntime

end MPRDSignedRegistryServeEndToEndRefinement

abbrev executed_signed_registry_serve_states_refine_via_execution_ready_packet_v1 :=
  @MPRDSignedRegistryServeEndToEndRefinement.executed_signed_registry_serve_states_refine_via_execution_ready_packet

abbrev executed_signed_registry_serve_states_refine_to_execution_boundary_via_runtime_witness_v1 :=
  @MPRDSignedRegistryServeEndToEndRefinement.executed_signed_registry_serve_states_refine_to_execution_boundary_via_runtime_witness

abbrev executed_signed_registry_serve_states_refine_to_execution_boundary_no_witness_v1 :=
  @MPRDSignedRegistryServeEndToEndRefinement.executed_signed_registry_serve_states_refine_to_execution_boundary
