# Neuro-Symbolic Disaster Loop

Generated: `2026-04-24T23:25:52Z`
Max composition depth: `11`
Frontier exhausted: `True`
Composition edge source: `atlas`
Re-entry edge source: `atlas`
Stable receipt hash: `sha256:b83ee1178c4bea460b9c7e3c67d5ccf1d7ac330e017746236fcfc7274c459561`
Current git head: `747bba207e8198b44787196aef25fa0a888dc561`
Gate worktree clean: `True`

## Summary

- Research gate: `OPEN_FOR_BOUNDED_RESEARCH`
- Hypotheses checked: `16003`
- Reachable disaster witnesses: `0`
- Unknown / blocked: `0`
- Bounded no-witness: `16003`
- Researchable under current bounded receipts: `16003`
- Blocked for promotion due optional instability: `0`
- Synthetic receipt mutations checked: `66`
- Synthetic fail-closed failures: `0`
- Synthetic blocker mutations checked: `22`
- Synthetic blocker fail-closed failures: `0`
- Synthetic provenance mutations checked: `16`
- Synthetic provenance fail-closed failures: `0`
- Synthetic optional-conflict mutations checked: `25`
- Synthetic optional-conflict expectation failures: `0`
- Optional-evidence blocked surfaces: `0`
- Dominant optional block: `None` / `0`
- Blocked hypothesis families: `0`
- Receipt git-head mismatches: `0`
- Receipt git-head compatible drifts: `12`
- Gate-relevant dirty paths: `0`
- Compressed independent frontier: `75599999` what-ifs through order `11`
- Result storage mode: `compact`

## Verdict Counts

- `NO_REACHABLE_WITNESS_BOUNDED`: `16003`

## Hypothesis Families

- `blocker_bypass_disaster`: `194`
- `chain_researchability`: `71`
- `chain_terminal_disaster`: `1079`
- `convergence_composition_disaster`: `299`
- `cycle_amplification_disaster`: `66`
- `edge_composition_disaster`: `196`
- `fanout_composition_disaster`: `64`
- `independent_pair_coreachability`: `1000`
- `independent_triple_coreachability`: `12714`
- `order_inversion_disaster`: `196`
- `receipt_fail_open_mutation`: `11`
- `reentry_retry_disaster`: `66`
- `single_surface_disaster`: `47`

## Researchability Counts

- `researchable_under_current_bounded_receipts`: `16003`

## Synthetic Receipt-State Mutations

- Checked: `66`
- Fail-closed observed: `66`
- Fail-closed failures: `0`
- `NO_REACHABLE_WITNESS_BOUNDED`: `11`
- `UNKNOWN_BLOCKED`: `55`

## Synthetic Blocker-State Mutations

- Checked: `22`
- Fail-closed observed: `22`
- Fail-closed failures: `0`
- `UNKNOWN_BLOCKED`: `22`

## Synthetic Provenance-State Mutations

- Checked: `16`
- Fail-closed observed: `16`
- Fail-closed failures: `0`
- `mandatory`: `11`
- `optional`: `5`

## Synthetic Optional-Conflict Mutations

- Checked: `25`
- Expected outcomes observed: `25`
- Expectation failures: `0`
- expected `blocked_for_promotion_due_optional_instability`: `20`
- expected `researchable_under_current_bounded_receipts`: `5`
- observed `blocked_for_promotion_due_optional_instability`: `20`
- observed `researchable_under_current_bounded_receipts`: `5`

## Frontier

- Surface count: `11`
- Max simple path depth: `11`
- Requested composition depth: `0`
- Effective composition depth: `11`
- Simple path frontier exhausted: `True`

## Optional Evidence Blocks

- none

## Research Block Frontier

- Gate: `OPEN_FOR_BOUNDED_RESEARCH`
- Open for bounded research: `True`
- Gate blockers: none
- Single-surface optional cut clears all blocks: `False`
- none

## Blocked Families

- `blocker_bypass_disaster`: total `194`, researchable `194`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `chain_researchability`: total `71`, researchable `71`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `chain_terminal_disaster`: total `1079`, researchable `1079`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `convergence_composition_disaster`: total `299`, researchable `299`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `cycle_amplification_disaster`: total `66`, researchable `66`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `edge_composition_disaster`: total `196`, researchable `196`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `fanout_composition_disaster`: total `64`, researchable `64`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `independent_pair_coreachability`: total `1000`, researchable `1000`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `independent_triple_coreachability`: total `12714`, researchable `12714`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `order_inversion_disaster`: total `196`, researchable `196`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `receipt_fail_open_mutation`: total `11`, researchable `11`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `reentry_retry_disaster`: total `66`, researchable `66`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`
- `single_surface_disaster`: total `47`, researchable `47`, optional-blocked `0`, mandatory/unknown `0`, reachable `0`

## Receipt Provenance

- Current git head: `747bba207e8198b44787196aef25fa0a888dc561`
- `mandatory` receipts: total `14`, exists `14`, with git head `12`, matching `0`, compatible drift `12`, mismatched `0`, missing git head `2`
- `optional` receipts: total `16`, exists `16`, with git head `0`, matching `0`, compatible drift `0`, mismatched `0`, missing git head `16`
- Git-head mismatches: none
- compatible drift `decision_token_proof_journal_binding` `mandatory` `internal/assurance/sota_stack/receipts/decoded_journal_metamorphic_v3_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `decision_token_proof_journal_binding` `mandatory` `internal/assurance/sota_stack/receipts/decision_token_proof_journal_binding_guided_v1_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `executor_side_effect_boundary` `mandatory` `internal/assurance/sota_stack/receipts/executor_side_effect_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `executor_side_effect_boundary` `mandatory` `internal/assurance/sota_stack/receipts/executor_side_effect_state_machine_guided_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `executor_transport_boundary` `mandatory` `internal/assurance/sota_stack/receipts/executor_transport_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `orchestrator_pipeline_ordering` `mandatory` `internal/assurance/sota_stack/receipts/orchestrator_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `policy_artifact_run_lifecycle` `mandatory` `internal/assurance/sota_stack/receipts/policy_artifact_runtime_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `quorum_snapshot_attestation` `mandatory` `internal/assurance/sota_stack/receipts/quorum_snapshot_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `registry_key_rotation_authorization` `mandatory` `internal/assurance/sota_stack/receipts/registry_key_rotation_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `replay_nonce_claim` `mandatory` `internal/assurance/sota_stack/receipts/anti_replay_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `selector_candidate_family` `mandatory` `internal/assurance/sota_stack/receipts/selector_candidate_family_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`
- compatible drift `tau_policy_certification_boundary` `mandatory` `internal/assurance/sota_stack/receipts/tau_policy_certification_state_machine_latest.json` from `80cfe7fb9d52085b8683687eea24ba5f426962dc` via `tools/run_neuro_symbolic_disaster_loop.py`

## Gate Worktree

- Checked paths: `tools/run_neuro_symbolic_disaster_loop.py`
- dirty paths: none

## Result Storage

- Mode: `compact`
- Full results included: `False`
- `results`: count `16003`, hash `sha256:a0351ba0ca626bdf98a8aa3a37dc8cf4e1ec4f7a5e15534182bd0a02097b014a`
- `synthetic_blocker_results`: count `22`, hash `sha256:2088740cf3db32b44a80c555e49be3bf629edbee6c84ca294799f472d634eceb`
- `synthetic_mutation_results`: count `66`, hash `sha256:08bc290d61eb3b008c1e74a2528da0670e1540b6dfe5cbca9f46505c3cbc8d09`
- `synthetic_optional_conflict_results`: count `25`, hash `sha256:425133db6df25bee749a15d23793fc43a7a173ca9c6a73555501bc24855d5441`
- `synthetic_provenance_results`: count `16`, hash `sha256:8b1af963fa8531d46174bba2884337dd1d1a86c8a8a5e1cc2478ce75af901083`

## Compressed Independent Frontier

- Total independent co-reachability what-ifs: `75599999`
- Researchable: `75599999`
- Optional blocked: `0`
- Mandatory blocked: `0`
- order `1`: total `47`, researchable `47`, optional-blocked `0`, mandatory-blocked `0`
- order `2`: total `1000`, researchable `1000`, optional-blocked `0`, mandatory-blocked `0`
- order `3`: total `12714`, researchable `12714`, optional-blocked `0`, mandatory-blocked `0`
- order `4`: total `107325`, researchable `107325`, optional-blocked `0`, mandatory-blocked `0`
- order `5`: total `631599`, researchable `631599`, optional-blocked `0`, mandatory-blocked `0`
- order `6`: total `2644058`, researchable `2644058`, optional-blocked `0`, mandatory-blocked `0`
- order `7`: total `7873720`, researchable `7873720`, optional-blocked `0`, mandatory-blocked `0`
- order `8`: total `16344896`, researchable `16344896`, optional-blocked `0`, mandatory-blocked `0`
- order `9`: total `22525440`, researchable `22525440`, optional-blocked `0`, mandatory-blocked `0`
- order `10`: total `18547200`, researchable `18547200`, optional-blocked `0`, mandatory-blocked `0`
- order `11`: total `6912000`, researchable `6912000`, optional-blocked `0`, mandatory-blocked `0`

## Counterfactual Unblock

- Not applicable: `no_optional_research_blocks`

## Promotion / Research Blocks

- none

## Scope

This receipt exhausts generated single-surface, receipt-fail-open, edge-composition, independent-pair and independent-triple co-reachability, order-inversion, bounded-chain, chain-terminal, fan-out, convergence, re-entry, and cycle-amplification hypotheses over the current atlas/receipt witness space. It also summarizes the full independent co-reachability frontier through order 11 in compressed form and runs synthetic receipt-state, blocker-state, provenance-state, and optional-conflict mutation checks. It is not a global proof of safety.
