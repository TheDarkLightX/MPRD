#!/usr/bin/env python3
"""Bounded neuro-symbolic disaster-state loop for the MPRD SOTA atlas.

The "neural" part is represented as explicit what-if hypothesis generation over
surfaces, danger states, and known cross-surface compositions.  The symbolic part
is deterministic: it checks the danger atlas and replayable receipts, then emits a
bounded verdict with either a witness pointer, a research block, or an exhausted
no-witness result.

This is not a proof of global safety.  It is a fail-closed bounded gate over the
current witness space.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import combinations
from math import prod
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SOTA = ROOT / "internal" / "assurance" / "sota_stack"
ATLAS = SOTA / "danger_atlas.json"
RECEIPTS = SOTA / "receipts"
DEFAULT_JSON = RECEIPTS / "neuro_symbolic_disaster_loop_latest.json"
DEFAULT_MD = RECEIPTS / "neuro_symbolic_disaster_loop_latest.md"
OPTIONAL_BLOCKING_DECISIONS = {
    "mixed_optional_lane",
    "reject_optional_parallel_lane",
    "reject_next_guided_candidate_for_now",
}
OPTIONAL_STABLE_DECISIONS = {
    "stable_optional_lane",
}
HARNESS_SOURCE_HINTS = {
    "orchestrator_ordering_symbolic": [
        "internal/experiments/concolic_20260405/src/bin/orchestrator-ordering-kani.rs",
    ],
    "operator_control_lifecycle": [
        "internal/experiments/concolic_20260405/src/bin/operator-control-lifecycle.rs",
    ],
}


DEFAULT_COMPOSITION_EDGES: tuple[tuple[str, str, str], ...] = (
    (
        "registry_key_rotation_authorization",
        "policy_artifact_run_lifecycle",
        "registry authorization controls policy artifact materialization",
    ),
    (
        "policy_artifact_run_lifecycle",
        "tau_policy_certification_boundary",
        "authorized policy artifacts feed Tau certification",
    ),
    (
        "tau_policy_certification_boundary",
        "selector_candidate_family",
        "certified policy semantics constrain selector admissibility",
    ),
    (
        "policy_artifact_run_lifecycle",
        "selector_candidate_family",
        "authorized policy artifacts constrain selectable candidates",
    ),
    (
        "selector_candidate_family",
        "orchestrator_pipeline_ordering",
        "selector output enters the orchestrator pipeline",
    ),
    (
        "quorum_snapshot_attestation",
        "orchestrator_pipeline_ordering",
        "trusted state provenance gates orchestrator decisions",
    ),
    (
        "orchestrator_pipeline_ordering",
        "decision_token_proof_journal_binding",
        "orchestrator outputs become proof/journal commitments",
    ),
    (
        "decision_token_proof_journal_binding",
        "replay_nonce_claim",
        "bound decision tokens must clear replay before side effects",
    ),
    (
        "replay_nonce_claim",
        "executor_side_effect_boundary",
        "replay clearance precedes local executor side effects",
    ),
    (
        "executor_side_effect_boundary",
        "executor_transport_boundary",
        "local execution boundary precedes network transport",
    ),
    (
        "operator_control_lifecycle",
        "orchestrator_pipeline_ordering",
        "operator control-plane state influences orchestrator behavior",
    ),
)


DEFAULT_REENTRY_EDGES: tuple[tuple[str, str, str], ...] = (
    (
        "executor_transport_boundary",
        "replay_nonce_claim",
        "transport retry or duplicate delivery re-presents a previously cleared claim",
    ),
    (
        "executor_side_effect_boundary",
        "replay_nonce_claim",
        "local retry after a side-effect attempt can re-enter replay clearance",
    ),
    (
        "decision_token_proof_journal_binding",
        "orchestrator_pipeline_ordering",
        "journal replay or audit reconstruction can re-enter orchestrator ordering",
    ),
    (
        "tau_policy_certification_boundary",
        "policy_artifact_run_lifecycle",
        "certification repair can request a new policy artifact run",
    ),
)


RECEIPT_STATE_MUTATIONS: tuple[tuple[str, str, str], ...] = (
    (
        "missing_mandatory_receipt",
        "mandatory",
        "the mandatory replay receipt disappeared before promotion",
    ),
    (
        "receipt_ok_false",
        "mandatory",
        "the mandatory replay receipt reported ok=false",
    ),
    (
        "nonzero_return_code",
        "mandatory",
        "the mandatory replay receipt reported a nonzero return code",
    ),
    (
        "artifact_delta",
        "mandatory",
        "the mandatory replay receipt reported generated artifact drift",
    ),
    (
        "stale_after_atlas_update",
        "mandatory",
        "the mandatory replay receipt was older than the atlas update it claims to cover",
    ),
    (
        "optional_lane_mixed",
        "optional",
        "the optional guided lane was still mixed while downstream research tried to use it",
    ),
)


BLOCKER_STATE_MUTATIONS: tuple[tuple[str, str], ...] = (
    (
        "blocker_source_missing",
        "a blocker/checker symbol disappeared from its source module",
    ),
    (
        "blocker_harness_unreferenced",
        "a blocker/checker symbol stopped being exercised by its stateful harness",
    ),
)


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    kind: str
    surfaces: tuple[str, ...]
    danger_states: tuple[str, ...]
    what_if: str


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def load_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def load_edge_family(
    atlas: dict[str, Any], field: str, defaults: tuple[tuple[str, str, str], ...]
) -> tuple[tuple[tuple[str, str, str], ...], str]:
    raw_edges = atlas.get(field)
    if raw_edges is None:
        return defaults, "tool_default"
    if not isinstance(raw_edges, list):
        raise ValueError(f"{field} must be a list when present")

    edges: list[tuple[str, str, str]] = []
    for index, item in enumerate(raw_edges):
        if not isinstance(item, dict):
            raise ValueError(f"{field}[{index}] must be an object")
        src = item.get("src")
        dst = item.get("dst")
        reason = item.get("reason")
        if not all(isinstance(value, str) and value for value in (src, dst, reason)):
            raise ValueError(f"{field}[{index}] requires non-empty string src, dst, reason")
        edges.append((src, dst, reason))
    return tuple(edges), "atlas"


def validate_edge_refs(
    edges: tuple[tuple[str, str, str], ...], surface_ids: set[str], family: str
) -> None:
    missing = sorted(
        {
            endpoint
            for src, dst, _ in edges
            for endpoint in (src, dst)
            if endpoint not in surface_ids
        }
    )
    if missing:
        raise ValueError(f"{family} reference missing surfaces: {', '.join(missing)}")


def source_hits(text: str, needle: str) -> list[int]:
    if not needle:
        return []
    return [index for index, line in enumerate(text.splitlines(), start=1) if needle in line]


def harness_paths(target: str) -> list[Path]:
    if target in HARNESS_SOURCE_HINTS:
        return [ROOT / path for path in HARNESS_SOURCE_HINTS[target]]
    fuzz_target = ROOT / "fuzz" / "fuzz_targets" / f"{target}.rs"
    if fuzz_target.exists():
        return [fuzz_target]
    return []


def receipt_ok(receipt: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if receipt.get("ok") is not True:
        reasons.append("receipt_ok_false")
    if receipt.get("return_code") not in (None, 0):
        reasons.append(f"return_code_{receipt.get('return_code')}")
    artifacts = receipt.get("artifacts")
    if isinstance(artifacts, dict) and artifacts.get("delta_files", 0) not in (0, None):
        reasons.append(f"artifact_delta_{artifacts.get('delta_files')}")
    if receipt.get("campaign_kind") == "runtime_mutation" and receipt.get("tests_passed") is False:
        reasons.append("runtime_tests_failed")
    return not reasons, reasons


def surface_receipts(surface: dict[str, Any]) -> list[Path]:
    paths = []
    for value in surface.get("campaign_receipts", []):
        paths.append(ROOT / value)
    return paths


def optional_receipts(surface: dict[str, Any]) -> list[Path]:
    paths = []
    for value in surface.get("optional_parallel_receipts", []):
        paths.append(ROOT / value)
    return paths


def check_optional_receipts(surface: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    summaries = []
    blockers = []
    for path in optional_receipts(surface):
        receipt = load_json(path)
        if receipt is None:
            rel_path = rel(path)
            blockers.append(f"optional_missing_receipt:{rel_path}")
            summaries.append(
                {
                    "path": rel_path,
                    "exists": False,
                    "schema": None,
                    "git_head": None,
                    "decision": None,
                    "next_guidance_decision": None,
                    "blocking": True,
                    "reasons": ["missing_receipt"],
                }
            )
            continue

        decision = receipt.get("decision")
        next_guidance = receipt.get("next_guidance_decision")
        reasons = []
        if decision in OPTIONAL_BLOCKING_DECISIONS:
            reasons.append(f"decision:{decision}")
        if next_guidance in OPTIONAL_BLOCKING_DECISIONS:
            reasons.append(f"next_guidance_decision:{next_guidance}")

        summary = {
            "path": rel(path),
            "exists": True,
            "schema": receipt.get("schema"),
            "git_head": receipt.get("git_head"),
            "decision": decision,
            "next_guidance_decision": next_guidance,
            "stabilizes_optional_lane": decision in OPTIONAL_STABLE_DECISIONS,
            "blocking": bool(reasons),
            "reasons": reasons,
        }
        summaries.append(summary)
        if reasons:
            blockers.extend(f"{reason}:{rel(path)}" for reason in reasons)
    return summaries, blockers


def check_blockers(surface: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    blocker_checks = []
    problems = []
    harnesses = surface.get("harnesses", [])
    for blocker in surface.get("blocker_functions", []):
        symbol = blocker["symbol"]
        source_path = ROOT / blocker["source_path"]
        source_lines = source_hits(load_text(source_path), blocker["source_match"])
        source_present = bool(source_lines)
        if not source_present:
            problems.append(f"blocker_source_missing:{symbol}")

        harness_hits = []
        referenced_by = []
        for harness in harnesses:
            for path in harness_paths(harness):
                hits = source_hits(load_text(path), blocker["harness_match"])
                if hits:
                    referenced_by.append(harness)
                    harness_hits.append({"path": rel(path), "lines": hits})
                    break
        referenced = bool(referenced_by)
        if not referenced:
            problems.append(f"blocker_harness_unreferenced:{symbol}")

        blocker_checks.append(
            {
                "symbol": symbol,
                "source_path": blocker["source_path"],
                "source_present": source_present,
                "source_lines": source_lines,
                "referenced": referenced,
                "referenced_by": referenced_by,
                "harness_hits": harness_hits,
            }
        )

    return {
        "blockers_tracked": len(blocker_checks),
        "blockers_present": sum(1 for entry in blocker_checks if entry["source_present"]),
        "blockers_referenced": sum(1 for entry in blocker_checks if entry["referenced"]),
        "blockers": blocker_checks,
    }, problems


def check_surface(surface: dict[str, Any]) -> dict[str, Any]:
    missing = list(surface.get("missing", []))
    receipts = surface_receipts(surface)
    receipt_summaries = []
    problems = []
    for path in receipts:
        receipt = load_json(path)
        if receipt is None:
            problems.append(f"missing_receipt:{rel(path)}")
            receipt_summaries.append(
                {
                    "path": rel(path),
                    "exists": False,
                    "ok": False,
                    "reasons": ["missing_receipt"],
                    "schema": None,
                    "git_head": None,
                    "started_at_utc": None,
                    "generated_at_utc": None,
                }
            )
            continue
        ok, reasons = receipt_ok(receipt)
        if not ok:
            problems.extend(f"{reason}:{rel(path)}" for reason in reasons)
        receipt_summaries.append(
            {
                "path": rel(path),
                "exists": True,
                "ok": ok,
                "reasons": reasons,
                "schema": receipt.get("schema"),
                "git_head": receipt.get("git_head"),
                "started_at_utc": receipt.get("started_at_utc"),
                "generated_at_utc": receipt.get("generated_at_utc"),
            }
        )

    if surface.get("coverage_status") not in (None, "covered"):
        problems.append(f"coverage_status:{surface.get('coverage_status')}")
    if missing:
        problems.extend(f"atlas_missing:{item}" for item in missing)
    blocker_summary, blocker_problems = check_blockers(surface)
    problems.extend(blocker_problems)
    optional_receipt_summaries, optional_research_blockers = check_optional_receipts(surface)

    atlas_optional_status = surface.get("optional_parallel_status")
    has_stable_optional_receipt = any(
        receipt.get("stabilizes_optional_lane")
        for receipt in optional_receipt_summaries
        if receipt.get("exists") and not receipt.get("blocking")
    )
    optional_status = (
        "stable_optional_lane"
        if atlas_optional_status == "mixed_optional_lane" and has_stable_optional_receipt
        else atlas_optional_status
    )
    optional_research_block = optional_status == "mixed_optional_lane" or bool(optional_research_blockers)
    return {
        "surface_id": surface["surface_id"],
        "mandatory_ok": not problems,
        "problems": problems,
        "atlas_optional_status": atlas_optional_status,
        "optional_status": optional_status,
        "has_stable_optional_receipt": has_stable_optional_receipt,
        "optional_research_block": optional_research_block,
        "optional_research_blockers": optional_research_blockers,
        "receipts": receipt_summaries,
        "optional_receipts": optional_receipt_summaries,
        "blocker_summary": blocker_summary,
    }


def paths_from_edges(max_depth: int, edges: tuple[tuple[str, str, str], ...]) -> list[tuple[tuple[str, ...], str]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for src, dst, reason in edges:
        adjacency.setdefault(src, []).append((dst, reason))

    paths: list[tuple[tuple[str, ...], str]] = []

    def visit(path: tuple[str, ...], reasons: list[str]) -> None:
        if len(path) > 1:
            paths.append((path, " | ".join(reasons)))
        if len(path) >= max_depth:
            return
        for nxt, reason in adjacency.get(path[-1], []):
            if nxt in path:
                continue
            visit((*path, nxt), [*reasons, reason])

    for src, _, _ in edges:
        visit((src,), [])
    return paths


def paths_between(
    start: str, end: str, max_depth: int, edges: tuple[tuple[str, str, str], ...]
) -> list[tuple[tuple[str, ...], str]]:
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for src, dst, reason in edges:
        adjacency.setdefault(src, []).append((dst, reason))

    paths: list[tuple[tuple[str, ...], str]] = []

    def visit(path: tuple[str, ...], reasons: list[str]) -> None:
        if len(path) >= max_depth:
            return
        for nxt, reason in adjacency.get(path[-1], []):
            if nxt in path and nxt != end:
                continue
            next_path = (*path, nxt)
            next_reasons = [*reasons, reason]
            if nxt == end:
                paths.append((next_path, " | ".join(next_reasons)))
                continue
            visit(next_path, next_reasons)

    visit((start,), [])
    return paths


def graph_by_src(edges: tuple[tuple[str, str, str], ...]) -> dict[str, list[tuple[str, str]]]:
    graph: dict[str, list[tuple[str, str]]] = {}
    for src, dst, reason in edges:
        graph.setdefault(src, []).append((dst, reason))
    return graph


def graph_by_dst(edges: tuple[tuple[str, str, str], ...]) -> dict[str, list[tuple[str, str]]]:
    graph: dict[str, list[tuple[str, str]]] = {}
    for src, dst, reason in edges:
        graph.setdefault(dst, []).append((src, reason))
    return graph


def generate_hypotheses(
    atlas: dict[str, Any],
    max_depth: int,
    composition_edges: tuple[tuple[str, str, str], ...],
    reentry_edges: tuple[tuple[str, str, str], ...],
) -> list[Hypothesis]:
    surfaces = {surface["surface_id"]: surface for surface in atlas.get("surfaces", [])}
    hypotheses: list[Hypothesis] = []
    for surface_id, surface in sorted(surfaces.items()):
        for danger_state in surface.get("danger_states", []):
            hypotheses.append(
                Hypothesis(
                    hypothesis_id=f"single::{surface_id}::{danger_state}",
                    kind="single_surface_disaster",
                    surfaces=(surface_id,),
                    danger_states=(danger_state,),
                    what_if=f"What if `{danger_state}` is reachable on `{surface_id}`?",
                )
            )

    for surface_id, surface in sorted(surfaces.items()):
        dangers = tuple(surface.get("danger_states", []))
        hypotheses.append(
            Hypothesis(
                hypothesis_id=f"receipt-fail-open::{surface_id}",
                kind="receipt_fail_open_mutation",
                surfaces=(surface_id,),
                danger_states=dangers,
                what_if=(
                    f"What if stale, missing, optional, or failed evidence for `{surface_id}` "
                    "were accidentally treated as promotable instead of fail-closed?"
                ),
            )
        )
        for blocker in surface.get("blocker_functions", []):
            for danger_state in dangers:
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=(
                            f"blocker-bypass::{surface_id}::{blocker['symbol']}::"
                            f"{danger_state}"
                        ),
                        kind="blocker_bypass_disaster",
                        surfaces=(surface_id,),
                        danger_states=(danger_state,),
                        what_if=(
                            f"What if blocker/checker `{blocker['symbol']}` stops guarding "
                            f"`{danger_state}` on `{surface_id}`?"
                        ),
                    )
                )

    for (surface_a_id, surface_a), (surface_b_id, surface_b) in combinations(sorted(surfaces.items()), 2):
        for danger_a in surface_a.get("danger_states", []):
            for danger_b in surface_b.get("danger_states", []):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=(
                            f"independent-pair::{surface_a_id}+{surface_b_id}::"
                            f"{danger_a}+{danger_b}"
                        ),
                        kind="independent_pair_coreachability",
                        surfaces=(surface_a_id, surface_b_id),
                        danger_states=(danger_a, danger_b),
                        what_if=(
                            f"What if `{danger_a}` on `{surface_a_id}` and `{danger_b}` "
                            f"on `{surface_b_id}` are co-reachable without relying on an "
                            "explicit atlas composition edge?"
                        ),
                    )
                )

    for (
        (surface_a_id, surface_a),
        (surface_b_id, surface_b),
        (surface_c_id, surface_c),
    ) in combinations(sorted(surfaces.items()), 3):
        for danger_a in surface_a.get("danger_states", []):
            for danger_b in surface_b.get("danger_states", []):
                for danger_c in surface_c.get("danger_states", []):
                    hypotheses.append(
                        Hypothesis(
                            hypothesis_id=(
                                f"independent-triple::{surface_a_id}+{surface_b_id}+{surface_c_id}::"
                                f"{danger_a}+{danger_b}+{danger_c}"
                            ),
                            kind="independent_triple_coreachability",
                            surfaces=(surface_a_id, surface_b_id, surface_c_id),
                            danger_states=(danger_a, danger_b, danger_c),
                            what_if=(
                                f"What if `{danger_a}` on `{surface_a_id}`, `{danger_b}` "
                                f"on `{surface_b_id}`, and `{danger_c}` on `{surface_c_id}` "
                                "are co-reachable as a three-surface disaster state?"
                            ),
                        )
                    )

    for src, dst, reason in composition_edges:
        if src not in surfaces or dst not in surfaces:
            continue
        src_dangers = surfaces[src].get("danger_states", [])
        dst_dangers = surfaces[dst].get("danger_states", [])
        for src_danger in src_dangers:
            for dst_danger in dst_dangers:
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"edge::{src}->{dst}::{src_danger}->{dst_danger}",
                        kind="edge_composition_disaster",
                        surfaces=(src, dst),
                        danger_states=(src_danger, dst_danger),
                        what_if=(
                            f"What if `{src_danger}` on `{src}` composes into "
                            f"`{dst_danger}` on `{dst}`? Reason: {reason}."
                        ),
                )
            )
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"order-inversion::{dst}->{src}::{dst_danger}->{src_danger}",
                        kind="order_inversion_disaster",
                        surfaces=(dst, src),
                        danger_states=(dst_danger, src_danger),
                        what_if=(
                            f"What if downstream disaster `{dst_danger}` on `{dst}` "
                            f"appears before upstream guard disaster `{src_danger}` on "
                            f"`{src}`? Intended order reason: {reason}."
                        ),
                    )
                )

    for path, reason in paths_from_edges(max_depth, composition_edges):
        if any(surface_id not in surfaces for surface_id in path):
            continue
        hypotheses.append(
            Hypothesis(
                hypothesis_id="chain::" + "->".join(path),
                kind="chain_researchability",
                surfaces=path,
                danger_states=tuple(
                    danger
                    for surface_id in path
                    for danger in surfaces[surface_id].get("danger_states", [])
                ),
                what_if=(
                    "What if this whole composed research path is opened: "
                    + " -> ".join(f"`{surface_id}`" for surface_id in path)
                    + f"? Reasons: {reason}."
                ),
            )
        )
        if len(path) < 3:
            continue
        first, last = path[0], path[-1]
        for first_danger in surfaces[first].get("danger_states", []):
            for last_danger in surfaces[last].get("danger_states", []):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=(
                            f"chain-terminal::{ '->'.join(path) }::"
                            f"{first_danger}->{last_danger}"
                        ),
                        kind="chain_terminal_disaster",
                        surfaces=path,
                        danger_states=(first_danger, last_danger),
                        what_if=(
                            f"What if `{first_danger}` at the start of "
                            f"`{' -> '.join(path)}` reaches terminal disaster "
                            f"`{last_danger}`? Reasons: {reason}."
                        ),
                    )
                )

    by_src = graph_by_src(composition_edges)
    for src, outgoing in sorted(by_src.items()):
        if src not in surfaces or len(outgoing) < 2:
            continue
        for (dst_a, reason_a), (dst_b, reason_b) in combinations(sorted(outgoing), 2):
            if dst_a not in surfaces or dst_b not in surfaces:
                continue
            for src_danger in surfaces[src].get("danger_states", []):
                for dst_a_danger in surfaces[dst_a].get("danger_states", []):
                    for dst_b_danger in surfaces[dst_b].get("danger_states", []):
                        hypotheses.append(
                            Hypothesis(
                                hypothesis_id=(
                                    f"fanout::{src}->{dst_a}+{dst_b}::"
                                    f"{src_danger}->{dst_a_danger}+{dst_b_danger}"
                                ),
                                kind="fanout_composition_disaster",
                                surfaces=(src, dst_a, dst_b),
                                danger_states=(src_danger, dst_a_danger, dst_b_danger),
                                what_if=(
                                    f"What if `{src_danger}` on `{src}` fans out into "
                                    f"`{dst_a_danger}` on `{dst_a}` and `{dst_b_danger}` "
                                    f"on `{dst_b}`? Reasons: {reason_a} | {reason_b}."
                                ),
                            )
                        )

    by_dst = graph_by_dst(composition_edges)
    for dst, incoming in sorted(by_dst.items()):
        if dst not in surfaces or len(incoming) < 2:
            continue
        for (src_a, reason_a), (src_b, reason_b) in combinations(sorted(incoming), 2):
            if src_a not in surfaces or src_b not in surfaces:
                continue
            for src_a_danger in surfaces[src_a].get("danger_states", []):
                for src_b_danger in surfaces[src_b].get("danger_states", []):
                    for dst_danger in surfaces[dst].get("danger_states", []):
                        hypotheses.append(
                            Hypothesis(
                                hypothesis_id=(
                                    f"convergence::{src_a}+{src_b}->{dst}::"
                                    f"{src_a_danger}+{src_b_danger}->{dst_danger}"
                                ),
                                kind="convergence_composition_disaster",
                                surfaces=(src_a, src_b, dst),
                                danger_states=(src_a_danger, src_b_danger, dst_danger),
                                what_if=(
                                    f"What if independent upstream disasters "
                                    f"`{src_a_danger}` on `{src_a}` and `{src_b_danger}` "
                                    f"on `{src_b}` converge into `{dst_danger}` on `{dst}`? "
                                    f"Reasons: {reason_a} | {reason_b}."
                                ),
                            )
                        )

    for src, dst, reason in reentry_edges:
        if src not in surfaces or dst not in surfaces:
            continue
        for src_danger in surfaces[src].get("danger_states", []):
            for dst_danger in surfaces[dst].get("danger_states", []):
                hypotheses.append(
                    Hypothesis(
                        hypothesis_id=f"reentry::{src}->{dst}::{src_danger}->{dst_danger}",
                        kind="reentry_retry_disaster",
                        surfaces=(src, dst),
                        danger_states=(src_danger, dst_danger),
                        what_if=(
                            f"What if `{src_danger}` on `{src}` creates a retry/re-entry "
                            f"path to `{dst_danger}` on `{dst}`? Reason: {reason}."
                        ),
                    )
                )
        for forward_path, forward_reason in paths_between(dst, src, max_depth, composition_edges):
            cycle_path = (*forward_path, dst)
            for src_danger in surfaces[src].get("danger_states", []):
                for dst_danger in surfaces[dst].get("danger_states", []):
                    hypotheses.append(
                        Hypothesis(
                            hypothesis_id=(
                                f"cycle-amplification::{ '->'.join(cycle_path) }::"
                                f"{dst_danger}->{src_danger}"
                            ),
                            kind="cycle_amplification_disaster",
                            surfaces=cycle_path,
                            danger_states=(dst_danger, src_danger),
                            what_if=(
                                f"What if `{dst_danger}` enters cycle "
                                f"`{' -> '.join(cycle_path)}` and amplifies into "
                                f"`{src_danger}` before the loop is rejected? "
                                f"Forward reasons: {forward_reason}. Re-entry reason: {reason}."
                            ),
                        )
                    )
    return hypotheses


def evaluate(hypothesis: Hypothesis, checks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    classification = classify_surface_ids(hypothesis.surfaces, checks)
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "kind": hypothesis.kind,
        "surfaces": list(hypothesis.surfaces),
        "danger_states": list(hypothesis.danger_states),
        "what_if": hypothesis.what_if,
        **classification,
    }


def classify_surface_ids(
    surface_ids: tuple[str, ...] | list[str], checks: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    surface_checks = [checks[surface_id] for surface_id in surface_ids]
    blockers = [check for check in surface_checks if not check["mandatory_ok"]]
    optional_blocks = [check for check in surface_checks if check["optional_research_block"]]

    if blockers:
        verdict = "UNKNOWN_BLOCKED"
        researchability = "blocked_missing_or_failed_receipt"
        witness_paths = [
            receipt["path"]
            for check in blockers
            for receipt in check["receipts"]
            if not receipt.get("ok", False)
        ]
    elif optional_blocks:
        verdict = "NO_REACHABLE_WITNESS_BOUNDED"
        researchability = "blocked_for_promotion_due_optional_instability"
        witness_paths = [
            receipt["path"]
            for check in optional_blocks
            for receipt in check["receipts"]
        ]
    else:
        verdict = "NO_REACHABLE_WITNESS_BOUNDED"
        researchability = "researchable_under_current_bounded_receipts"
        witness_paths = [
            receipt["path"]
            for check in surface_checks
            for receipt in check["receipts"]
        ]

    reachable_witnesses = []
    for check in surface_checks:
        for problem in check["problems"]:
            if problem.startswith(("receipt_ok_false", "return_code_", "artifact_delta_", "runtime_tests_failed")):
                reachable_witnesses.append(problem)

    if reachable_witnesses:
        verdict = "REACHABLE_DISASTER_WITNESS"
        researchability = "blocked_reachable_disaster_witness"

    return {
        "verdict": verdict,
        "researchability": researchability,
        "surface_check_ids": [check["surface_id"] for check in surface_checks],
        "witness_paths": sorted(set(witness_paths)),
        "reachable_witnesses": reachable_witnesses,
    }


def mutate_surface_check(check: dict[str, Any], mutation_id: str) -> dict[str, Any]:
    mutated = deepcopy(check)
    if mutation_id == "optional_lane_mixed":
        mutated["optional_status"] = "mixed_optional_lane"
        mutated["optional_research_block"] = True
        return mutated

    mutated["mandatory_ok"] = False
    mutated.setdefault("problems", []).append(f"synthetic_{mutation_id}")
    if mutated.get("receipts"):
        mutated["receipts"][0]["ok"] = False
        mutated["receipts"][0].setdefault("reasons", []).append(f"synthetic_{mutation_id}")
    else:
        mutated.setdefault("receipts", []).append(
            {
                "path": f"synthetic://{mutated['surface_id']}/{mutation_id}",
                "exists": False,
                "ok": False,
                "reasons": [f"synthetic_{mutation_id}"],
            }
        )
    return mutated


def mutate_blocker_check(check: dict[str, Any], mutation_id: str) -> dict[str, Any]:
    mutated = deepcopy(check)
    blocker_summary = mutated.get("blocker_summary", {})
    blockers = blocker_summary.get("blockers", [])
    if not blockers:
        mutated["mandatory_ok"] = False
        mutated.setdefault("problems", []).append(f"synthetic_{mutation_id}:no_blockers")
        return mutated

    blocker = blockers[0]
    blocker["source_present"] = mutation_id != "blocker_source_missing"
    blocker["referenced"] = mutation_id != "blocker_harness_unreferenced"
    if mutation_id == "blocker_source_missing":
        blocker["source_lines"] = []
        blocker_summary["blockers_present"] = max(0, blocker_summary.get("blockers_present", 0) - 1)
    if mutation_id == "blocker_harness_unreferenced":
        blocker["referenced_by"] = []
        blocker["harness_hits"] = []
        blocker_summary["blockers_referenced"] = max(0, blocker_summary.get("blockers_referenced", 0) - 1)
    mutated["mandatory_ok"] = False
    mutated.setdefault("problems", []).append(f"synthetic_{mutation_id}:{blocker['symbol']}")
    return mutated


def evaluate_receipt_state_mutations(
    surfaces: dict[str, dict[str, Any]], checks: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for surface_id, surface in sorted(surfaces.items()):
        for mutation_id, mutation_class, description in RECEIPT_STATE_MUTATIONS:
            mutated_checks = dict(checks)
            mutated_checks[surface_id] = mutate_surface_check(checks[surface_id], mutation_id)
            hypothesis = Hypothesis(
                hypothesis_id=f"synthetic-receipt::{surface_id}::{mutation_id}",
                kind="synthetic_receipt_state_mutation",
                surfaces=(surface_id,),
                danger_states=tuple(surface.get("danger_states", [])),
                what_if=f"What if `{surface_id}` saw this synthetic evidence fault: {description}?",
            )
            result = evaluate(hypothesis, mutated_checks)
            if mutation_class == "optional":
                fail_closed_observed = result["researchability"] == "blocked_for_promotion_due_optional_instability"
            else:
                fail_closed_observed = result["verdict"] == "UNKNOWN_BLOCKED"
            result["synthetic_mutation"] = {
                "mutation_id": mutation_id,
                "mutation_class": mutation_class,
                "description": description,
                "fail_closed_observed": fail_closed_observed,
            }
            results.append(result)
    return results


def evaluate_blocker_state_mutations(
    surfaces: dict[str, dict[str, Any]], checks: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for surface_id, surface in sorted(surfaces.items()):
        if not surface.get("blocker_functions"):
            continue
        for mutation_id, description in BLOCKER_STATE_MUTATIONS:
            mutated_checks = dict(checks)
            mutated_checks[surface_id] = mutate_blocker_check(checks[surface_id], mutation_id)
            hypothesis = Hypothesis(
                hypothesis_id=f"synthetic-blocker::{surface_id}::{mutation_id}",
                kind="synthetic_blocker_state_mutation",
                surfaces=(surface_id,),
                danger_states=tuple(surface.get("danger_states", [])),
                what_if=f"What if `{surface_id}` saw this synthetic blocker fault: {description}?",
            )
            result = evaluate(hypothesis, mutated_checks)
            result["synthetic_mutation"] = {
                "mutation_id": mutation_id,
                "mutation_class": "blocker",
                "description": description,
                "fail_closed_observed": result["verdict"] == "UNKNOWN_BLOCKED",
            }
            results.append(result)
    return results


def evaluate_provenance_state_mutations(
    checks: dict[str, dict[str, Any]],
    summary: dict[str, Any],
    synthetic_mutation_summary: dict[str, Any],
    synthetic_blocker_summary: dict[str, Any],
    optional_evidence_summary: dict[str, Any],
    frontier: dict[str, Any],
    current_git_head: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    mutation_plan = (
        ("mandatory_git_head_mismatch", "receipts"),
        ("optional_git_head_mismatch", "optional_receipts"),
    )
    for surface_id, check in sorted(checks.items()):
        for mutation_id, receipt_key in mutation_plan:
            if not check.get(receipt_key):
                continue
            mutated_checks = deepcopy(checks)
            mutated_receipt = mutated_checks[surface_id][receipt_key][0]
            old_git_head = mutated_receipt.get("git_head")
            mutated_receipt["git_head"] = f"synthetic-old-{current_git_head[:12]}"
            provenance = summarize_receipt_provenance(mutated_checks, current_git_head)
            mutated_gate = summarize_gate_status(
                summary,
                synthetic_mutation_summary,
                synthetic_blocker_summary,
                optional_evidence_summary,
                provenance,
                frontier,
            )
            fail_closed_observed = (
                "receipt_git_head_mismatch" in mutated_gate["blockers"]
                and not mutated_gate["open_for_bounded_research"]
            )
            results.append(
                {
                    "hypothesis_id": f"synthetic-provenance::{surface_id}::{mutation_id}",
                    "kind": "synthetic_provenance_state_mutation",
                    "surface": surface_id,
                    "receipt_channel": "mandatory" if receipt_key == "receipts" else "optional",
                    "receipt_path": mutated_receipt.get("path"),
                    "old_git_head": old_git_head,
                    "mutated_git_head": mutated_receipt["git_head"],
                    "gate": mutated_gate["gate"],
                    "gate_blockers": mutated_gate["blockers"],
                    "fail_closed_observed": fail_closed_observed,
                }
            )
    return results


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    researchability_counts: dict[str, int] = {}
    kind_counts: dict[str, int] = {}
    for result in results:
        counts[result["verdict"]] = counts.get(result["verdict"], 0) + 1
        key = result["researchability"]
        researchability_counts[key] = researchability_counts.get(key, 0) + 1
        kind = result["kind"]
        kind_counts[kind] = kind_counts.get(kind, 0) + 1
    return {
        "hypotheses": len(results),
        "verdict_counts": counts,
        "researchability_counts": researchability_counts,
        "kind_counts": kind_counts,
        "reachable_disaster_witnesses": counts.get("REACHABLE_DISASTER_WITNESS", 0),
        "unknown_blocked": counts.get("UNKNOWN_BLOCKED", 0),
        "bounded_no_witness": counts.get("NO_REACHABLE_WITNESS_BOUNDED", 0),
    }


def summarize_synthetic_mutations(results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize(results)
    failures = [
        result["hypothesis_id"]
        for result in results
        if not result.get("synthetic_mutation", {}).get("fail_closed_observed", False)
    ]
    summary["fail_closed_observed"] = len(results) - len(failures)
    summary["fail_closed_failures"] = len(failures)
    summary["failure_ids"] = failures
    return summary


def summarize_synthetic_provenance_mutations(results: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [
        result["hypothesis_id"]
        for result in results
        if not result.get("fail_closed_observed", False)
    ]
    by_channel: dict[str, int] = {}
    for result in results:
        channel = result["receipt_channel"]
        by_channel[channel] = by_channel.get(channel, 0) + 1
    return {
        "hypotheses": len(results),
        "by_channel": by_channel,
        "fail_closed_observed": len(results) - len(failures),
        "fail_closed_failures": len(failures),
        "failure_ids": failures,
    }


def summarize_optional_evidence(checks: dict[str, dict[str, Any]]) -> dict[str, Any]:
    blocked = []
    for surface_id, check in sorted(checks.items()):
        if not check["optional_research_block"]:
            continue
        blocked.append(
            {
                "surface_id": surface_id,
                "optional_status": check["optional_status"],
                "blockers": check.get("optional_research_blockers", []),
            }
        )
    return {
        "surfaces_with_optional_research_block": len(blocked),
        "blocked_surfaces": blocked,
    }


def summarize_research_blocks(
    results: list[dict[str, Any]], checks: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    optional_counts: dict[str, int] = {}
    missing_or_failed_counts: dict[str, int] = {}
    for result in results:
        if result["researchability"] == "researchable_under_current_bounded_receipts":
            continue
        for surface_id in result["surfaces"]:
            check = checks[surface_id]
            if check["optional_research_block"]:
                optional_counts[surface_id] = optional_counts.get(surface_id, 0) + 1
            if not check["mandatory_ok"]:
                missing_or_failed_counts[surface_id] = missing_or_failed_counts.get(surface_id, 0) + 1

    optional_cut = sorted(optional_counts, key=lambda key: (-optional_counts[key], key))
    return {
        "optional_block_counts": optional_counts,
        "mandatory_block_counts": missing_or_failed_counts,
        "dominant_optional_block_surface": optional_cut[0] if optional_cut else None,
        "dominant_optional_block_count": optional_counts[optional_cut[0]] if optional_cut else 0,
        "single_surface_optional_cut_clears_all_blocks": (
            len(optional_counts) == 1 and not missing_or_failed_counts
        ),
    }


def summarize_blocked_families(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, dict[str, Any]] = {}
    for result in results:
        kind = result["kind"]
        entry = by_kind.setdefault(
            kind,
            {
                "total": 0,
                "researchable": 0,
                "optional_blocked": 0,
                "mandatory_or_unknown_blocked": 0,
                "reachable_witness": 0,
                "representative_blocked_hypothesis": None,
            },
        )
        entry["total"] += 1
        if result["verdict"] == "REACHABLE_DISASTER_WITNESS":
            entry["reachable_witness"] += 1
        elif result["researchability"] == "blocked_for_promotion_due_optional_instability":
            entry["optional_blocked"] += 1
            if entry["representative_blocked_hypothesis"] is None:
                entry["representative_blocked_hypothesis"] = result["hypothesis_id"]
        elif result["researchability"] == "researchable_under_current_bounded_receipts":
            entry["researchable"] += 1
        else:
            entry["mandatory_or_unknown_blocked"] += 1
            if entry["representative_blocked_hypothesis"] is None:
                entry["representative_blocked_hypothesis"] = result["hypothesis_id"]

    return {
        "by_kind": dict(sorted(by_kind.items())),
        "blocked_kind_count": sum(
            1
            for entry in by_kind.values()
            if entry["optional_blocked"]
            or entry["mandatory_or_unknown_blocked"]
            or entry["reachable_witness"]
        ),
    }


def summarize_receipt_provenance(
    checks: dict[str, dict[str, Any]], current_git_head: str
) -> dict[str, Any]:
    def empty() -> dict[str, Any]:
        return {
            "total": 0,
            "exists": 0,
            "with_git_head": 0,
            "matching_git_head": 0,
            "mismatched_git_head": 0,
            "missing_git_head": 0,
        }

    summary = {
        "current_git_head": current_git_head,
        "mandatory": empty(),
        "optional": empty(),
        "mismatches": [],
        "missing_git_head_receipts": [],
    }

    def add(channel: str, surface_id: str, receipt: dict[str, Any]) -> None:
        bucket = summary[channel]
        bucket["total"] += 1
        if receipt.get("exists"):
            bucket["exists"] += 1
        git = receipt.get("git_head")
        if git:
            bucket["with_git_head"] += 1
            if git == current_git_head:
                bucket["matching_git_head"] += 1
            else:
                bucket["mismatched_git_head"] += 1
                summary["mismatches"].append(
                    {
                        "surface_id": surface_id,
                        "channel": channel,
                        "path": receipt.get("path"),
                        "git_head": git,
                    }
                )
        else:
            bucket["missing_git_head"] += 1
            summary["missing_git_head_receipts"].append(
                {
                    "surface_id": surface_id,
                    "channel": channel,
                    "path": receipt.get("path"),
                    "schema": receipt.get("schema"),
                }
            )

    for surface_id, check in sorted(checks.items()):
        for receipt in check.get("receipts", []):
            add("mandatory", surface_id, receipt)
        for receipt in check.get("optional_receipts", []):
            add("optional", surface_id, receipt)

    summary["has_git_head_mismatch"] = bool(summary["mismatches"])
    return summary


def summarize_compressed_independent_frontier(
    surfaces: dict[str, dict[str, Any]], checks: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    by_order = []
    max_order = len(surfaces)
    surface_items = sorted(surfaces.items())
    for order in range(1, max_order + 1):
        total = 0
        researchable = 0
        optional_blocked = 0
        mandatory_blocked = 0
        for subset in combinations(surface_items, order):
            surface_ids = [surface_id for surface_id, _ in subset]
            combo_count = prod(len(surface.get("danger_states", [])) for _, surface in subset)
            if combo_count == 0:
                continue
            total += combo_count
            if any(not checks[surface_id]["mandatory_ok"] for surface_id in surface_ids):
                mandatory_blocked += combo_count
            elif any(checks[surface_id]["optional_research_block"] for surface_id in surface_ids):
                optional_blocked += combo_count
            else:
                researchable += combo_count
        by_order.append(
            {
                "order": order,
                "total": total,
                "researchable": researchable,
                "optional_blocked": optional_blocked,
                "mandatory_blocked": mandatory_blocked,
            }
        )

    return {
        "schema": "mprd/compressed-independent-coreachability/v1",
        "max_order": max_order,
        "by_order": by_order,
        "totals": {
            "total": sum(row["total"] for row in by_order),
            "researchable": sum(row["researchable"] for row in by_order),
            "optional_blocked": sum(row["optional_blocked"] for row in by_order),
            "mandatory_blocked": sum(row["mandatory_blocked"] for row in by_order),
        },
    }


def clear_optional_research_blocks(
    checks: dict[str, dict[str, Any]], surface_ids: set[str]
) -> dict[str, dict[str, Any]]:
    cleared = deepcopy(checks)
    for surface_id in surface_ids:
        if surface_id not in cleared:
            continue
        old_status = cleared[surface_id].get("optional_status")
        cleared[surface_id]["optional_status"] = f"counterfactual_cleared:{old_status}"
        cleared[surface_id]["optional_research_block"] = False
        cleared[surface_id]["optional_research_blockers"] = []
        for receipt in cleared[surface_id].get("optional_receipts", []):
            receipt["counterfactual_cleared"] = True
    return cleared


def summarize_counterfactual_unblock(
    surfaces: dict[str, dict[str, Any]],
    results: list[dict[str, Any]],
    checks: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    current_blocks = summarize_research_blocks(results, checks)
    cut = set(current_blocks["optional_block_counts"])
    if not cut:
        return {
            "cleared_surfaces": [],
            "applicable": False,
            "reason": "no_optional_research_blocks",
        }

    cleared_checks = clear_optional_research_blocks(checks, cut)
    counterfactual_results = []
    for result in results:
        classification = classify_surface_ids(result["surfaces"], cleared_checks)
        counterfactual_results.append(
            {
                "hypothesis_id": result["hypothesis_id"],
                "kind": result["kind"],
                "surfaces": result["surfaces"],
                **classification,
            }
        )
    summary_after_clear = summarize(counterfactual_results)
    research_blocks_after_clear = summarize_research_blocks(counterfactual_results, cleared_checks)
    compressed_after_clear = summarize_compressed_independent_frontier(surfaces, cleared_checks)
    return {
        "cleared_surfaces": sorted(cut),
        "applicable": True,
        "summary_after_clear": summary_after_clear,
        "research_block_summary_after_clear": research_blocks_after_clear,
        "compressed_independent_frontier_after_clear": compressed_after_clear,
        "opens_all_materialized_hypotheses": (
            summary_after_clear["reachable_disaster_witnesses"] == 0
            and summary_after_clear["unknown_blocked"] == 0
            and summary_after_clear["researchability_counts"].get(
                "blocked_for_promotion_due_optional_instability", 0
            )
            == 0
        ),
        "opens_all_compressed_independent_frontier": (
            compressed_after_clear["totals"]["optional_blocked"] == 0
            and compressed_after_clear["totals"]["mandatory_blocked"] == 0
        ),
    }


def summarize_gate_status(
    summary: dict[str, Any],
    synthetic_summary: dict[str, Any],
    synthetic_blocker_summary: dict[str, Any],
    optional_evidence: dict[str, Any],
    receipt_provenance: dict[str, Any],
    frontier: dict[str, Any],
    synthetic_provenance_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    synthetic_provenance_summary = synthetic_provenance_summary or {
        "fail_closed_failures": 0
    }
    blockers = []
    if summary["reachable_disaster_witnesses"]:
        blockers.append("reachable_disaster_witness")
    if summary["unknown_blocked"]:
        blockers.append("unknown_or_missing_mandatory_receipt")
    if synthetic_summary["fail_closed_failures"]:
        blockers.append("synthetic_receipt_fail_closed_failure")
    if synthetic_blocker_summary["fail_closed_failures"]:
        blockers.append("synthetic_blocker_fail_closed_failure")
    if synthetic_provenance_summary["fail_closed_failures"]:
        blockers.append("synthetic_provenance_fail_closed_failure")
    if not frontier["simple_path_frontier_exhausted"]:
        blockers.append("composition_frontier_not_exhausted")
    if optional_evidence["surfaces_with_optional_research_block"]:
        blockers.append("optional_research_block")
    if receipt_provenance["has_git_head_mismatch"]:
        blockers.append("receipt_git_head_mismatch")

    if summary["reachable_disaster_witnesses"]:
        gate = "BLOCKED_REACHABLE_DISASTER_WITNESS"
    elif optional_evidence["surfaces_with_optional_research_block"]:
        gate = "BLOCKED_PENDING_OPTIONAL_STABILITY"
    elif blockers:
        gate = "BLOCKED_FAIL_CLOSED"
    else:
        gate = "OPEN_FOR_BOUNDED_RESEARCH"

    return {
        "gate": gate,
        "blockers": blockers,
        "no_reachable_disaster_witnesses": summary["reachable_disaster_witnesses"] == 0,
        "bounded_frontier_exhausted": frontier["simple_path_frontier_exhausted"],
        "synthetic_fail_closed_ok": (
            synthetic_summary["fail_closed_failures"] == 0
            and synthetic_blocker_summary["fail_closed_failures"] == 0
            and synthetic_provenance_summary["fail_closed_failures"] == 0
        ),
        "receipt_git_head_mismatch_free": not receipt_provenance["has_git_head_mismatch"],
        "open_for_bounded_research": gate == "OPEN_FOR_BOUNDED_RESEARCH",
    }


def value_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def result_digest(name: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "count": len(results),
        "hash": value_hash(results),
    }


def summarize_result_storage(
    full_results: bool,
    results: list[dict[str, Any]],
    synthetic_mutation_results: list[dict[str, Any]],
    synthetic_blocker_results: list[dict[str, Any]],
    synthetic_provenance_results: list[dict[str, Any]],
) -> dict[str, Any]:
    mode = "full" if full_results else "compact"
    return {
        "mode": mode,
        "full_results_included": full_results,
        "description": (
            "Full materialized result arrays are included in this JSON receipt."
            if full_results
            else "Materialized result arrays are omitted; use result_digests and samples, or rerun with --full-results."
        ),
        "digests": {
            "results": result_digest("results", results),
            "synthetic_mutation_results": result_digest(
                "synthetic_mutation_results", synthetic_mutation_results
            ),
            "synthetic_blocker_results": result_digest(
                "synthetic_blocker_results", synthetic_blocker_results
            ),
            "synthetic_provenance_results": result_digest(
                "synthetic_provenance_results", synthetic_provenance_results
            ),
        },
    }


def sample_results(
    results: list[dict[str, Any]],
    synthetic_mutation_results: list[dict[str, Any]],
    synthetic_blocker_results: list[dict[str, Any]],
    synthetic_provenance_results: list[dict[str, Any]],
    limit: int = 40,
) -> dict[str, Any]:
    blocked = [
        result
        for result in results
        if result["researchability"] != "researchable_under_current_bounded_receipts"
    ]
    reachable = [result for result in results if result["verdict"] == "REACHABLE_DISASTER_WITNESS"]
    unknown = [result for result in results if result["verdict"] == "UNKNOWN_BLOCKED"]
    synthetic_failures = [
        result
        for result in [*synthetic_mutation_results, *synthetic_blocker_results]
        if not result.get("synthetic_mutation", {}).get("fail_closed_observed", False)
    ]
    synthetic_provenance_failures = [
        result
        for result in synthetic_provenance_results
        if not result.get("fail_closed_observed", False)
    ]
    return {
        "limit": limit,
        "blocked_results": blocked[:limit],
        "reachable_results": reachable[:limit],
        "unknown_results": unknown[:limit],
        "synthetic_fail_closed_failures": synthetic_failures[:limit],
        "synthetic_provenance_fail_closed_failures": synthetic_provenance_failures[:limit],
        "truncated": {
            "blocked_results": max(0, len(blocked) - limit),
            "reachable_results": max(0, len(reachable) - limit),
            "unknown_results": max(0, len(unknown) - limit),
            "synthetic_fail_closed_failures": max(0, len(synthetic_failures) - limit),
            "synthetic_provenance_fail_closed_failures": max(
                0, len(synthetic_provenance_failures) - limit
            ),
        },
    }


def stable_report_hash(report: dict[str, Any]) -> str:
    stable_keys = [
        "schema",
        "program_id",
        "current_git_head",
        "atlas",
        "max_depth",
        "surface_count",
        "frontier",
        "edge_sources",
        "composition_edges",
        "reentry_edges",
        "summary",
        "synthetic_mutation_summary",
        "synthetic_blocker_summary",
        "synthetic_provenance_summary",
        "optional_evidence_summary",
        "research_block_summary",
        "blocked_family_summary",
        "receipt_provenance_summary",
        "gate_summary",
        "counterfactual_unblock_summary",
        "compressed_independent_frontier",
        "surface_checks",
        "result_samples",
    ]
    stable = {key: report[key] for key in stable_keys}
    stable["result_digests"] = report["result_storage"]["digests"]
    return value_hash(stable)


def assert_equal(name: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")


def self_test() -> int:
    fake_checks = {
        "safe": {
            "surface_id": "safe",
            "mandatory_ok": True,
            "problems": [],
            "optional_status": None,
            "optional_research_block": False,
            "optional_research_blockers": [],
            "receipts": [{"path": "safe.json", "ok": True}],
            "optional_receipts": [],
            "blocker_summary": {"blockers_tracked": 0, "blockers_present": 0, "blockers_referenced": 0, "blockers": []},
        },
        "optional": {
            "surface_id": "optional",
            "mandatory_ok": True,
            "problems": [],
            "optional_status": "mixed_optional_lane",
            "optional_research_block": True,
            "optional_research_blockers": ["decision:mixed_optional_lane:optional.json"],
            "receipts": [{"path": "optional.json", "ok": True}],
            "optional_receipts": [],
            "blocker_summary": {"blockers_tracked": 0, "blockers_present": 0, "blockers_referenced": 0, "blockers": []},
        },
        "bad": {
            "surface_id": "bad",
            "mandatory_ok": False,
            "problems": ["receipt_ok_false:bad.json"],
            "optional_status": None,
            "optional_research_block": False,
            "optional_research_blockers": [],
            "receipts": [{"path": "bad.json", "ok": False}],
            "optional_receipts": [],
            "blocker_summary": {"blockers_tracked": 0, "blockers_present": 0, "blockers_referenced": 0, "blockers": []},
        },
    }

    assert_equal(
        "safe researchability",
        classify_surface_ids(("safe",), fake_checks)["researchability"],
        "researchable_under_current_bounded_receipts",
    )
    assert_equal(
        "optional researchability",
        classify_surface_ids(("optional",), fake_checks)["researchability"],
        "blocked_for_promotion_due_optional_instability",
    )
    assert_equal(
        "reachable witness classification",
        classify_surface_ids(("bad",), fake_checks)["verdict"],
        "REACHABLE_DISASTER_WITNESS",
    )

    cleared = clear_optional_research_blocks(fake_checks, {"optional"})
    assert_equal(
        "counterfactual optional clear",
        classify_surface_ids(("optional",), cleared)["researchability"],
        "researchable_under_current_bounded_receipts",
    )

    fake_surfaces = {
        "safe": {"surface_id": "safe", "danger_states": ["s1", "s2"]},
        "optional": {"surface_id": "optional", "danger_states": ["o1", "o2", "o3"]},
    }
    compressed = summarize_compressed_independent_frontier(fake_surfaces, fake_checks)
    assert_equal("compressed total", compressed["totals"]["total"], 11)
    assert_equal("compressed researchable", compressed["totals"]["researchable"], 2)
    assert_equal("compressed optional blocked", compressed["totals"]["optional_blocked"], 9)

    family_summary = summarize_blocked_families(
        [
            {
                "hypothesis_id": "h1",
                "kind": "family",
                "verdict": "NO_REACHABLE_WITNESS_BOUNDED",
                "researchability": "researchable_under_current_bounded_receipts",
            },
            {
                "hypothesis_id": "h2",
                "kind": "family",
                "verdict": "NO_REACHABLE_WITNESS_BOUNDED",
                "researchability": "blocked_for_promotion_due_optional_instability",
            },
            {
                "hypothesis_id": "h3",
                "kind": "other",
                "verdict": "REACHABLE_DISASTER_WITNESS",
                "researchability": "blocked_reachable_disaster_witness",
            },
        ]
    )
    assert_equal("family blocked count", family_summary["blocked_kind_count"], 2)
    assert_equal("family optional blocked", family_summary["by_kind"]["family"]["optional_blocked"], 1)
    assert_equal("family reachable witness", family_summary["by_kind"]["other"]["reachable_witness"], 1)

    provenance_checks = deepcopy(fake_checks)
    provenance_checks["safe"]["receipts"][0]["git_head"] = "current"
    provenance_checks["optional"]["receipts"][0]["git_head"] = "old"
    provenance = summarize_receipt_provenance(provenance_checks, "current")
    assert_equal("provenance matching git", provenance["mandatory"]["matching_git_head"], 1)
    assert_equal("provenance mismatched git", provenance["mandatory"]["mismatched_git_head"], 1)

    optional_evidence = summarize_optional_evidence(fake_checks)
    summary = {
        "reachable_disaster_witnesses": 0,
        "unknown_blocked": 0,
    }
    synthetic_ok = {"fail_closed_failures": 0}
    gate = summarize_gate_status(
        summary,
        synthetic_ok,
        synthetic_ok,
        optional_evidence,
        {"has_git_head_mismatch": False},
        {"simple_path_frontier_exhausted": True},
    )
    assert_equal("gate optional block", gate["gate"], "BLOCKED_PENDING_OPTIONAL_STABILITY")

    reachable_gate = summarize_gate_status(
        {"reachable_disaster_witnesses": 1, "unknown_blocked": 0},
        synthetic_ok,
        synthetic_ok,
        {"surfaces_with_optional_research_block": 0},
        {"has_git_head_mismatch": False},
        {"simple_path_frontier_exhausted": True},
    )
    assert_equal("gate reachable witness", reachable_gate["gate"], "BLOCKED_REACHABLE_DISASTER_WITNESS")

    provenance_gate = summarize_gate_status(
        {"reachable_disaster_witnesses": 0, "unknown_blocked": 0},
        synthetic_ok,
        synthetic_ok,
        {"surfaces_with_optional_research_block": 0},
        {"has_git_head_mismatch": True},
        {"simple_path_frontier_exhausted": True},
    )
    assert_equal("gate provenance mismatch", provenance_gate["gate"], "BLOCKED_FAIL_CLOSED")

    synthetic_provenance = evaluate_provenance_state_mutations(
        provenance_checks,
        {"reachable_disaster_witnesses": 0, "unknown_blocked": 0},
        synthetic_ok,
        synthetic_ok,
        {"surfaces_with_optional_research_block": 0},
        {"simple_path_frontier_exhausted": True},
        "current",
    )
    synthetic_provenance_summary = summarize_synthetic_provenance_mutations(synthetic_provenance)
    assert_equal("synthetic provenance count", synthetic_provenance_summary["hypotheses"], 3)
    assert_equal(
        "synthetic provenance fail closed",
        synthetic_provenance_summary["fail_closed_failures"],
        0,
    )

    try:
        validate_edge_refs((("safe", "missing", "bad edge"),), {"safe"}, "composition_edges")
    except ValueError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("missing edge reference did not fail closed")

    print(
        json.dumps(
            {
                "schema": "mprd/neuro-symbolic-disaster-loop-self-test/v1",
                "ok": True,
                "checks": [
                    "safe_researchable",
                    "optional_blocked",
                    "reachable_witness",
                    "counterfactual_clear",
                    "compressed_counts",
                    "blocked_family_summary",
                    "receipt_provenance",
                    "synthetic_provenance_mutation",
                    "gate_status",
                    "missing_edge_fail_closed",
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    synthetic_summary = report["synthetic_mutation_summary"]
    synthetic_blocker_summary = report["synthetic_blocker_summary"]
    synthetic_provenance_summary = report["synthetic_provenance_summary"]
    optional_evidence = report["optional_evidence_summary"]
    research_blocks = report["research_block_summary"]
    blocked_family_summary = report["blocked_family_summary"]
    provenance = report["receipt_provenance_summary"]
    gate_summary = report["gate_summary"]
    counterfactual = report["counterfactual_unblock_summary"]
    compressed = report["compressed_independent_frontier"]
    result_storage = report["result_storage"]
    result_samples = report["result_samples"]
    frontier = report["frontier"]
    lines = [
        "# Neuro-Symbolic Disaster Loop",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        f"Max composition depth: `{report['max_depth']}`",
        f"Frontier exhausted: `{frontier['simple_path_frontier_exhausted']}`",
        f"Composition edge source: `{report['edge_sources']['composition_edges']}`",
        f"Re-entry edge source: `{report['edge_sources']['reentry_edges']}`",
        f"Stable receipt hash: `{report['stable_receipt_hash']}`",
        f"Current git head: `{report['current_git_head']}`",
        "",
        "## Summary",
        "",
        f"- Research gate: `{gate_summary['gate']}`",
        f"- Hypotheses checked: `{summary['hypotheses']}`",
        f"- Reachable disaster witnesses: `{summary['reachable_disaster_witnesses']}`",
        f"- Unknown / blocked: `{summary['unknown_blocked']}`",
        f"- Bounded no-witness: `{summary['bounded_no_witness']}`",
        f"- Researchable under current bounded receipts: `{summary['researchability_counts'].get('researchable_under_current_bounded_receipts', 0)}`",
        f"- Blocked for promotion due optional instability: `{summary['researchability_counts'].get('blocked_for_promotion_due_optional_instability', 0)}`",
        f"- Synthetic receipt mutations checked: `{synthetic_summary['hypotheses']}`",
        f"- Synthetic fail-closed failures: `{synthetic_summary['fail_closed_failures']}`",
        f"- Synthetic blocker mutations checked: `{synthetic_blocker_summary['hypotheses']}`",
        f"- Synthetic blocker fail-closed failures: `{synthetic_blocker_summary['fail_closed_failures']}`",
        f"- Synthetic provenance mutations checked: `{synthetic_provenance_summary['hypotheses']}`",
        f"- Synthetic provenance fail-closed failures: `{synthetic_provenance_summary['fail_closed_failures']}`",
        f"- Optional-evidence blocked surfaces: `{optional_evidence['surfaces_with_optional_research_block']}`",
        f"- Dominant optional block: `{research_blocks['dominant_optional_block_surface']}` / `{research_blocks['dominant_optional_block_count']}`",
        f"- Blocked hypothesis families: `{blocked_family_summary['blocked_kind_count']}`",
        f"- Receipt git-head mismatches: `{len(provenance['mismatches'])}`",
        f"- Compressed independent frontier: `{compressed['totals']['total']}` what-ifs through order `{compressed['max_order']}`",
        f"- Result storage mode: `{result_storage['mode']}`",
        "",
        "## Verdict Counts",
        "",
    ]
    for key, value in sorted(summary["verdict_counts"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Hypothesis Families", ""])
    for key, value in sorted(summary["kind_counts"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Researchability Counts", ""])
    for key, value in sorted(summary["researchability_counts"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Synthetic Receipt-State Mutations", ""])
    lines.append(f"- Checked: `{synthetic_summary['hypotheses']}`")
    lines.append(f"- Fail-closed observed: `{synthetic_summary['fail_closed_observed']}`")
    lines.append(f"- Fail-closed failures: `{synthetic_summary['fail_closed_failures']}`")
    for key, value in sorted(synthetic_summary["verdict_counts"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Synthetic Blocker-State Mutations", ""])
    lines.append(f"- Checked: `{synthetic_blocker_summary['hypotheses']}`")
    lines.append(f"- Fail-closed observed: `{synthetic_blocker_summary['fail_closed_observed']}`")
    lines.append(f"- Fail-closed failures: `{synthetic_blocker_summary['fail_closed_failures']}`")
    for key, value in sorted(synthetic_blocker_summary["verdict_counts"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Synthetic Provenance-State Mutations", ""])
    lines.append(f"- Checked: `{synthetic_provenance_summary['hypotheses']}`")
    lines.append(f"- Fail-closed observed: `{synthetic_provenance_summary['fail_closed_observed']}`")
    lines.append(f"- Fail-closed failures: `{synthetic_provenance_summary['fail_closed_failures']}`")
    for key, value in sorted(synthetic_provenance_summary["by_channel"].items()):
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Frontier", ""])
    lines.append(f"- Surface count: `{frontier['surface_count']}`")
    lines.append(f"- Max simple path depth: `{frontier['max_simple_path_depth']}`")
    lines.append(f"- Requested composition depth: `{frontier['requested_max_depth']}`")
    lines.append(f"- Effective composition depth: `{frontier['effective_max_depth']}`")
    lines.append(f"- Simple path frontier exhausted: `{frontier['simple_path_frontier_exhausted']}`")
    lines.extend(["", "## Optional Evidence Blocks", ""])
    if not optional_evidence["blocked_surfaces"]:
        lines.append("- none")
    else:
        for item in optional_evidence["blocked_surfaces"]:
            lines.append(f"- `{item['surface_id']}` status `{item['optional_status']}`")
            for blocker in item["blockers"]:
                lines.append(f"- `{blocker}`")
    lines.extend(["", "## Research Block Frontier", ""])
    lines.append(f"- Gate: `{gate_summary['gate']}`")
    lines.append(
        f"- Open for bounded research: `{gate_summary['open_for_bounded_research']}`"
    )
    if gate_summary["blockers"]:
        for blocker in gate_summary["blockers"]:
            lines.append(f"- Gate blocker: `{blocker}`")
    else:
        lines.append("- Gate blockers: none")
    lines.append(
        f"- Single-surface optional cut clears all blocks: "
        f"`{research_blocks['single_surface_optional_cut_clears_all_blocks']}`"
    )
    if research_blocks["optional_block_counts"]:
        for surface_id, count in sorted(
            research_blocks["optional_block_counts"].items(),
            key=lambda item: (-item[1], item[0]),
        ):
            lines.append(f"- `{surface_id}`: `{count}` blocked hypotheses")
    else:
        lines.append("- none")
    lines.extend(["", "## Blocked Families", ""])
    for kind, entry in blocked_family_summary["by_kind"].items():
        lines.append(
            f"- `{kind}`: total `{entry['total']}`, researchable `{entry['researchable']}`, "
            f"optional-blocked `{entry['optional_blocked']}`, mandatory/unknown `{entry['mandatory_or_unknown_blocked']}`, "
            f"reachable `{entry['reachable_witness']}`"
        )
        if entry["representative_blocked_hypothesis"]:
            lines.append(f"- representative `{entry['representative_blocked_hypothesis']}`")
    lines.extend(["", "## Receipt Provenance", ""])
    lines.append(f"- Current git head: `{provenance['current_git_head']}`")
    for channel in ("mandatory", "optional"):
        bucket = provenance[channel]
        lines.append(
            f"- `{channel}` receipts: total `{bucket['total']}`, exists `{bucket['exists']}`, "
            f"with git head `{bucket['with_git_head']}`, matching `{bucket['matching_git_head']}`, "
            f"mismatched `{bucket['mismatched_git_head']}`, missing git head `{bucket['missing_git_head']}`"
        )
    if provenance["mismatches"]:
        for item in provenance["mismatches"][:20]:
            lines.append(
                f"- mismatch `{item['surface_id']}` `{item['channel']}` `{item['path']}` -> `{item['git_head']}`"
            )
    else:
        lines.append("- Git-head mismatches: none")
    lines.extend(["", "## Result Storage", ""])
    lines.append(f"- Mode: `{result_storage['mode']}`")
    lines.append(f"- Full results included: `{result_storage['full_results_included']}`")
    for name, digest in sorted(result_storage["digests"].items()):
        lines.append(f"- `{name}`: count `{digest['count']}`, hash `{digest['hash']}`")
    lines.extend(["", "## Compressed Independent Frontier", ""])
    lines.append(
        f"- Total independent co-reachability what-ifs: `{compressed['totals']['total']}`"
    )
    lines.append(f"- Researchable: `{compressed['totals']['researchable']}`")
    lines.append(f"- Optional blocked: `{compressed['totals']['optional_blocked']}`")
    lines.append(f"- Mandatory blocked: `{compressed['totals']['mandatory_blocked']}`")
    for row in compressed["by_order"]:
        lines.append(
            f"- order `{row['order']}`: total `{row['total']}`, "
            f"researchable `{row['researchable']}`, optional-blocked `{row['optional_blocked']}`, "
            f"mandatory-blocked `{row['mandatory_blocked']}`"
        )
    lines.extend(["", "## Counterfactual Unblock", ""])
    if not counterfactual["applicable"]:
        lines.append(f"- Not applicable: `{counterfactual['reason']}`")
    else:
        after = counterfactual["summary_after_clear"]
        compressed_after = counterfactual["compressed_independent_frontier_after_clear"]
        lines.append(f"- Cleared surfaces: `{', '.join(counterfactual['cleared_surfaces'])}`")
        lines.append(
            f"- Opens all materialized hypotheses: "
            f"`{counterfactual['opens_all_materialized_hypotheses']}`"
        )
        lines.append(
            f"- Opens all compressed independent frontier: "
            f"`{counterfactual['opens_all_compressed_independent_frontier']}`"
        )
        lines.append(
            f"- Materialized after clear: researchable "
            f"`{after['researchability_counts'].get('researchable_under_current_bounded_receipts', 0)}`, "
            f"optional-blocked "
            f"`{after['researchability_counts'].get('blocked_for_promotion_due_optional_instability', 0)}`, "
            f"unknown `{after['unknown_blocked']}`, reachable "
            f"`{after['reachable_disaster_witnesses']}`"
        )
        lines.append(
            f"- Compressed after clear: researchable "
            f"`{compressed_after['totals']['researchable']}`, optional-blocked "
            f"`{compressed_after['totals']['optional_blocked']}`, mandatory-blocked "
            f"`{compressed_after['totals']['mandatory_blocked']}`"
        )
    lines.extend(["", "## Promotion / Research Blocks", ""])
    if report.get("results"):
        blocked = [
            r
            for r in report["results"]
            if r["researchability"] != "researchable_under_current_bounded_receipts"
        ]
        truncated = 0
    else:
        blocked = result_samples["blocked_results"]
        truncated = result_samples["truncated"]["blocked_results"]
    if not blocked:
        lines.append("- none")
    else:
        for result in blocked[:40]:
            lines.append(f"- `{result['hypothesis_id']}` -> `{result['researchability']}`")
        if truncated:
            lines.append(f"- `{truncated}` additional blocked results omitted from compact sample")
    lines.extend(["", "## Scope", ""])
    lines.append(
        "This receipt exhausts generated single-surface, receipt-fail-open, edge-composition, "
        "independent-pair and independent-triple co-reachability, order-inversion, bounded-chain, "
        "chain-terminal, fan-out, convergence, re-entry, and cycle-amplification hypotheses over "
        "the current atlas/receipt witness space. It also summarizes the full independent "
        "co-reachability frontier through order 11 in compressed form and runs synthetic "
        "receipt-state, blocker-state, and provenance-state mutation checks. "
        "It is not a global proof of safety."
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--max-depth",
        type=int,
        default=0,
        help="composition path depth; 0 means full simple-path depth over known surfaces",
    )
    parser.add_argument("--json", default=str(DEFAULT_JSON))
    parser.add_argument("--md", default=str(DEFAULT_MD))
    parser.add_argument(
        "--strict-research-gate",
        action="store_true",
        help="exit nonzero unless the bounded research gate is fully open",
    )
    parser.add_argument(
        "--full-results",
        action="store_true",
        help="include full materialized per-hypothesis result arrays in the JSON receipt",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run in-process disaster-loop gate self-tests without reading/writing receipts",
    )
    args = parser.parse_args()
    if args.self_test:
        return self_test()

    atlas = json.loads(ATLAS.read_text(encoding="utf-8"))
    current_git_head = git_head()
    surfaces = {surface["surface_id"]: surface for surface in atlas.get("surfaces", [])}
    effective_max_depth = args.max_depth if args.max_depth > 0 else len(surfaces)
    frontier = {
        "surface_count": len(surfaces),
        "max_simple_path_depth": len(surfaces),
        "requested_max_depth": args.max_depth,
        "effective_max_depth": effective_max_depth,
        "simple_path_frontier_exhausted": effective_max_depth >= len(surfaces),
    }
    composition_edges, composition_edge_source = load_edge_family(
        atlas, "composition_edges", DEFAULT_COMPOSITION_EDGES
    )
    reentry_edges, reentry_edge_source = load_edge_family(atlas, "reentry_edges", DEFAULT_REENTRY_EDGES)
    validate_edge_refs(composition_edges, set(surfaces), "composition_edges")
    validate_edge_refs(reentry_edges, set(surfaces), "reentry_edges")
    checks = {surface_id: check_surface(surface) for surface_id, surface in surfaces.items()}
    hypotheses = generate_hypotheses(atlas, effective_max_depth, composition_edges, reentry_edges)
    results = [evaluate(hypothesis, checks) for hypothesis in hypotheses]
    synthetic_mutation_results = evaluate_receipt_state_mutations(surfaces, checks)
    synthetic_blocker_results = evaluate_blocker_state_mutations(surfaces, checks)
    summary = summarize(results)
    synthetic_mutation_summary = summarize_synthetic_mutations(synthetic_mutation_results)
    synthetic_blocker_summary = summarize_synthetic_mutations(synthetic_blocker_results)
    optional_evidence_summary = summarize_optional_evidence(checks)
    research_block_summary = summarize_research_blocks(results, checks)
    blocked_family_summary = summarize_blocked_families(results)
    receipt_provenance_summary = summarize_receipt_provenance(checks, current_git_head)
    counterfactual_unblock_summary = summarize_counterfactual_unblock(surfaces, results, checks)
    compressed_independent_frontier = summarize_compressed_independent_frontier(surfaces, checks)
    synthetic_provenance_results = evaluate_provenance_state_mutations(
        checks,
        summary,
        synthetic_mutation_summary,
        synthetic_blocker_summary,
        optional_evidence_summary,
        frontier,
        current_git_head,
    )
    synthetic_provenance_summary = summarize_synthetic_provenance_mutations(
        synthetic_provenance_results
    )
    gate_summary = summarize_gate_status(
        summary,
        synthetic_mutation_summary,
        synthetic_blocker_summary,
        optional_evidence_summary,
        receipt_provenance_summary,
        frontier,
        synthetic_provenance_summary,
    )
    result_storage = summarize_result_storage(
        args.full_results,
        results,
        synthetic_mutation_results,
        synthetic_blocker_results,
        synthetic_provenance_results,
    )
    result_sample_summary = sample_results(
        results,
        synthetic_mutation_results,
        synthetic_blocker_results,
        synthetic_provenance_results,
    )

    report = {
        "schema": "mprd/neuro-symbolic-disaster-loop/v1",
        "program_id": atlas.get("program_id"),
        "generated_at_utc": now_iso(),
        "current_git_head": current_git_head,
        "atlas": rel(ATLAS),
        "max_depth": effective_max_depth,
        "surface_count": len(surfaces),
        "frontier": frontier,
        "edge_sources": {
            "composition_edges": composition_edge_source,
            "reentry_edges": reentry_edge_source,
        },
        "composition_edges": [
            {"src": src, "dst": dst, "reason": reason}
            for src, dst, reason in composition_edges
        ],
        "reentry_edges": [
            {"src": src, "dst": dst, "reason": reason}
            for src, dst, reason in reentry_edges
        ],
        "summary": summary,
        "synthetic_mutation_summary": synthetic_mutation_summary,
        "synthetic_blocker_summary": synthetic_blocker_summary,
        "synthetic_provenance_summary": synthetic_provenance_summary,
        "optional_evidence_summary": optional_evidence_summary,
        "research_block_summary": research_block_summary,
        "blocked_family_summary": blocked_family_summary,
        "receipt_provenance_summary": receipt_provenance_summary,
        "gate_summary": gate_summary,
        "counterfactual_unblock_summary": counterfactual_unblock_summary,
        "compressed_independent_frontier": compressed_independent_frontier,
        "surface_checks": checks,
        "result_storage": result_storage,
        "result_samples": result_sample_summary,
        "results": results if args.full_results else [],
        "synthetic_mutation_results": synthetic_mutation_results if args.full_results else [],
        "synthetic_blocker_results": synthetic_blocker_results if args.full_results else [],
        "synthetic_provenance_results": synthetic_provenance_results
        if args.full_results
        else [],
    }
    report["stable_receipt_hash"] = stable_report_hash(report)

    json_path = Path(args.json)
    md_path = Path(args.md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(md_path, report)
    print("witness_space_summary:")
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    print("synthetic_mutation_summary:")
    print(json.dumps(report["synthetic_mutation_summary"], indent=2, sort_keys=True))
    print("synthetic_blocker_summary:")
    print(json.dumps(report["synthetic_blocker_summary"], indent=2, sort_keys=True))
    print("synthetic_provenance_summary:")
    print(json.dumps(report["synthetic_provenance_summary"], indent=2, sort_keys=True))
    print("gate_summary:")
    print(json.dumps(report["gate_summary"], indent=2, sort_keys=True))
    print("result_storage:")
    print(json.dumps(report["result_storage"], indent=2, sort_keys=True))
    print(f"wrote {json_path}")
    print(f"wrote {md_path}")
    if report["summary"]["reachable_disaster_witnesses"]:
        return 1
    if args.strict_research_gate and not report["gate_summary"]["open_for_bounded_research"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
