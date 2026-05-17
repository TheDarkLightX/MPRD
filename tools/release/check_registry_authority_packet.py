#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "mprd/registry-authority-admission/v1"
REPORT_SCHEMA = "mprd/registry-authority-admission-report/v1"
TIER_RANK = {
    "experimental": 0,
    "certified": 1,
    "verified": 2,
}
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"failed to parse JSON {path}: {exc}")
    if not isinstance(payload, dict):
        fail(f"JSON root must be an object: {path}")
    return payload


def require_str(obj: dict[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"missing non-empty string field: {key}")
    return value.strip()


def require_id(obj: dict[str, Any], key: str) -> str:
    value = require_str(obj, key)
    if not ID_RE.fullmatch(value):
        fail(f"{key} must be a stable id matching {ID_RE.pattern}: {value!r}")
    return value


def require_hex32(obj: dict[str, Any], key: str) -> str:
    value = require_str(obj, key).lower()
    if not HEX32_RE.fullmatch(value):
        fail(f"{key} must be lowercase 32-byte hex")
    if set(value) == {"0"}:
        fail(f"{key} must not be all-zero")
    return value


def require_epoch(obj: dict[str, Any], key: str) -> int:
    value = obj.get(key)
    if not isinstance(value, int) or value < 0:
        fail(f"{key} must be a non-negative integer")
    return value


def require_tier(obj: dict[str, Any], key: str) -> str:
    value = require_str(obj, key).lower()
    if value not in TIER_RANK:
        fail(f"{key} must be one of {sorted(TIER_RANK)}")
    return value


def require_id_list(obj: dict[str, Any], key: str) -> list[str]:
    value = obj.get(key)
    if not isinstance(value, list) or not value:
        fail(f"{key} must be a non-empty list")
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not ID_RE.fullmatch(item.strip()):
            fail(f"{key}[{idx}] must be a stable id")
        out.append(item.strip())
    if len(set(out)) != len(out):
        fail(f"{key} must not contain duplicates")
    return out


def validate(packet: dict[str, Any], release_report: dict[str, Any], *, expected_environment: str | None) -> dict[str, Any]:
    if packet.get("schema") != SCHEMA:
        fail(f"registry authority packet schema must be {SCHEMA}")
    if release_report.get("report_schema") != "mprd/deploy-verify-release/v1":
        fail("release report schema must be mprd/deploy-verify-release/v1")

    environment = require_str(packet, "environment")
    if expected_environment is not None and environment != expected_environment:
        fail(f"authority environment mismatch: packet={environment!r} expected={expected_environment!r}")
    local_node_id = require_id(packet, "local_node_id")

    binding = packet.get("registry_binding")
    if not isinstance(binding, dict):
        fail("registry_binding must be an object")
    policy_epoch = require_epoch(binding, "policy_epoch")
    registry_root_hex = require_hex32(binding, "registry_root_hex")
    if policy_epoch != release_report.get("policy_epoch"):
        fail("registry authority policy_epoch does not match verified release report")
    if registry_root_hex != str(release_report.get("registry_root_hex", "")).lower():
        fail("registry authority registry_root_hex does not match verified release report")

    namespaces_raw = packet.get("namespaces")
    if not isinstance(namespaces_raw, list) or not namespaces_raw:
        fail("namespaces must be a non-empty list")
    namespaces: dict[str, dict[str, Any]] = {}
    for idx, raw in enumerate(namespaces_raw):
        if not isinstance(raw, dict):
            fail(f"namespaces[{idx}] must be an object")
        namespace_id = require_id(raw, "namespace_id")
        if namespace_id in namespaces:
            fail(f"duplicate namespace_id: {namespace_id}")
        owner_set_id = require_id(raw, "owner_set_id")
        allowed_node_ids = require_id_list(raw, "allowed_node_ids")
        min_tier = require_tier(raw, "min_certification_tier")
        activation_epoch = require_epoch(raw, "activation_epoch")
        if activation_epoch > policy_epoch:
            fail(f"namespace {namespace_id} activation_epoch is in the future")
        if local_node_id not in allowed_node_ids:
            fail(f"local_node_id {local_node_id} is not assigned to namespace {namespace_id}")
        namespaces[namespace_id] = {
            "owner_set_id": owner_set_id,
            "allowed_node_ids": allowed_node_ids,
            "min_certification_tier": min_tier,
            "activation_epoch": activation_epoch,
        }

    release_policies = release_report.get("policies")
    if not isinstance(release_policies, list) or not release_policies:
        fail("release report must contain at least one policy")
    release_by_hash: dict[str, dict[str, Any]] = {}
    for idx, policy in enumerate(release_policies):
        if not isinstance(policy, dict):
            fail(f"release policies[{idx}] must be an object")
        policy_hash = require_hex32(policy, "policy_hash_hex")
        if policy_hash in release_by_hash:
            fail(f"duplicate release policy hash: {policy_hash}")
        if policy.get("artifact_validation") != "validated":
            fail(f"release policy {policy_hash} is not artifact-validated")
        release_by_hash[policy_hash] = policy

    admissions_raw = packet.get("policy_admissions")
    if not isinstance(admissions_raw, list) or not admissions_raw:
        fail("policy_admissions must be a non-empty list")
    admissions_by_hash: dict[str, dict[str, Any]] = {}
    for idx, raw in enumerate(admissions_raw):
        if not isinstance(raw, dict):
            fail(f"policy_admissions[{idx}] must be an object")
        policy_hash = require_hex32(raw, "policy_hash_hex")
        if policy_hash in admissions_by_hash:
            fail(f"duplicate policy admission: {policy_hash}")
        admissions_by_hash[policy_hash] = raw

    release_hashes = set(release_by_hash)
    admission_hashes = set(admissions_by_hash)
    if admission_hashes != release_hashes:
        fail(
            "policy_admissions must exactly match verified release policies "
            f"(missing={sorted(release_hashes - admission_hashes)} extra={sorted(admission_hashes - release_hashes)})"
        )

    normalized_admissions: list[dict[str, Any]] = []
    for policy_hash in sorted(admissions_by_hash):
        admission = admissions_by_hash[policy_hash]
        release_policy = release_by_hash[policy_hash]
        namespace_id = require_id(admission, "namespace_id")
        namespace = namespaces.get(namespace_id)
        if namespace is None:
            fail(f"policy {policy_hash} references unknown namespace {namespace_id}")
        certification_tier = require_tier(admission, "certification_tier")
        if TIER_RANK[certification_tier] < TIER_RANK[namespace["min_certification_tier"]]:
            fail(f"policy {policy_hash} certification tier is below namespace minimum")
        activation_epoch = require_epoch(admission, "activation_epoch")
        if activation_epoch > policy_epoch:
            fail(f"policy {policy_hash} activation_epoch is in the future")
        admitted_node_ids = require_id_list(admission, "admitted_node_ids")
        unknown_nodes = sorted(set(admitted_node_ids) - set(namespace["allowed_node_ids"]))
        if unknown_nodes:
            fail(f"policy {policy_hash} admits nodes outside namespace assignment: {unknown_nodes}")
        if local_node_id not in admitted_node_ids:
            fail(f"local_node_id {local_node_id} is not admitted for policy {policy_hash}")

        expected_source_governance = admission.get("source_governance")
        if expected_source_governance is not None and expected_source_governance != release_policy.get("source_governance"):
            fail(f"policy {policy_hash} source_governance does not match release report")
        expected_exec_kind = admission.get("policy_exec_kind")
        if expected_exec_kind is not None and expected_exec_kind != release_policy.get("policy_exec_kind"):
            fail(f"policy {policy_hash} policy_exec_kind does not match release report")

        normalized_admissions.append(
            {
                "policy_hash_hex": policy_hash,
                "namespace_id": namespace_id,
                "certification_tier": certification_tier,
                "activation_epoch": activation_epoch,
                "admitted_node_ids": admitted_node_ids,
                "source_governance": release_policy.get("source_governance"),
                "policy_exec_kind": release_policy.get("policy_exec_kind"),
            }
        )

    return {
        "schema": REPORT_SCHEMA,
        "ok": True,
        "environment": environment,
        "policy_epoch": policy_epoch,
        "registry_root_hex": registry_root_hex,
        "local_node_id": local_node_id,
        "namespace_count": len(namespaces),
        "policy_admission_count": len(normalized_admissions),
        "namespaces": sorted(namespaces.keys()),
        "policy_admissions": normalized_admissions,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry-authority", required=True, type=Path)
    parser.add_argument("--release-report", required=True, type=Path)
    parser.add_argument("--environment")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    packet = load_json(args.registry_authority)
    release_report = load_json(args.release_report)
    report = validate(packet, release_report, expected_environment=args.environment)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
