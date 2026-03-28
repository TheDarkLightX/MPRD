#!/usr/bin/env python3
"""Replay the tracked RC1 Tau equivalence receipt for shipped Policy Algebra menu entries."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = REPO_ROOT / "docs/receipts/rc1_policy_menu_tau_equivalence_20260328.json"
CLI_PREFIX = ["cargo", "run", "-q", "-p", "mprd-cli", "--", "policy"]
SCHEMA = "mprd/rc1-policy-menu-tau-equivalence-receipt/v1"


def run_cli(*args: str) -> str:
    proc = subprocess.run(
        [*CLI_PREFIX, *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join([*CLI_PREFIX, *args])}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc.stdout


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_menu_rows() -> list[dict[str, object]]:
    rows = json.loads(run_cli("algebra-menu-list", "--format", "json"))
    if not isinstance(rows, list):
        raise RuntimeError("menu list command did not return a JSON array")
    ids = [row.get("id") for row in rows]
    if len(ids) != len(set(ids)):
        raise RuntimeError("menu list returned duplicate ids")
    return rows


def build_receipt() -> dict[str, object]:
    rows = load_menu_rows()
    entries: list[dict[str, object]] = []

    with tempfile.TemporaryDirectory(prefix="mprd_policy_menu_tau_") as temp_dir:
        tmp = Path(temp_dir)
        for row in rows:
            menu_id = str(row["id"])
            output_name = str(row["suggested_output_name"])
            policy_path = tmp / f"{menu_id}.pal"
            tau_path = tmp / f"{menu_id}.tau"

            run_cli("algebra-menu-write", "--id", menu_id, "--out", str(policy_path))
            run_cli(
                "algebra-menu-emit-tau",
                "--id",
                menu_id,
                "--output-name",
                output_name,
                "--out",
                str(tau_path),
            )
            certify_stdout = run_cli(
                "algebra-certify-tau",
                "--policy",
                str(policy_path),
                "--tau",
                str(tau_path),
                "--output-name",
                output_name,
            )

            equivalent = any(
                line.strip() == "equivalent: true"
                for line in certify_stdout.splitlines()
            )
            if not equivalent:
                raise RuntimeError(
                    f"semantic equivalence failed for menu entry {menu_id}\n{certify_stdout}"
                )

            entries.append(
                {
                    "id": menu_id,
                    "category": row["category"],
                    "suggested_output_name": output_name,
                    "policy_hash_v1": row["policy_hash_v1"],
                    "robdd_sem_hash_v1": row["robdd_sem_hash_v1"],
                    "policy_bytes_sha256": sha256_hex(policy_path),
                    "tau_sha256": sha256_hex(tau_path),
                    "atoms": row["atoms"],
                    "deny_if_atoms": row["deny_if_atoms"],
                    "certified_equivalent": True,
                }
            )

    return {
        "schema": SCHEMA,
        "menu_count": len(entries),
        "entries": entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Where to write the deterministic JSON receipt",
    )
    args = parser.parse_args()

    receipt = build_receipt()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
