#!/usr/bin/env python3
"""Replay the tracked RC1 network barrier TLA specs and emit a summary receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any


REPLAY_SPECS = [
    "serial_commit_network_barrier",
    "distributed_replay_claim_barrier",
    "distributed_replay_visibility_barrier",
    "distributed_replay_lease_barrier",
    "distributed_replay_split_brain_barrier",
    "distributed_replay_direct_handoff_barrier",
    "distributed_replay_quorum_barrier",
    "distributed_replay_quorum_equivocation_barrier",
    "distributed_replay_equivocation_recovery_barrier",
    "distributed_replay_hidden_equivocation_barrier",
    "distributed_effect_finalization_barrier",
    "idempotent_http_effect_barrier",
    "idempotent_file_effect_barrier",
]


def repo_root() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def default_output_path() -> str:
    date = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    return f"docs/receipts/rc1_network_replay_{date}.json"


def resolve_tla2tools_jar(root: pathlib.Path) -> pathlib.Path:
    override = os.environ.get("TLA2TOOLS_JAR")
    if override:
        jar = pathlib.Path(override)
        if jar.is_file():
            return jar
        raise FileNotFoundError(f"TLA2TOOLS_JAR does not exist: {jar}")

    jar = root / "external" / "tla2tools" / "tla2tools.jar"
    if jar.is_file():
        return jar

    raise FileNotFoundError(
        "could not find tla2tools.jar; set TLA2TOOLS_JAR or restore external/tla2tools"
    )


def git_head(root: pathlib.Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()


def parse_metric(pattern: str, text: str, key: str) -> int:
    match = re.search(pattern, text)
    if not match:
        tail = text[-400:].replace("\n", "\\n")
        raise RuntimeError(f"missing TLC metric {key}; output tail={tail}")
    return int(match.group(1).replace(",", ""))


def relativize_or_placeholder(root: pathlib.Path, path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return "${TLA2TOOLS_JAR}"


def run_spec(root: pathlib.Path, jar: pathlib.Path, spec_name: str) -> dict[str, Any]:
    specs_dir = root / "docs" / "specs"
    tla_path = specs_dir / f"{spec_name}.tla"
    cfg_path = specs_dir / f"{spec_name}.cfg"
    if not tla_path.is_file() or not cfg_path.is_file():
        raise FileNotFoundError(f"missing TLA spec pair for {spec_name}")

    cmd = [
        "java",
        "-cp",
        str(jar),
        "tlc2.TLC",
        "-cleanup",
        "-deadlock",
        "-config",
        str(cfg_path),
        str(tla_path),
    ]
    proc = subprocess.run(
        cmd,
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    output = proc.stdout + proc.stderr
    tla_rel = str(tla_path.relative_to(root))
    cfg_rel = str(cfg_path.relative_to(root))
    jar_ref = relativize_or_placeholder(root, jar)
    output_lines = output.splitlines()

    entry: dict[str, Any] = {
        "spec": spec_name,
        "tla": tla_rel,
        "cfg": cfg_rel,
        "command": [
            "java",
            "-cp",
            jar_ref,
            "tlc2.TLC",
            "-cleanup",
            "-deadlock",
            "-config",
            cfg_rel,
            tla_rel,
        ],
        "exit_code": proc.returncode,
        "status": "passed" if proc.returncode == 0 else "failed",
        "tlc_version": output_lines[0] if output_lines else "unknown",
    }

    if proc.returncode == 0:
        entry["states_generated"] = parse_metric(
            r"([0-9,]+) states generated, [0-9,]+ distinct states found, [0-9,]+ states left on queue\.",
            output,
            "states_generated",
        )
        entry["distinct_states"] = parse_metric(
            r"[0-9,]+ states generated, ([0-9,]+) distinct states found, [0-9,]+ states left on queue\.",
            output,
            "distinct_states",
        )
        entry["search_depth"] = parse_metric(
            r"The depth of the complete state graph search is ([0-9,]+)\.",
            output,
            "search_depth",
        )
    else:
        entry["error_excerpt"] = output[-4000:]

    return entry


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=default_output_path(),
        help="repo-relative path for the summary receipt",
    )
    args = parser.parse_args()

    root = repo_root()
    jar = resolve_tla2tools_jar(root)
    entries = [run_spec(root, jar, spec_name) for spec_name in REPLAY_SPECS]
    all_passed = all(entry["status"] == "passed" for entry in entries)

    summary = {
        "schema": "mprd/rc1-network-replay/v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "git_head": git_head(root),
        "tla2tools_jar_ref": relativize_or_placeholder(root, jar),
        "all_passed": all_passed,
        "spec_count": len(entries),
        "entries": entries,
    }

    output_path = root / args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
