#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_commit() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def copy_first_image_ids(input_dir: Path, output_dir: Path, version: str) -> None:
    matches = sorted(input_dir.rglob("image_ids.txt"))
    if not matches:
        return
    shutil.copy2(matches[0], output_dir / f"mprd-{version}-image-ids.txt")
    json_matches = sorted(input_dir.rglob("image_ids.json"))
    if json_matches:
        shutil.copy2(json_matches[0], output_dir / f"mprd-{version}-image-ids.json")


def collect_release_reports(input_dir: Path) -> list[dict]:
    reports = []
    for path in sorted(input_dir.rglob("*-release-report.json")):
        reports.append(json.loads(path.read_text()))
    return reports


def write_combined_report(output_dir: Path, version: str, release_claim: str, reports: list[dict]) -> Path:
    path = output_dir / f"mprd-{version}-release-report.json"
    payload = {
        "schema": "mprd/binary-release-report-set/v1",
        "project": "MPRD",
        "version": version,
        "git_commit": git_commit(),
        "release_claim": release_claim,
        "reports": reports,
        "created_at": utc_now(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def write_checksums(output_dir: Path, version: str) -> Path:
    path = output_dir / f"mprd-{version}-checksums.txt"
    files = sorted(
        p for p in output_dir.iterdir()
        if p.is_file() and p.name != path.name and not p.name.endswith(".sig") and not p.name.endswith(".pem")
    )
    path.write_text("\n".join(f"{sha256_file(item)}  {item.name}" for item in files) + "\n")
    return path


def write_provenance(output_dir: Path, version: str, release_claim: str) -> Path:
    path = output_dir / f"mprd-{version}-provenance.intoto.jsonl"
    subjects = [
        {
            "name": item.name,
            "digest": {"sha256": sha256_file(item)},
        }
        for item in sorted(output_dir.iterdir())
        if item.is_file() and item.name != path.name and not item.name.endswith(".sig") and not item.name.endswith(".pem")
    ]
    builder_id = os.environ.get("GITHUB_SERVER_URL", "local")
    repository = os.environ.get("GITHUB_REPOSITORY", "TheDarkLightX/MPRD")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if run_id:
        builder_id = f"{builder_id}/{repository}/actions/runs/{run_id}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/TheDarkLightX/MPRD/.github/workflows/release-artifacts.yml",
                "externalParameters": {
                    "version": version,
                    "release_claim": release_claim,
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+https://github.com/{repository}",
                        "digest": {"gitCommit": git_commit()},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": run_id or "local",
                    "startedOn": utc_now(),
                },
            },
        },
    }
    path.write_text(json.dumps(statement, sort_keys=True) + "\n")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble top-level MPRD release assets.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--release-claim",
        default="registry-bound mpb-v1 production path only",
    )
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(args.input_dir.rglob("*")):
        if path.is_file() and path.name.endswith((".tar.gz", ".spdx.json", "-build-info.json", "-release-report.json")):
            shutil.copy2(path, args.output_dir / path.name)
    copy_first_image_ids(args.input_dir, args.output_dir, args.version)
    reports = collect_release_reports(args.input_dir)
    write_combined_report(args.output_dir, args.version, args.release_claim, reports)
    write_provenance(args.output_dir, args.version, args.release_claim)
    write_checksums(args.output_dir, args.version)
    print(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
