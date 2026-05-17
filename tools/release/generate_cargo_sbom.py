#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def utc_now() -> str:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        return datetime.fromtimestamp(int(source_date_epoch), UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def spdx_id(raw: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", raw)
    return f"SPDXRef-Package-{cleaned}"


def package_purl(package: dict) -> str:
    return f"pkg:cargo/{package['name']}@{package['version']}"


def run_cargo_metadata() -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def build_sbom(metadata: dict, version: str, target: str) -> dict:
    namespace_seed = json.dumps(
        {
            "version": version,
            "target": target,
            "workspace_root": metadata.get("workspace_root"),
            "resolve_root": metadata.get("resolve", {}).get("root"),
        },
        sort_keys=True,
    ).encode()
    namespace_hash = hashlib.sha256(namespace_seed).hexdigest()
    packages = []
    relationships = []
    seen_ids: set[str] = set()

    for index, package in enumerate(sorted(metadata["packages"], key=lambda p: (p["name"], p["version"], p["id"]))):
        package_id = spdx_id(f"{package['name']}-{package['version']}-{index}")
        seen_ids.add(package_id)
        external_refs = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": package_purl(package),
            }
        ]
        packages.append(
            {
                "name": package["name"],
                "SPDXID": package_id,
                "versionInfo": package["version"],
                "downloadLocation": package.get("source") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": package.get("license") or "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": external_refs,
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": package_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"MPRD {version} {target}",
        "documentNamespace": f"https://github.com/TheDarkLightX/MPRD/releases/{version}/sbom/{namespace_hash}",
        "creationInfo": {
            "created": utc_now(),
            "creators": ["Tool: tools/release/generate_cargo_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal SPDX JSON SBOM from Cargo metadata.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    metadata = run_cargo_metadata()
    sbom = build_sbom(metadata, args.version, args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
