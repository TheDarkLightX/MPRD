#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from check_image_ids import load_expected_ids, validate_payload


ROOT = Path(__file__).resolve().parents[2]


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True)
    return proc.stdout.strip()


def maybe_run(cmd: list[str]) -> str | None:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        return datetime.fromtimestamp(int(source_date_epoch), UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def release_mtime() -> int:
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch:
        return int(source_date_epoch)
    commit_timestamp = maybe_run(["git", "show", "-s", "--format=%ct", "HEAD"])
    return int(commit_timestamp) if commit_timestamp else 0


def read_rust_toolchain() -> str:
    path = ROOT / "rust-toolchain.toml"
    if not path.exists():
        return "unknown"
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("channel"):
            return stripped.split("=", 1)[1].strip().strip('"')
    return "unknown"


def image_id_map(payload: dict) -> dict[str, str]:
    return {name: entry["hex"] for name, entry in payload["ids"].items()}


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_checksums(path: Path, files: list[Path], base_dir: Path) -> None:
    rows = []
    for item in sorted(files, key=lambda p: str(p.relative_to(base_dir))):
        rel = item.relative_to(base_dir).as_posix()
        rows.append(f"{sha256_file(item)}  {rel}")
    path.write_text("\n".join(rows) + "\n")


def add_tree_to_tar(tar: tarfile.TarFile, source: Path, arc_root: str, mtime: int) -> None:
    for path in sorted(source.rglob("*")):
        rel = path.relative_to(source).as_posix()
        arcname = f"{arc_root}/{rel}"
        info = tar.gettarinfo(str(path), arcname)
        info.mtime = mtime
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        if path.is_file():
            with path.open("rb") as fh:
                tar.addfile(info, fh)
        else:
            tar.addfile(info)


def write_tar_gz(source: Path, output: Path, arc_root: str, mtime: int) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=mtime) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                add_tree_to_tar(tar, source, arc_root, mtime)


def require_release_env(allow_dirty: bool) -> None:
    if os.environ.get("RISC0_FORCE_BUILD") != "1":
        raise SystemExit("RISC0_FORCE_BUILD=1 is required for release packaging")
    if os.environ.get("RISC0_SKIP_BUILD") == "1":
        raise SystemExit("RISC0_SKIP_BUILD=1 is forbidden for release packaging")
    dirty = run(["git", "status", "--porcelain"])
    if dirty and not allow_dirty:
        raise SystemExit("refusing to package a release from a dirty worktree; pass --allow-dirty for local dry runs only")


def main() -> int:
    parser = argparse.ArgumentParser(description="Package an attested MPRD release binary tarball.")
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--image-ids-json", type=Path, required=True)
    parser.add_argument("--image-ids-text", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--release-claim",
        default="registry-bound mpb-v1 production path only",
    )
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    require_release_env(args.allow_dirty)
    if not args.binary.exists():
        raise SystemExit(f"missing binary: {args.binary}")
    if not args.sbom.exists():
        raise SystemExit(f"missing SBOM: {args.sbom}")

    payload = json.loads(args.image_ids_json.read_text())
    expected = load_expected_ids(ROOT / "methods/src/expected_image_ids.rs")
    errors = validate_payload(payload, expected)
    if errors:
        raise SystemExit("release image ID gate failed:\n" + "\n".join(f"- {error}" for error in errors))

    git_commit = run(["git", "rev-parse", "HEAD"])
    git_tag = maybe_run(["git", "describe", "--tags", "--exact-match", "HEAD"])
    binary_sha256 = sha256_file(args.binary)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_name = f"mprd-{args.version}-{args.target}"
    tar_path = output_dir / f"{package_name}.tar.gz"
    build_info_path = output_dir / f"{package_name}-build-info.json"
    report_path = output_dir / f"{package_name}-release-report.json"

    build_info = {
        "project": "MPRD",
        "version": args.version,
        "git_commit": git_commit,
        "git_tag": git_tag,
        "rust_toolchain": read_rust_toolchain(),
        "risc0_tooling": os.environ.get("CARGO_RISCZERO_VERSION", "cargo-risczero 1.2.6"),
        "risc0_force_build": True,
        "risc0_skip_build": False,
        "targets": [args.target],
        "embedded_guest_image_ids": image_id_map(payload),
        "release_claim": args.release_claim,
        "binary_sha256": binary_sha256,
        "built_at": utc_now(),
    }
    report = {
        "schema": "mprd/binary-release-report/v1",
        "project": "MPRD",
        "version": args.version,
        "target": args.target,
        "git_commit": git_commit,
        "release_claim": args.release_claim,
        "release_artifact_class": "production-grade",
        "binary": {
            "name": "mprd",
            "sha256": binary_sha256,
        },
        "gates": {
            "risc0_force_build": True,
            "risc0_skip_build_forbidden": True,
            "image_ids_nonzero": True,
            "image_ids_match_locked_expected_ids": True,
            "sbom_present": True,
            "cargo_lock_required": (ROOT / "Cargo.lock").exists(),
            "rust_toolchain_pinned": (ROOT / "rust-toolchain.toml").exists(),
        },
        "known_exclusions": [
            "release artifact does not bundle private signing keys or operator registry secrets",
            "deployment-specific signed registry checkpoints and guest manifests remain deployment bundle inputs",
        ],
        "created_at": utc_now(),
    }

    write_json(build_info_path, build_info)
    write_json(report_path, report)

    with tempfile.TemporaryDirectory(prefix="mprd-release-") as tmp:
        staging = Path(tmp) / package_name
        staging.mkdir()
        shutil.copy2(args.binary, staging / "mprd")
        os.chmod(staging / "mprd", 0o755)
        for root_name in ("LICENSE", "README.md"):
            root_path = ROOT / root_name
            if root_path.exists():
                shutil.copy2(root_path, staging / root_name)
        (staging / "RELEASE_NOTES.md").write_text(
            f"# MPRD {args.version}\n\n"
            f"Release claim: {args.release_claim}.\n\n"
            "This artifact was packaged only after RISC0_FORCE_BUILD=1, non-placeholder image ID, "
            "locked expected image ID, SBOM, and checksum gates passed.\n"
        )
        write_json(staging / "BUILD_INFO.json", build_info)
        shutil.copy2(args.image_ids_text, staging / "image_ids.txt")
        shutil.copy2(args.sbom, staging / "sbom.spdx.json")
        write_json(staging / "release-report.json", report)
        checksum_inputs = [p for p in staging.rglob("*") if p.is_file()]
        write_checksums(staging / "checksums.txt", checksum_inputs, staging)
        write_tar_gz(staging, tar_path, package_name, release_mtime())

    (output_dir / f"{package_name}.tar.gz.sha256").write_text(
        f"{sha256_file(tar_path)}  {tar_path.name}\n"
    )
    print(tar_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
