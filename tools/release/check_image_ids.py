#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REQUIRED_IDS = ("mprd_guest", "mprd_mpb_guest", "mprd_tau_compiled_guest")
ZERO_HEX = "0" * 64


def image_words_to_hex(words: list[int]) -> str:
    if len(words) != 8:
        raise ValueError(f"expected 8 u32 words, got {len(words)}")
    return "".join(int(word).to_bytes(4, "little", signed=False).hex() for word in words)


def load_expected_ids(path: Path) -> dict[str, str]:
    text = path.read_text()
    pattern = re.compile(r"pub const EXPECTED_(MPRD(?:_MPB|_TAU_COMPILED)?_GUEST)_ID:\s*\[u32;\s*8\]\s*=\s*\[([^\]]+)\];")
    expected: dict[str, str] = {}
    name_map = {
        "MPRD_GUEST": "mprd_guest",
        "MPRD_MPB_GUEST": "mprd_mpb_guest",
        "MPRD_TAU_COMPILED_GUEST": "mprd_tau_compiled_guest",
    }
    for match in pattern.finditer(text):
        raw_name = match.group(1)
        words = [int(part.strip()) for part in match.group(2).split(",") if part.strip()]
        expected[name_map[raw_name]] = image_words_to_hex(words)
    missing = [name for name in REQUIRED_IDS if name not in expected]
    if missing:
        raise ValueError(f"{path} missing expected image IDs: {', '.join(missing)}")
    return expected


def validate_payload(payload: dict, expected: dict[str, str] | None = None) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != "mprd/risc0-image-ids/v1":
        errors.append("schema must be mprd/risc0-image-ids/v1")
    ids = payload.get("ids")
    if not isinstance(ids, dict):
        errors.append("ids must be an object")
        return errors

    for name in REQUIRED_IDS:
        entry = ids.get(name)
        if not isinstance(entry, dict):
            errors.append(f"{name}: missing image ID entry")
            continue
        image_hex = entry.get("hex")
        if not isinstance(image_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", image_hex):
            errors.append(f"{name}: hex must be 64 lowercase hex characters")
            continue
        if image_hex == ZERO_HEX:
            errors.append(f"{name}: image ID is all-zero placeholder")
        if entry.get("is_placeholder") is True:
            errors.append(f"{name}: image ID is marked as placeholder")
        words = entry.get("u32_words")
        if isinstance(words, list):
            try:
                word_hex = image_words_to_hex(words)
            except (OverflowError, TypeError, ValueError) as exc:
                errors.append(f"{name}: invalid u32_words: {exc}")
            else:
                if word_hex != image_hex:
                    errors.append(f"{name}: u32_words do not match hex field")
        if expected is not None and expected.get(name) != image_hex:
            errors.append(
                f"{name}: image ID drift detected; got {image_hex}, expected {expected.get(name)}"
            )

    if payload.get("all_nonzero") is not True:
        errors.append("all_nonzero must be true for release artifacts")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail closed on placeholder or drifted Risc0 image IDs.")
    parser.add_argument("image_ids_json", type=Path)
    parser.add_argument(
        "--expected-rust",
        type=Path,
        default=Path("methods/src/expected_image_ids.rs"),
        help="Rust file containing EXPECTED_*_ID constants.",
    )
    args = parser.parse_args()

    payload = json.loads(args.image_ids_json.read_text())
    expected = load_expected_ids(args.expected_rust) if args.expected_rust else None
    errors = validate_payload(payload, expected)
    if errors:
        for error in errors:
            print(f"release image ID gate failed: {error}", file=sys.stderr)
        return 2
    print("release image ID gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
