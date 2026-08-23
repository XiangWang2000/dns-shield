#!/usr/bin/env python3
"""Verify the packaged active.bin against its pinned production contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from build_blocklist import (
    FORMAT_VERSION,
    HASH_ALGORITHM_FNV1A_64,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
)


@dataclass(frozen=True)
class ActiveBlocklistVerificationReport:
    artifact_sha256: str
    artifact_size: int
    entry_count: int
    source_revision: str
    source_sha256: str


def verify_asset(
    production_manifest_path: Path,
    asset_path: Path,
    source_manifest_path: Path | None = None,
) -> ActiveBlocklistVerificationReport:
    manifest = json.loads(production_manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError(
            f"Unsupported production manifest schema: {manifest.get('schema_version')}"
        )
    if source_manifest_path is not None:
        source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))
        if source_manifest.get("schema_version") != 1:
            raise ValueError(
                "Unsupported source manifest schema: "
                f"{source_manifest.get('schema_version')}"
            )
        for field in ("source_revision", "source_sha256", "source_size"):
            if manifest[field] != source_manifest[field]:
                raise ValueError(f"Production/source manifest mismatch for {field}")
    artifact = asset_path.read_bytes()
    artifact_sha256 = hashlib.sha256(artifact).hexdigest()

    if len(artifact) != manifest["artifact_size"]:
        raise ValueError(
            f"Artifact size mismatch: expected {manifest['artifact_size']}, "
            f"found {len(artifact)}"
        )
    if artifact_sha256 != manifest["artifact_sha256"]:
        raise ValueError(
            "Artifact SHA-256 mismatch: expected "
            f"{manifest['artifact_sha256']}, found {artifact_sha256}"
        )
    if len(artifact) < HEADER_SIZE:
        raise ValueError("Artifact is smaller than its header")

    magic, version, algorithm, entry_count = struct.unpack_from(
        HEADER_FORMAT, artifact, 0
    )
    if magic != MAGIC:
        raise ValueError("Artifact magic does not match the blocklist format")
    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported artifact format version: {version}")
    if algorithm != HASH_ALGORITHM_FNV1A_64:
        raise ValueError(f"Unsupported artifact hash algorithm: {algorithm}")
    if entry_count != manifest["entry_count"]:
        raise ValueError(
            f"Artifact entry count mismatch: expected {manifest['entry_count']}, "
            f"found {entry_count}"
        )
    expected_size = HEADER_SIZE + entry_count * 8
    if expected_size != len(artifact):
        raise ValueError(
            f"Artifact header size mismatch: expected {expected_size}, "
            f"found {len(artifact)}"
        )

    previous: int | None = None
    for (current,) in struct.iter_unpack("<Q", artifact[HEADER_SIZE:]):
        if previous is not None and previous >= current:
            raise ValueError("Artifact hashes are not strictly sorted")
        previous = current

    return ActiveBlocklistVerificationReport(
        artifact_sha256=artifact_sha256,
        artifact_size=len(artifact),
        entry_count=entry_count,
        source_revision=manifest["source_revision"],
        source_sha256=manifest["source_sha256"],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-manifest", type=Path)
    parser.add_argument("--asset", required=True, type=Path)
    args = parser.parse_args()
    report = verify_asset(args.manifest, args.asset, args.source_manifest)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
