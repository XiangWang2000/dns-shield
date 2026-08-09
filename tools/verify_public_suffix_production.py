#!/usr/bin/env python3
"""Verify generated production Public Suffix outputs against one pinned manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from build_public_suffix import (
    FLAG_INCLUDES_PRIVATE,
    FORMAT_VERSION,
    HEADER_FORMAT,
    MAGIC,
    build_artifact,
)


@dataclass(frozen=True)
class ProductionManifest:
    schema_version: int
    source_revision: str
    git_blob_sha1: str
    idna_version: str
    normalized_sha256: str
    normalized_size: int
    artifact_sha256: str
    artifact_size: int
    exact_rules: int
    wildcard_rules: int
    exception_rules: int


@dataclass(frozen=True)
class VerificationReport:
    source_revision: str
    normalized_sha256: str
    normalized_size: int
    artifact_sha256: str
    artifact_size: int
    exact_rules: int
    wildcard_rules: int
    exception_rules: int


def _require_hash(value: str, length: int, description: str) -> None:
    if len(value) != length or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(
            f"{description} must be a lowercase {length}-character hexadecimal value"
        )


def load_production_manifest(path: Path) -> ProductionManifest:
    manifest = ProductionManifest(**json.loads(path.read_text(encoding="utf-8")))
    if manifest.schema_version != 1:
        raise ValueError(
            f"Unsupported production Public Suffix schema: {manifest.schema_version}"
        )
    _require_hash(manifest.source_revision, 40, "Public Suffix source revision")
    _require_hash(manifest.git_blob_sha1, 40, "Public Suffix git blob")
    _require_hash(manifest.normalized_sha256, 64, "Normalized source SHA-256")
    _require_hash(manifest.artifact_sha256, 64, "Artifact SHA-256")
    for name, value in (
        ("normalized_size", manifest.normalized_size),
        ("artifact_size", manifest.artifact_size),
        ("exact_rules", manifest.exact_rules),
        ("wildcard_rules", manifest.wildcard_rules),
        ("exception_rules", manifest.exception_rules),
    ):
        if value < 0:
            raise ValueError(f"Production Public Suffix {name} must be non-negative")
    if not manifest.idna_version:
        raise ValueError("Production Public Suffix IDNA version must not be blank")
    return manifest


def _require_equal(actual: object, expected: object, description: str) -> None:
    if actual != expected:
        raise ValueError(
            f"{description} mismatch: expected {expected}, found {actual}"
        )


def verify_artifact_contract(
    production_manifest_path: Path,
    artifact_path: Path,
) -> tuple[ProductionManifest, bytes]:
    """Verify one artifact without requiring the normalized source beside it."""
    expected = load_production_manifest(production_manifest_path)
    artifact = artifact_path.read_bytes()
    artifact_sha256 = hashlib.sha256(artifact).hexdigest()

    _require_equal(len(artifact), expected.artifact_size, "Artifact size")
    _require_equal(artifact_sha256, expected.artifact_sha256, "Artifact SHA-256")

    header_size = struct.calcsize(HEADER_FORMAT)
    if len(artifact) < header_size:
        raise ValueError(
            f"Artifact is smaller than its {header_size}-byte production header"
        )

    (
        magic,
        version,
        flags,
        exact_count,
        wildcard_count,
        exception_count,
        embedded_source_sha256,
    ) = struct.unpack_from(HEADER_FORMAT, artifact)
    _require_equal(magic, MAGIC, "Artifact magic")
    _require_equal(version, FORMAT_VERSION, "Artifact format version")
    _require_equal(flags, FLAG_INCLUDES_PRIVATE, "Artifact flags")
    _require_equal(
        embedded_source_sha256.hex(),
        expected.normalized_sha256,
        "Embedded source SHA-256",
    )
    _require_equal(
        (exact_count, wildcard_count, exception_count),
        (expected.exact_rules, expected.wildcard_rules, expected.exception_rules),
        "Artifact header rule counts",
    )
    return expected, artifact


def verify_production_outputs(
    production_manifest_path: Path,
    source_manifest_path: Path,
    normalized_path: Path,
    artifact_path: Path,
) -> VerificationReport:
    expected, artifact = verify_artifact_contract(
        production_manifest_path,
        artifact_path,
    )
    source_manifest = json.loads(source_manifest_path.read_text(encoding="utf-8"))

    _require_equal(
        source_manifest.get("source_revision"),
        expected.source_revision,
        "Public Suffix source revision",
    )
    _require_equal(
        source_manifest.get("git_blob_sha1"),
        expected.git_blob_sha1,
        "Public Suffix Git blob",
    )
    _require_equal(
        source_manifest.get("idna_version"),
        expected.idna_version,
        "Public Suffix IDNA version",
    )

    normalized = normalized_path.read_bytes()
    normalized_sha256 = hashlib.sha256(normalized).hexdigest()

    _require_equal(len(normalized), expected.normalized_size, "Normalized source size")
    _require_equal(
        normalized_sha256,
        expected.normalized_sha256,
        "Normalized source SHA-256",
    )

    regenerated_artifact, rules = build_artifact(normalized)
    if regenerated_artifact != artifact:
        raise ValueError(
            "Production Public Suffix artifact does not exactly match deterministic regeneration"
        )

    actual_counts = (
        len(rules.exact),
        len(rules.wildcard_suffixes),
        len(rules.exceptions),
    )
    expected_counts = (
        expected.exact_rules,
        expected.wildcard_rules,
        expected.exception_rules,
    )
    _require_equal(actual_counts, expected_counts, "Production rule counts")

    return VerificationReport(
        source_revision=expected.source_revision,
        normalized_sha256=normalized_sha256,
        normalized_size=len(normalized),
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        artifact_size=len(artifact),
        exact_rules=actual_counts[0],
        wildcard_rules=actual_counts[1],
        exception_rules=actual_counts[2],
    )


def write_report(path: Path, report: VerificationReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(asdict(report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--normalized", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--report-output", type=Path)
    args = parser.parse_args()

    report = verify_production_outputs(
        args.manifest,
        args.source_manifest,
        args.normalized,
        args.artifact,
    )
    if args.report_output is not None:
        write_report(args.report_output, report)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
