#!/usr/bin/env python3
"""Verify a candidate packaged Public Suffix asset against the pinned production contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from verify_public_suffix_production import verify_artifact_contract


@dataclass(frozen=True)
class AssetVerificationReport:
    artifact_sha256: str
    artifact_size: int
    normalized_sha256: str
    exact_rules: int
    wildcard_rules: int
    exception_rules: int


def verify_asset(
    production_manifest_path: Path,
    asset_path: Path,
) -> AssetVerificationReport:
    expected, artifact = verify_artifact_contract(
        production_manifest_path,
        asset_path,
    )
    return AssetVerificationReport(
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
        artifact_size=len(artifact),
        normalized_sha256=expected.normalized_sha256,
        exact_rules=expected.exact_rules,
        wildcard_rules=expected.wildcard_rules,
        exception_rules=expected.exception_rules,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--asset", required=True, type=Path)
    args = parser.parse_args()

    report = verify_asset(args.manifest, args.asset)
    print(json.dumps(asdict(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
