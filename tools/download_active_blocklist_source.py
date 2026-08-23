#!/usr/bin/env python3
"""Download and verify the pinned production blocklist source."""

from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

MAX_SOURCE_BYTES = 8 * 1024 * 1024


def validate_manifest(manifest: dict[str, object]) -> str:
    if manifest.get("schema_version") != 1:
        raise ValueError(
            f"Unsupported blocklist source schema: {manifest.get('schema_version')}"
        )
    revision = manifest["source_revision"]
    if (
        not isinstance(revision, str)
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        raise ValueError(f"Invalid pinned blocklist revision: {revision}")
    expected_url = (
        "https://raw.githubusercontent.com/badmojr/1Hosts/"
        f"{revision}/Lite/domains.wildcards"
    )
    if manifest["source_name"] != "badmojr/1Hosts Lite":
        raise ValueError(f"Unsupported blocklist source: {manifest['source_name']}")
    if manifest["source_path"] != "Lite/domains.wildcards":
        raise ValueError(f"Unsupported blocklist source path: {manifest['source_path']}")
    if manifest["source_url"] != expected_url:
        raise ValueError("Pinned blocklist source URL does not match its revision and path")
    return expected_url


def verify_source(manifest: dict[str, object], source: bytes) -> None:
    validate_manifest(manifest)

    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError(f"Blocklist source exceeds {MAX_SOURCE_BYTES} bytes")
    if len(source) != manifest["source_size"]:
        raise ValueError(
            f"Blocklist source size mismatch: expected {manifest['source_size']}, "
            f"found {len(source)}"
        )
    source_sha256 = hashlib.sha256(source).hexdigest()
    if source_sha256 != manifest["source_sha256"]:
        raise ValueError(
            "Blocklist source SHA-256 mismatch: expected "
            f"{manifest['source_sha256']}, found {source_sha256}"
        )
    git_blob_sha1 = hashlib.sha1(
        f"blob {len(source)}\0".encode("ascii") + source
    ).hexdigest()
    if git_blob_sha1 != manifest["git_blob_sha1"]:
        raise ValueError(
            "Blocklist source Git blob mismatch: expected "
            f"{manifest['git_blob_sha1']}, found {git_blob_sha1}"
        )


def download_source(manifest_path: Path, output_path: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_url = validate_manifest(manifest)
    with urllib.request.urlopen(source_url, timeout=30) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    verify_source(manifest, source)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(source)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    download_source(args.manifest, args.output)


if __name__ == "__main__":
    main()
