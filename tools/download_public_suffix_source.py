#!/usr/bin/env python3
"""Download one pinned Public Suffix List source revision over HTTPS."""

from __future__ import annotations

import argparse
import hashlib
import urllib.request
from pathlib import Path

from prepare_public_suffix_source import MAX_SOURCE_BYTES, SourceManifest, load_manifest


USER_AGENT = "dns-shield-public-suffix-rebuilder/1"


def pinned_source_url(manifest: SourceManifest) -> str:
    return (
        "https://raw.githubusercontent.com/"
        f"{manifest.source_name}/{manifest.source_revision}/public_suffix_list.dat"
    )


def download_pinned_source(
    manifest: SourceManifest,
    timeout_seconds: int = 30,
) -> bytes:
    request = urllib.request.Request(
        pinned_source_url(manifest),
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError(f"Public Suffix source exceeds {MAX_SOURCE_BYTES} bytes")
    return source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    source = download_pinned_source(manifest, args.timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(source)
    print(f"Downloaded {len(source)} bytes from {pinned_source_url(manifest)}")
    print(f"Source SHA-256: {hashlib.sha256(source).hexdigest()}")


if __name__ == "__main__":
    main()
