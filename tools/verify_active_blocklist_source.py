#!/usr/bin/env python3
"""Verify a local blocklist source against the pinned source contract."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from download_active_blocklist_source import verify_source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source = args.input.read_bytes()
    verify_source(manifest, source)
    print(
        json.dumps(
            {
                "source_revision": manifest["source_revision"],
                "source_sha256": hashlib.sha256(source).hexdigest(),
                "source_size": len(source),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
