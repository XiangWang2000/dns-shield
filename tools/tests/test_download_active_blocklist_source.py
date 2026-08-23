from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from download_active_blocklist_source import download_source  # noqa: E402


class FakeResponse:
    def __init__(self, contents: bytes) -> None:
        self.contents = contents

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int) -> bytes:
        return self.contents[:size]


class DownloadActiveBlocklistSourceTest(unittest.TestCase):
    def manifest(self, directory: Path, source: bytes) -> Path:
        revision = "1" * 40
        path = directory / "source.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "source_name": "badmojr/1Hosts Lite",
                    "source_revision": revision,
                    "source_path": "Lite/domains.wildcards",
                    "source_url": (
                        "https://raw.githubusercontent.com/badmojr/1Hosts/"
                        f"{revision}/Lite/domains.wildcards"
                    ),
                    "source_size": len(source),
                    "source_sha256": hashlib.sha256(source).hexdigest(),
                    "git_blob_sha1": hashlib.sha1(
                        f"blob {len(source)}\0".encode("ascii") + source
                    ).hexdigest(),
                    "license": "MPL-2.0",
                    "license_url": "https://www.mozilla.org/MPL/2.0/",
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_downloads_source_matching_pinned_contract(self) -> None:
        source = b"ads.example\ntracker.example\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest = self.manifest(directory, source)
            output = directory / "source.txt"
            with patch(
                "download_active_blocklist_source.urllib.request.urlopen",
                return_value=FakeResponse(source),
            ):
                download_source(manifest, output)

            self.assertEqual(source, output.read_bytes())

    def test_rejects_source_hash_mismatch(self) -> None:
        source = b"ads.example\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest = self.manifest(directory, source)
            output = directory / "source.txt"
            with patch(
                "download_active_blocklist_source.urllib.request.urlopen",
                return_value=FakeResponse(b"bad.example\n"),
            ):
                with self.assertRaisesRegex(ValueError, "size mismatch|SHA-256 mismatch"):
                    download_source(manifest, output)

    def test_rejects_unpinned_url_before_network_request(self) -> None:
        source = b"ads.example\n"
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest = self.manifest(directory, source)
            contents = json.loads(manifest.read_text(encoding="utf-8"))
            contents["source_url"] = "https://example.com/list.txt"
            manifest.write_text(json.dumps(contents), encoding="utf-8")

            with patch(
                "download_active_blocklist_source.urllib.request.urlopen"
            ) as urlopen:
                with self.assertRaisesRegex(ValueError, "URL does not match"):
                    download_source(manifest, directory / "source.txt")
                urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
