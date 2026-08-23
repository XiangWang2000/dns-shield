from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from build_blocklist import build_artifact  # noqa: E402
from verify_active_blocklist_asset import verify_asset  # noqa: E402


class VerifyActiveBlocklistAssetTest(unittest.TestCase):
    def files(self, directory: Path) -> tuple[Path, Path]:
        artifact, unique_domains, _ = build_artifact(
            ["ads.example", "tracker.example"]
        )
        manifest_path = directory / "production.json"
        artifact_path = directory / "active.bin"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "source_revision": "1" * 40,
                    "source_sha256": "2" * 64,
                    "source_size": 42,
                    "parsed_domains": unique_domains,
                    "unique_domains": unique_domains,
                    "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                    "artifact_size": len(artifact),
                    "entry_count": unique_domains,
                }
            ),
            encoding="utf-8",
        )
        artifact_path.write_bytes(artifact)
        return manifest_path, artifact_path

    def test_accepts_artifact_matching_production_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path, artifact_path = self.files(Path(temporary_directory))
            report = verify_asset(manifest_path, artifact_path)

        self.assertEqual(2, report.entry_count)
        self.assertEqual(40, report.artifact_size)

    def test_rejects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path, artifact_path = self.files(Path(temporary_directory))
            artifact = bytearray(artifact_path.read_bytes())
            artifact[-1] ^= 1
            artifact_path.write_bytes(artifact)

            with self.assertRaisesRegex(ValueError, "Artifact SHA-256"):
                verify_asset(manifest_path, artifact_path)

    def test_rejects_entry_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path, artifact_path = self.files(Path(temporary_directory))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["entry_count"] += 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "entry count mismatch"):
                verify_asset(manifest_path, artifact_path)


if __name__ == "__main__":
    unittest.main()
