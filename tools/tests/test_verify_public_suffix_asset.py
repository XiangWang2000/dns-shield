from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from build_public_suffix import build_artifact  # noqa: E402
from verify_public_suffix_asset import verify_asset  # noqa: E402


class VerifyPublicSuffixAssetTest(unittest.TestCase):
    def files(self, directory: Path) -> tuple[Path, Path]:
        normalized = b"""// ===BEGIN ICANN DOMAINS===
com
co.uk
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""
        artifact, rules = build_artifact(normalized)
        manifest_path = directory / "production.json"
        artifact_path = directory / "public_suffix.bin"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "source_revision": "1" * 40,
                    "git_blob_sha1": "2" * 40,
                    "idna_version": "3.18",
                    "normalized_sha256": hashlib.sha256(normalized).hexdigest(),
                    "normalized_size": len(normalized),
                    "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
                    "artifact_size": len(artifact),
                    "exact_rules": len(rules.exact),
                    "wildcard_rules": len(rules.wildcard_suffixes),
                    "exception_rules": len(rules.exceptions),
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

        self.assertEqual(3, report.exact_rules)
        self.assertEqual(1, report.wildcard_rules)
        self.assertEqual(1, report.exception_rules)

    def test_rejects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path, artifact_path = self.files(Path(temporary_directory))
            artifact = bytearray(artifact_path.read_bytes())
            artifact[-1] ^= 1
            artifact_path.write_bytes(artifact)

            with self.assertRaisesRegex(ValueError, "Artifact SHA-256"):
                verify_asset(manifest_path, artifact_path)

    def test_rejects_manifest_rule_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            manifest_path, artifact_path = self.files(Path(temporary_directory))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["exact_rules"] += 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "header rule counts"):
                verify_asset(manifest_path, artifact_path)


if __name__ == "__main__":
    unittest.main()
