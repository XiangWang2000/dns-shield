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
from verify_public_suffix_production import (  # noqa: E402
    verify_production_outputs,
    write_report,
)


class VerifyPublicSuffixProductionTest(unittest.TestCase):
    def source(self) -> bytes:
        return b"""// ===BEGIN ICANN DOMAINS===
com
co.uk
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""

    def files(self, directory: Path) -> tuple[Path, Path, Path, Path]:
        normalized = self.source()
        artifact, rules = build_artifact(normalized)
        source_revision = "1" * 40
        git_blob = "2" * 40
        idna_version = "3.18"

        production_manifest = directory / "production.json"
        source_manifest = directory / "source.json"
        normalized_path = directory / "normalized.dat"
        artifact_path = directory / "artifact.bin"

        production_manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "source_revision": source_revision,
                    "git_blob_sha1": git_blob,
                    "idna_version": idna_version,
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
        source_manifest.write_text(
            json.dumps(
                {
                    "source_revision": source_revision,
                    "git_blob_sha1": git_blob,
                    "idna_version": idna_version,
                }
            ),
            encoding="utf-8",
        )
        normalized_path.write_bytes(normalized)
        artifact_path.write_bytes(artifact)
        return production_manifest, source_manifest, normalized_path, artifact_path

    def test_verifies_deterministic_outputs_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = self.files(directory)
            report = verify_production_outputs(*paths)
            report_path = directory / "reports" / "verification.json"
            write_report(report_path, report)
            written = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(3, report.exact_rules)
        self.assertEqual(1, report.wildcard_rules)
        self.assertEqual(1, report.exception_rules)
        self.assertEqual(report.artifact_sha256, written["artifact_sha256"])

    def test_rejects_artifact_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = list(self.files(directory))
            artifact_path = paths[3]
            artifact = bytearray(artifact_path.read_bytes())
            artifact[-1] ^= 1
            artifact_path.write_bytes(artifact)

            with self.assertRaisesRegex(ValueError, "Artifact SHA-256"):
                verify_production_outputs(*paths)

    def test_rejects_manifest_and_source_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = list(self.files(directory))
            source_manifest_path = paths[1]
            source_manifest = json.loads(
                source_manifest_path.read_text(encoding="utf-8")
            )
            source_manifest["source_revision"] = "3" * 40
            source_manifest_path.write_text(
                json.dumps(source_manifest),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "source revision"):
                verify_production_outputs(*paths)

    def test_rejects_normalized_source_drift_before_regeneration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = list(self.files(directory))
            normalized_path = paths[2]
            normalized_path.write_bytes(normalized_path.read_bytes() + b"\n")

            with self.assertRaisesRegex(ValueError, "Normalized source size"):
                verify_production_outputs(*paths)


if __name__ == "__main__":
    unittest.main()
