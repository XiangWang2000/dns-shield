from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from prepare_public_suffix_source import (  # noqa: E402
    SourceManifest,
    git_blob_sha1,
    load_manifest,
    load_pinned_idna_encoder,
    normalize_source,
    prepare_source,
    verify_source,
)


BASE_MANIFEST = SourceManifest(
    schema_version=1,
    source_name="publicsuffix/list",
    source_url="https://publicsuffix.org/list/public_suffix_list.dat",
    source_revision="e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20",
    git_blob_sha1="0" * 40,
    license="MPL-2.0",
    license_url="https://mozilla.org/MPL/2.0/",
    idna_package="idna",
    idna_version="3.18",
    idna_wheel_sha256=(
        "7f952cbe720b688055e3f87de14f5c3e"
        "5fdaa8bc3928985c4077ca689de849a2"
    ),
)


class PreparePublicSuffixSourceTest(unittest.TestCase):
    def source(self) -> bytes:
        return """// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0.
// An upstream comment that is intentionally removed.
// ===BEGIN ICANN DOMAINS===
COM
公司.cn
*.食狮.公司.cn
!www.食狮.公司.cn
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
GITHUB.IO
// ===END PRIVATE DOMAINS===
""".encode("utf-8")

    def encoder(self, value: str) -> str:
        return {
            "COM": "com",
            "公司.cn": "xn--55qx5d.cn",
            "食狮.公司.cn": "xn--85x722f.xn--55qx5d.cn",
            "www.食狮.公司.cn": (
                "www.xn--85x722f.xn--55qx5d.cn"
            ),
            "GITHUB.IO": "github.io",
        }[value]

    def test_manifest_pins_expected_upstream_and_idna_versions(self) -> None:
        manifest_path = TOOLS_DIR / "public_suffix_source.json"

        manifest = load_manifest(manifest_path)

        self.assertEqual(
            "e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20",
            manifest.source_revision,
        )
        self.assertEqual(
            "52b981034da22eb87ee6cc719cba4d5561a7d351",
            manifest.git_blob_sha1,
        )
        self.assertEqual("idna", manifest.idna_package)
        self.assertEqual("3.18", manifest.idna_version)
        self.assertEqual("MPL-2.0", manifest.license)

    def test_uses_standard_git_blob_identity(self) -> None:
        self.assertEqual(
            "ce013625030ba8dba906f756967f9e9ca394464a",
            git_blob_sha1(b"hello\n"),
        )

    def test_verifies_blob_license_and_section_markers(self) -> None:
        source = self.source()
        manifest = replace(
            BASE_MANIFEST,
            git_blob_sha1=git_blob_sha1(source),
        )

        verify_source(source, manifest)

        with self.assertRaisesRegex(ValueError, "blob mismatch"):
            verify_source(source + b"changed", manifest)
        with self.assertRaisesRegex(ValueError, "MPL-2.0"):
            verify_source(
                source.replace(b"Mozilla Public", b"Other License"),
                replace(
                    manifest,
                    git_blob_sha1=git_blob_sha1(
                        source.replace(b"Mozilla Public", b"Other License")
                    ),
                ),
            )

    def test_normalizes_unicode_rules_deterministically(self) -> None:
        normalized, stats = normalize_source(
            self.source(),
            BASE_MANIFEST,
            self.encoder,
        )
        repeated, repeated_stats = normalize_source(
            self.source(),
            BASE_MANIFEST,
            self.encoder,
        )
        text = normalized.decode("ascii")

        self.assertEqual(normalized, repeated)
        self.assertEqual(stats, repeated_stats)
        self.assertIn("com\n", text)
        self.assertIn("xn--55qx5d.cn\n", text)
        self.assertIn("*.xn--85x722f.xn--55qx5d.cn\n", text)
        self.assertIn("!www.xn--85x722f.xn--55qx5d.cn\n", text)
        self.assertIn("github.io\n", text)
        self.assertNotIn("upstream comment", text)
        self.assertEqual(3, stats.exact_rules)
        self.assertEqual(1, stats.wildcard_rules)
        self.assertEqual(1, stats.exception_rules)
        self.assertEqual(
            hashlib.sha256(normalized).hexdigest(),
            stats.normalized_sha256,
        )

    def test_requires_icann_then_private_section_order(self) -> None:
        reversed_sections = """// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
// ===BEGIN ICANN DOMAINS===
com
// ===END ICANN DOMAINS===
""".encode("ascii")

        with self.assertRaisesRegex(ValueError, "section start"):
            normalize_source(
                reversed_sections,
                BASE_MANIFEST,
                str.lower,
            )

    def test_rejects_malformed_rules_and_encoder_output(self) -> None:
        malformed = self.source().replace(b"COM\n", b"bad.*.rule\n")
        with self.assertRaisesRegex(ValueError, "Malformed"):
            normalize_source(malformed, BASE_MANIFEST, str.lower)

        with self.assertRaisesRegex(ValueError, "invalid rule"):
            normalize_source(
                self.source(),
                BASE_MANIFEST,
                lambda _: "公司.cn",
            )

    def test_requires_exact_pinned_idna_version(self) -> None:
        with patch("importlib.metadata.version", return_value="3.17"):
            with self.assertRaisesRegex(
                RuntimeError,
                "Expected idna==3.18",
            ):
                load_pinned_idna_encoder(BASE_MANIFEST)

    def test_offline_preparation_writes_auditable_metadata(self) -> None:
        source = self.source()
        manifest = replace(
            BASE_MANIFEST,
            git_blob_sha1=git_blob_sha1(source),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest_path = directory / "manifest.json"
            input_path = directory / "source.dat"
            output_path = directory / "normalized.dat"
            metadata_path = directory / "metadata.json"
            manifest_path.write_text(
                json.dumps(manifest.__dict__),
                encoding="utf-8",
            )
            input_path.write_bytes(source)

            with patch(
                "prepare_public_suffix_source.load_pinned_idna_encoder",
                return_value=self.encoder,
            ):
                stats = prepare_source(
                    manifest_path,
                    output_path,
                    metadata_path,
                    input_path,
                )

            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

        self.assertEqual(stats.normalized_sha256, metadata["preparation"]["normalized_sha256"])
        self.assertEqual(manifest.source_revision, metadata["manifest"]["source_revision"])
        self.assertEqual(manifest.git_blob_sha1, metadata["manifest"]["git_blob_sha1"])


if __name__ == "__main__":
    unittest.main()
