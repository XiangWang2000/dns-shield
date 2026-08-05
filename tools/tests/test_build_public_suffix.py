from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(TOOLS_DIR))

from build_public_suffix import (  # noqa: E402
    FLAG_INCLUDES_PRIVATE,
    FORMAT_VERSION,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    build_public_suffix,
    parse_public_suffix_list,
)


class BuildPublicSuffixTest(unittest.TestCase):
    def test_parses_icann_private_wildcard_and_exception_rules(self) -> None:
        rules = parse_public_suffix_list(
            """
// ===BEGIN ICANN DOMAINS===
COM
co.uk
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""
        )

        self.assertEqual(("co.uk", "com", "github.io"), rules.exact)
        self.assertEqual(("ck",), rules.wildcard_suffixes)
        self.assertEqual(("www.ck",), rules.exceptions)
        self.assertTrue(rules.includes_private)

    def test_requires_both_psl_sections_and_rejects_malformed_rules(self) -> None:
        with self.assertRaisesRegex(ValueError, "Missing PRIVATE section"):
            parse_public_suffix_list(
                """
// ===BEGIN ICANN DOMAINS===
com
// ===END ICANN DOMAINS===
"""
            )

        with self.assertRaisesRegex(ValueError, "Malformed Public Suffix rule"):
            parse_public_suffix_list(
                """
// ===BEGIN ICANN DOMAINS===
bad..rule
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""
            )

        with self.assertRaisesRegex(ValueError, "Malformed Public Suffix rule"):
            parse_public_suffix_list(
                """
// ===BEGIN ICANN DOMAINS===
bad.*.rule
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""
            )

    def test_matches_shared_cross_language_fixture_and_pinned_metadata(self) -> None:
        input_path = FIXTURES_DIR / "public_suffix_list.dat"
        metadata = json.loads(
            (FIXTURES_DIR / "public_suffix.metadata.json").read_text(encoding="utf-8")
        )
        expected_artifact = base64.b64decode(
            (FIXTURES_DIR / "public_suffix.bin.base64")
            .read_text(encoding="ascii")
            .strip()
        )

        self.assertEqual(
            metadata["source_sha256"],
            hashlib.sha256(input_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            metadata["artifact_sha256"],
            hashlib.sha256(expected_artifact).hexdigest(),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "public-suffix.bin"
            stats = build_public_suffix(input_path, output_path)
            artifact = output_path.read_bytes()

        self.assertEqual(expected_artifact, artifact)
        self.assertEqual(metadata["exact_rules"], stats.exact_rules)
        self.assertEqual(metadata["wildcard_rules"], stats.wildcard_rules)
        self.assertEqual(metadata["exception_rules"], stats.exception_rules)
        self.assertEqual(metadata["artifact_size"], stats.output_size)
        self.assertEqual(metadata["source_sha256"], stats.source_sha256)
        self.assertEqual(metadata["artifact_sha256"], stats.artifact_sha256)

        (
            magic,
            version,
            flags,
            exact_count,
            wildcard_count,
            exception_count,
            source_sha256,
        ) = struct.unpack_from(HEADER_FORMAT, artifact)

        self.assertEqual(MAGIC, magic)
        self.assertEqual(FORMAT_VERSION, version)
        self.assertEqual(FLAG_INCLUDES_PRIVATE, flags)
        self.assertEqual(metadata["exact_rules"], exact_count)
        self.assertEqual(metadata["wildcard_rules"], wildcard_count)
        self.assertEqual(metadata["exception_rules"], exception_count)
        self.assertEqual(bytes.fromhex(metadata["source_sha256"]), source_sha256)
        self.assertEqual(60, HEADER_SIZE)


if __name__ == "__main__":
    unittest.main()
