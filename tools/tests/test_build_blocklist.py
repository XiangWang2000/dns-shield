from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from build_blocklist import (  # noqa: E402
    FORMAT_VERSION,
    HASH_ALGORITHM_FNV1A_64,
    HEADER_FORMAT,
    HEADER_SIZE,
    MAGIC,
    build_blocklist,
    fnv1a64,
    parse_domains,
)


class BuildBlocklistTest(unittest.TestCase):
    def test_parses_domain_and_hosts_formats_with_current_normalization(self) -> None:
        domains = parse_domains(
            [
                "doubleclick.net\n",
                "0.0.0.0 pagead2.googlesyndication.com # comment\n",
                "127.0.0.1 telemetry.example\r\n",
                " DOUBLECLICK.NET \n",
                "invalid line with spaces\n",
                "unknown\n",
            ]
        )

        self.assertEqual(
            [
                "doubleclick.net",
                "pagead2.googlesyndication.com",
                "telemetry.example",
                "doubleclick.net",
            ],
            domains,
        )

    def test_uses_stable_golden_fnv1a_hashes(self) -> None:
        self.assertEqual(0xDC8C04CD127775CD, fnv1a64(b"doubleclick.net"))
        self.assertEqual(0x6B1BF3DBC7755D59, fnv1a64(b"github.com"))

    def test_writes_a_deterministic_sorted_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            first_input = directory / "first.txt"
            second_input = directory / "second.txt"
            first_output = directory / "first.bin"
            second_output = directory / "second.bin"
            first_input.write_text("github.com\n0.0.0.0 doubleclick.net\n", encoding="utf-8")
            second_input.write_text("DOUBLECLICK.NET\ngithub.com\ndoubleclick.net\n", encoding="utf-8")

            first_stats = build_blocklist(first_input, first_output)
            second_stats = build_blocklist(second_input, second_output)
            artifact = first_output.read_bytes()

            self.assertEqual(2, first_stats.unique_domains)
            self.assertEqual(first_stats.sha256, second_stats.sha256)
            self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
            self.assertEqual(hashlib.sha256(artifact).hexdigest(), first_stats.sha256)

            magic, version, algorithm, entry_count = struct.unpack_from(HEADER_FORMAT, artifact)
            hashes = [
                struct.unpack_from("<Q", artifact, HEADER_SIZE + index * 8)[0]
                for index in range(entry_count)
            ]
            self.assertEqual(MAGIC, magic)
            self.assertEqual(FORMAT_VERSION, version)
            self.assertEqual(HASH_ALGORITHM_FNV1A_64, algorithm)
            self.assertEqual(2, entry_count)
            self.assertEqual(sorted(hashes), hashes)
            self.assertEqual(HEADER_SIZE + entry_count * 8, len(artifact))


if __name__ == "__main__":
    unittest.main()
