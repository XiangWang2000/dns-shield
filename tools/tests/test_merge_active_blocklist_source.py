from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from merge_active_blocklist_source import (  # noqa: E402
    derive_source,
    validate_production_manifest,
    validate_source_manifest,
)


class MergeActiveBlocklistSourceTest(unittest.TestCase):
    def test_derives_canonical_domains_with_the_pinned_rule_order(self) -> None:
        base = (
            "0.0.0.0 base.example\n"
            "127.0.0.1 existing.example # base source\n"
        ).encode("ascii")
        adguard = (
            "||EXISTING.example^\n"
            "||child.base.example^\n"
            "||keep.example^\n"
            "||child.safe.example^\n"
            "||adsystem.test^\n"
            "@@||safe.example^\n"
            "||bad.example/path^\n"
            "! comment\n"
        ).encode("ascii")

        canonical, counts = derive_source(base, adguard)

        self.assertEqual(
            b"base.example\nexisting.example\nkeep.example\n",
            canonical,
        )
        self.assertEqual(
            {
                "base_parsed_domains": 2,
                "base_domains": 2,
                "simple_block_rule_lines": 5,
                "simple_block_domains": 5,
                "simple_exception_rule_lines": 1,
                "simple_exception_domains": 1,
                "ignored_noncomment_rule_lines": 1,
                "excluded_by_base": 2,
                "excluded_by_builtin_matcher": 1,
                "excluded_by_simple_exceptions": 1,
                "extra_domains": 1,
                "merged_domains": 3,
                "merged_hashes": 3,
            },
            counts,
        )

    def test_schema2_manifests_pin_both_sources_and_artifact_offline(self) -> None:
        source = json.loads(
            (TOOLS_DIR / "active_blocklist_source.json").read_text(encoding="utf-8")
        )
        production = json.loads(
            (TOOLS_DIR / "active_blocklist_production.json").read_text(encoding="utf-8")
        )

        validate_source_manifest(source)
        validate_production_manifest(production, source)
        self.assertEqual(2, len(source["sources"]))
        self.assertTrue(source["sources"][0]["source_url"].endswith(
            "/7a4588e87bcf7e86e0b8169d391b8422bd3c5d36/Lite/domains.wildcards"
        ))
        self.assertTrue(source["sources"][1]["source_url"].endswith(
            "/bef5669f914c1d2419e732feeefde79fcdca0eab/Filters/filter.txt"
        ))

    def test_schema2_rejects_a_raw_url_not_derived_from_its_revision(self) -> None:
        source = json.loads(
            (TOOLS_DIR / "active_blocklist_source.json").read_text(encoding="utf-8")
        )
        source["sources"][1]["source_url"] = (
            "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/"
            "master/Filters/filter.txt"
        )

        with self.assertRaisesRegex(ValueError, "immutable revision and path"):
            validate_source_manifest(source)

    def test_schema2_cross_checks_production_source_metadata(self) -> None:
        source = json.loads(
            (TOOLS_DIR / "active_blocklist_source.json").read_text(encoding="utf-8")
        )
        production = json.loads(
            (TOOLS_DIR / "active_blocklist_production.json").read_text(encoding="utf-8")
        )
        production["source_revision"] = "0" * 40

        with self.assertRaisesRegex(ValueError, "Production/source manifest mismatch"):
            validate_production_manifest(production, source)


if __name__ == "__main__":
    unittest.main()
