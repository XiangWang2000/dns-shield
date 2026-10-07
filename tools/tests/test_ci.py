import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("ci", Path(__file__).resolve().parents[1] / "ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class CiRoutingTest(unittest.TestCase):
    def test_allowlist_does_not_skip_packaged_data_or_build_logic(self):
        for path in ("README.md", "docs/deep/test.md", "AGENTS.md"):
            self.assertTrue(ci.is_documentation(path), path)
        for path in ("app/src/main/assets/help.md", ".github/workflows/ci.yml",
                     "verify.ps1", "tools/ci.py", "docs/sample.bin", "README.md.kt"):
            self.assertFalse(ci.is_documentation(path), path)

    def test_git_history_merge_base_rename_and_unknown_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE).decode().strip()
            git("init", "-q")
            git("config", "user.name", "CI test")
            git("config", "user.email", "ci@example.invalid")
            (root / "README.md").write_text("base\n")
            git("add", ".")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            (root / "README.md").write_text("docs\n")
            git("commit", "-qam", "docs")
            head = git("rev-parse", "HEAD")
            event = {"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
            self.assertTrue(ci.classify(event, root))
            self.assertTrue(ci.classify({"before": base, "after": head}, root))
            self.assertFalse(ci.classify({"before": head, "after": head}, root))
            self.assertFalse(ci.classify({"before": "0" * 40, "after": head}, root))
            self.assertFalse(ci.classify({"before": "f" * 40, "after": head}, root))
            self.assertFalse(ci.classify({}))
            (root / "source.kt").write_text("source\n")
            git("add", ".")
            git("commit", "-qm", "source")
            source = git("rev-parse", "HEAD")
            (root / "docs").mkdir()
            git("mv", "source.kt", "docs/source.md")
            git("commit", "-qm", "rename")
            self.assertFalse(ci.classify({"before": source, "after": git("rev-parse", "HEAD")}, root))
            # Net documentation-only changes are safe even if an intermediate commit had source.
            event["pull_request"]["head"]["sha"] = git("rev-parse", "HEAD")
            self.assertTrue(ci.classify(event, root))
            (root / "retained.kt").write_text("source\n")
            git("add", ".")
            git("commit", "-qm", "retained source")
            (root / "README.md").write_text("last commit is docs\n")
            git("commit", "-qam", "last docs")
            # The PR includes source even when its most recent commit is documentation.
            event["pull_request"]["head"]["sha"] = git("rev-parse", "HEAD")
            self.assertFalse(ci.classify(event, root))


    def test_docs_validation_rejects_missing_and_empty_links(self):
        errors, count, _ = ci.documentation_errors(
            "[ok](../README.md)\n[bad](missing.md)\n[empty]()\n",
            Path("docs/example.md"), {"README.md"})
        self.assertEqual(count, 2)
        self.assertEqual(len(errors), 2)

    def test_fences_external_urls_and_local_evidence(self):
        fence = chr(96) * 3
        text = f"{fence}text\n[example](missing)\n{fence}\n[web](https://example.invalid)\n"
        text += "[raw](../captures/local.txt)\n[anchor](#section)\n"
        errors, count, evidence = ci.documentation_errors(text, Path("docs/example.md"), set())
        self.assertEqual((errors, count, evidence), ([], 0, 1))
        errors, _, _ = ci.documentation_errors(fence + "\nunclosed", Path("README.md"), set())
        self.assertTrue(errors)

    def test_html_image_and_deleted_target(self):
        errors, count, _ = ci.documentation_errors(
            '<img src="icon.png">\n[old](docs/deleted.md)\n',
            Path("README.md"), {"icon.png"})
        self.assertEqual(count, 2)
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
