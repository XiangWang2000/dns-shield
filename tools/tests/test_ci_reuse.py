import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import zipfile

SPEC = importlib.util.spec_from_file_location("ci_reuse", Path(__file__).resolve().parents[1] / "ci_reuse.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def zipped(proof):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("proof.json", json.dumps(proof))
    return stream.getvalue()


class ReuseTest(unittest.TestCase):
    def setUp(self):
        self.repo = "owner/repo"
        self.after, self.head, self.tree, self.blob, self.tested = [c * 40 for c in "abcde"]
        self.environment = dict(GITHUB_EVENT_NAME="push", GITHUB_REPOSITORY=self.repo, GITHUB_SHA=self.after)
        self.event = dict(ref="refs/heads/main", after=self.after,
                          repository=dict(full_name=self.repo, default_branch="main"))
        self.pr = dict(number=7, state="closed", merged_at="2026-10-18T00:00:00Z",
                       merge_commit_sha=self.after, head=dict(sha=self.head),
                       base=dict(ref="main", repo=dict(full_name=self.repo)))
        self.run = dict(id=100, run_attempt=1, path=ci.WORKFLOW, head_sha=self.head,
                        event="pull_request", status="completed", conclusion="success",
                        repository=dict(full_name=self.repo), pull_requests=[dict(number=7, head=dict(sha=self.head))])
        self.artifact = dict(id=200, name="verified-tree", expired=False, size_in_bytes=1024)
        self.proof = dict(schema=ci.SCHEMA, tested_tree=self.tree, tested_commit=self.tested,
                          workflow_blob_sha=self.blob, pr_head_sha=self.head, run_id=100, run_attempt=1,
                          pr_number=7, base_ref="main", repository=self.repo)
        self.runs = [self.run]
        self.artifacts = [self.artifact]
        self.commit = dict(tree=dict(sha=self.tree), parents=[dict(sha="f" * 40), dict(sha=self.head)])

    def query(self, path):
        if "/pulls?" in path:
            return [self.pr]
        if "/workflows/ci.yml/runs?" in path:
            return dict(workflow_runs=self.runs)
        if "/artifacts?" in path:
            return dict(artifacts=self.artifacts)
        if "/git/commits/" in path:
            return self.commit
        raise AssertionError(path)

    def resolve(self, expression):
        if expression == "HEAD^{commit}":
            return self.after
        if expression.endswith("^{tree}"):
            return self.tree
        if expression.endswith(":" + ci.WORKFLOW):
            return self.blob
        raise AssertionError(expression)

    def check(self, **overrides):
        dependencies = dict(query=self.query, download=lambda *_: zipped(self.proof), resolve=self.resolve)
        dependencies.update(overrides)
        return ci.check(self.event, self.environment, **dependencies)

    def test_identical_tree_reuses_synthetic_pr_merge_not_head_commit(self):
        self.assertNotEqual(self.head, self.tested)
        self.assertNotEqual(self.after, self.tested)  # Also supports squash merge with the same tree.
        self.assertEqual(self.check(), "https://github.com/owner/repo/actions/runs/100/attempts/1")

    def test_empty_post_merge_run_association_requires_proof_pr_identity(self):
        self.run["pull_requests"] = []
        self.assertIsNotNone(self.check())
        for key, bad in (("pr_number", 8), ("base_ref", "other"), ("repository", "other/repo")):
            old = self.proof[key]
            self.proof[key] = bad
            self.assertIsNone(self.check())
            self.proof[key] = old

    def test_proof_identity_and_tree_mismatches_do_not_reuse(self):
        for key in self.proof:
            with self.subTest(key=key):
                original = self.proof[key]
                self.proof[key] = "invalid"
                self.assertIsNone(self.check())
                self.proof[key] = original

    def test_latest_pending_failed_or_new_attempt_blocks_previous_green(self):
        original = copy.deepcopy(self.run)
        for state, conclusion in (("in_progress", None), ("completed", "failure"), ("completed", "cancelled")):
            newer = dict(original, id=101, status=state, conclusion=conclusion)
            self.runs = [newer, original]
            self.assertIsNone(self.check())
        self.runs = [dict(original, run_attempt=2)]
        self.assertIsNone(self.check())

    def test_wrong_workflow_event_repo_or_pr_does_not_reuse(self):
        for key, bad in (("path", "other.yml"), ("event", "push"), ("head_sha", "f" * 40),
                         ("repository", {"full_name": "other/repo"}), ("pull_requests", [dict(number=8, head=dict(sha=self.head))])):
            with self.subTest(key=key):
                old = self.run[key]
                self.run[key] = bad
                self.assertIsNone(self.check())
                self.run[key] = old
        self.pr["merge_commit_sha"] = "f" * 40
        self.assertIsNone(self.check())

    def test_artifact_missing_duplicate_expired_oversized_or_invalid(self):
        for artifacts in ([], [self.artifact, self.artifact], [dict(self.artifact, expired=True)],
                          [dict(self.artifact, size_in_bytes=ci.MAX_ZIP + 1)]):
            self.artifacts = artifacts
            self.assertIsNone(self.check())
        self.artifacts = [self.artifact]
        self.assertIsNone(self.check(download=lambda *_: b"not a zip"))
        self.proof["unknown"] = True
        self.assertIsNone(self.check())

    def test_server_commit_must_match_tree_and_pr_head(self):
        self.commit["tree"]["sha"] = "f" * 40
        self.assertIsNone(self.check())
        self.commit["tree"]["sha"] = self.tree
        self.commit["parents"] = [dict(sha=self.head)]
        self.assertIsNone(self.check())

    def test_unknown_api_error_runs_normal_checks(self):
        def unavailable(_):
            raise subprocess.CalledProcessError(1, "gh")
        self.assertIsNone(self.check(query=unavailable))
        self.assertIsNone(ci.check({}, self.environment))

    def test_only_exact_main_push_checkout_is_eligible(self):
        for key, bad in (("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_SHA", "f" * 40),
                         ("GITHUB_REPOSITORY", "other/repo")):
            old = self.environment[key]
            self.environment[key] = bad
            self.assertIsNone(self.check())
            self.environment[key] = old
        self.event["ref"] = "refs/heads/feature"
        self.assertIsNone(self.check())

    def test_record_rejects_non_pr_wrong_checkout_or_dirty_source(self):
        environment = dict(self.environment, GITHUB_EVENT_NAME="pull_request", GITHUB_SHA=self.tested,
                           GITHUB_RUN_ID="100", GITHUB_RUN_ATTEMPT="1")
        event = dict(pull_request=self.pr, repository=dict(full_name=self.repo))
        def resolve(expression):
            return self.tested if expression == "HEAD^{commit}" else self.resolve(expression)
        with patch.object(ci, "git", side_effect=resolve), patch.object(ci.subprocess, "run"):
            self.assertEqual(ci.record(event, environment), self.proof)
            environment["GITHUB_SHA"] = self.after
            with self.assertRaises(ValueError):
                ci.record(event, environment)
        with self.assertRaises(ValueError):
            ci.record(event, self.environment)
        environment["GITHUB_SHA"] = self.tested
        with patch.object(ci, "git", side_effect=resolve), patch.object(ci.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "git")):
            with self.assertRaises(subprocess.CalledProcessError):
                ci.record(event, environment)


if __name__ == "__main__":
    unittest.main()
