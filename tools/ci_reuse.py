"""Reuse only a successful PR's recorded checkout tree on an identical main push."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/ci.yml"
SCHEMA = "dns-shield-ci-proof-v1"
SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_ZIP = 262144
MAX_PROOF = 16384


def git(expression):
    return subprocess.check_output(["git", "rev-parse", "--verify", expression],
                                   cwd=ROOT, stderr=subprocess.PIPE, timeout=15).decode().strip()


def api(path):
    data = subprocess.check_output(["gh", "api", path], stderr=subprocess.PIPE, timeout=25)
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("API response too large")
    return json.loads(data)


def archive(repo, artifact):
    # Unredirected auth is sent only to api.github.com, not the signed blob URL.
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact['id']}/zip")
    request.add_unredirected_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(MAX_ZIP + 1)
    if len(data) > MAX_ZIP:
        raise ValueError("Artifact too large")
    return data


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate proof key")
        result[key] = value
    return result


def read_proof(data):
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        entries = bundle.infolist()
        if len(entries) != 1 or entries[0].filename != "proof.json" or entries[0].file_size > MAX_PROOF:
            raise ValueError("Invalid proof archive")
        return json.loads(bundle.read(entries[0]), object_pairs_hook=unique_keys)


def record(event, environment):
    if environment.get("GITHUB_EVENT_NAME") != "pull_request":
        raise ValueError("Proofs are only recorded for PR verification")
    pr = event["pull_request"]
    head = pr["head"]["sha"]
    repo = environment["GITHUB_REPOSITORY"]
    if event["repository"]["full_name"] != repo or pr["base"]["repo"]["full_name"] != repo:
        raise ValueError("PR repository does not match this run")
    commit = git("HEAD^{commit}")
    if not SHA.fullmatch(head) or commit != environment["GITHUB_SHA"]:
        raise ValueError("Checkout does not match this run")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True, timeout=15)
    run_id, attempt = int(environment["GITHUB_RUN_ID"]), int(environment["GITHUB_RUN_ATTEMPT"])
    if run_id <= 0 or attempt <= 0:
        raise ValueError("Invalid run identity")
    return dict(schema=SCHEMA, tested_tree=git(commit + "^{tree}"), tested_commit=commit,
                pr_number=pr["number"], base_ref=pr["base"]["ref"], repository=repo,
                pr_head_sha=head, run_id=run_id, run_attempt=attempt,
                workflow_blob_sha=git(commit + ":" + WORKFLOW))


def find_evidence(event, environment, query=api, download=archive, resolve=git):
    if environment.get("GITHUB_EVENT_NAME") != "push" or event.get("ref") != "refs/heads/main":
        return None
    repo = event["repository"]["full_name"]
    if (event["repository"]["default_branch"] != "main" or
            not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or
            repo != environment.get("GITHUB_REPOSITORY")):
        return None
    after = event["after"]
    if not SHA.fullmatch(after) or environment.get("GITHUB_SHA") != after or resolve("HEAD^{commit}") != after:
        return None
    tree, workflow = resolve(after + "^{tree}"), resolve(after + ":" + WORKFLOW)
    prs = query(f"repos/{repo}/commits/{after}/pulls?per_page=100")
    matches = [pr for pr in prs if pr.get("merged_at") and pr.get("state") == "closed"
               and pr.get("merge_commit_sha") == after and pr["base"]["ref"] == "main"
               and pr["base"]["repo"]["full_name"] == repo]
    if len(matches) != 1:
        return None
    pr = matches[0]
    head = pr["head"]["sha"]
    if not SHA.fullmatch(head):
        return None
    runs = query(f"repos/{repo}/actions/workflows/ci.yml/runs?event=pull_request&head_sha={head}&per_page=100")
    candidates = [run for run in runs["workflow_runs"] if run.get("head_sha") == head
                  and run.get("event") == "pull_request" and run.get("path") == WORKFLOW]
    if not candidates:
        return None
    # Inspect the latest run, including failed/pending reruns; never fall back to an older green run.
    run = max(candidates, key=lambda item: int(item["id"]))
    if (run["status"] != "completed" or run["conclusion"] != "success"
            or run["repository"]["full_name"] != repo
            or (run["pull_requests"] and not any(
                item["number"] == pr["number"] and item["head"]["sha"] == head
                for item in run["pull_requests"]))):
        return None
    artifacts = query(f"repos/{repo}/actions/runs/{run['id']}/artifacts?per_page=100")
    matches = [item for item in artifacts["artifacts"] if item["name"] == "verified-tree"]
    if len(matches) != 1 or matches[0]["expired"] or not 0 < matches[0]["size_in_bytes"] <= MAX_ZIP:
        return None
    proof = read_proof(download(repo, matches[0]))
    # GitHub may remove run.pull_requests after merge; the run artifact binds PR identity.
    expected = dict(schema=SCHEMA, tested_tree=tree, workflow_blob_sha=workflow,
                    pr_number=pr["number"], base_ref="main", repository=repo,
                    pr_head_sha=head, run_id=run["id"], run_attempt=run["run_attempt"])
    if set(proof) != set(expected) | {"tested_commit"} or any(proof[key] != value for key, value in expected.items()):
        return None
    tested = proof["tested_commit"]
    if not isinstance(tested, str) or not SHA.fullmatch(tested):
        return None
    # API head_sha is the PR head, not the synthetic merge commit checked out by Actions.
    commit = query(f"repos/{repo}/git/commits/{tested}")
    if (commit["tree"]["sha"] != tree or len(commit["parents"]) != 2
            or commit["parents"][1]["sha"] != head):
        return None
    return f"https://github.com/{repo}/actions/runs/{int(run['id'])}/attempts/{int(run['run_attempt'])}"


def check(event, environment, **dependencies):
    try:
        return find_evidence(event, environment, **dependencies)
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile):
        # Unavailable/expired/ambiguous proof causes normal verification, not a false pass.
        print("PR verification proof unavailable or invalid; running normal verification.")
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("record", "check"))
    parser.add_argument("--event", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    event = json.loads(args.event.read_text(encoding="utf-8"))
    if args.command == "record":
        args.output.write_text(json.dumps(record(event, os.environ)) + "\n", encoding="utf-8")
    else:
        evidence = check(event, os.environ)
        with args.output.open("a", encoding="utf-8") as output:
            output.write(f"reuse={str(bool(evidence)).lower()}\nevidence_url={evidence or ''}\n")
        print(f"Reusing {evidence}" if evidence else "Run normal verification.")


if __name__ == "__main__":
    main()
