"""CI routing and local documentation checks; no network dependencies."""
import argparse
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {"README.md", "CHANGELOG.md", "PRIVACY.md", "THIRD_PARTY_NOTICES.md", "AGENTS.md"}
SHA = re.compile(r"[0-9a-f]{40,64}\Z")


def is_documentation(path):
    return path in ROOT_DOCS or (path.startswith("docs/") and path.endswith(".md"))


def git(*args, root=ROOT):
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE)


def changed_paths(event, root=ROOT):
    """Return all changed paths, including both sides of renames; None is unknown."""
    try:
        if "pull_request" in event:
            pr = event["pull_request"]
            base, head = pr["base"]["sha"], pr["head"]["sha"]
            if not SHA.fullmatch(base) or not SHA.fullmatch(head):
                return None
            base = git("merge-base", base, head, root=root).decode().strip()
        else:
            base, head = event["before"], event["after"]
            if not SHA.fullmatch(base) or not SHA.fullmatch(head) or set(base) == {"0"}:
                return None
        paths = git("diff", "--no-renames", "--name-only", "-z", base, head, "--", root=root)
        changed = [p.decode("utf-8") for p in paths.split(b"\0") if p]
        return changed or None
    except (KeyError, TypeError, subprocess.CalledProcessError, UnicodeError):
        return None


VARIANT_DIRS = {
    "androidTestD03test": "d03", "d03test": "d03",
    "androidTestD04DeviceTest": "d04", "d04DeviceTest": "d04",
    "androidTestD08test": "d08", "d08test": "d08",
    "androidTestD14DeviceTest": "d14", "d14DeviceTest": "d14",
    "androidTestD15test": "d15", "d15test": "d15",
}
CORE_PREFIXES = ("app/src/main/java/", "app/src/main/kotlin/", "app/src/main/res/",
                 "app/src/main/assets/", "app/src/test/")


def select_scope(paths):
    """Only known ordinary source paths receive the smaller gate."""
    if not paths:
        return "Full", []
    if all(is_documentation(p) for p in paths):
        return "Docs", []
    variants = set()
    for path in paths:
        if is_documentation(path) or path.startswith(CORE_PREFIXES):
            continue
        parts = path.split("/")
        if len(parts) > 3 and parts[:2] == ["app", "src"] and parts[2] in VARIANT_DIRS:
            variants.add(VARIANT_DIRS[parts[2]])
        else:
            # Shared androidTest, build/CI logic, native code and unknown paths
            # retain the full gate. D07/D12 remain outside the historical gate.
            return "Full", []
    return ("Selected", sorted(variants)) if variants else ("Core", [])


def classify(event, root=ROOT):
    return select_scope(changed_paths(event, root))[0] == "Docs"


def documentation_errors(text, document, tracked):
    """Check file targets outside code fences. Remote URLs/anchors are not fetched."""
    errors = []
    fence = None
    local_links = 0
    local_evidence = 0
    for number, line in enumerate(text.splitlines(), 1):
        fence_match = re.match(r"^\s*(" + chr(96) + r"{3,}|~{3,})", line)
        if fence_match:
            token = fence_match[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        targets = re.findall(r"!?\[[^\]\n]*\]\(([^)\n]*)\)", line)
        targets += re.findall(r'<(?:img|a)\b[^>]*(?:src|href)=["\']([^"\']*)["\']', line)
        for raw in targets:
            match = re.match(r"\s*(?:<([^>]+)>|(\S+))", raw)
            if not match:
                errors.append(f"{document}:{number}: empty link target")
                continue
            target = match[1] or match[2]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            # GitHub repository-root links start with /; other links are document-relative.
            location = (ROOT / unquote(parsed.path).lstrip("/") if parsed.path.startswith("/")
                        else ROOT / document.parent / unquote(parsed.path)).resolve()
            try:
                relative = location.relative_to(ROOT.resolve()).as_posix()
            except ValueError:
                errors.append(f"{document}:{number}: target outside repository: {target}")
                continue
            # Historical reports explicitly link local, ignored raw evidence.
            if relative.startswith("captures/"):
                local_evidence += 1
                continue
            local_links += 1
            if relative != "." and relative not in tracked and not any(
                    p.startswith(relative.rstrip("/") + "/") for p in tracked):
                errors.append(f"{document}:{number}: missing tracked target: {target}")
    if fence is not None:
        errors.append(f"{document}: unclosed code fence")
    if any(ord(c) < 32 and c not in "\r\n\t" for c in text):
        errors.append(f"{document}: unexpected control character")
    return errors, local_links, local_evidence


def verify_docs():
    tracked = {p.decode("utf-8") for p in git("ls-files", "-z").split(b"\0") if p}
    errors, count, evidence = [], 0, 0
    docs = sorted(p for p in tracked if is_documentation(p))
    for name in docs:
        found, links, skipped = documentation_errors(
            (ROOT / name).read_text(encoding="utf-8"), Path(name), tracked)
        errors.extend(found)
        count += links
        evidence += skipped
    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Documentation passed: {len(docs)} files, {count} local targets; "
          f"{evidence} historical local-evidence links excluded. Remote URLs/anchors not checked.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    classify_parser = commands.add_parser("classify")
    classify_parser.add_argument("--event", type=Path, required=True)
    classify_parser.add_argument("--output", type=Path, required=True)
    commands.add_parser("verify-docs")
    args = parser.parse_args()
    if args.command == "classify":
        event = json.loads(args.event.read_text(encoding="utf-8"))
        scope, variants = select_scope(changed_paths(event))
        docs_only = scope == "Docs"
        with args.output.open("a", encoding="utf-8") as output:
            output.write(f"docs_only={str(docs_only).lower()}\nscope={scope}\nvariants={','.join(variants)}\n")
        print(f"Verification scope: {scope}; variants: {variants}")
    else:
        verify_docs()


if __name__ == "__main__":
    main()
