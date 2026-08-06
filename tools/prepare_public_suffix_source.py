#!/usr/bin/env python3
"""Acquire and normalize one pinned Public Suffix List source."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

BEGIN_ICANN = "// ===BEGIN ICANN DOMAINS==="
END_ICANN = "// ===END ICANN DOMAINS==="
BEGIN_PRIVATE = "// ===BEGIN PRIVATE DOMAINS==="
END_PRIVATE = "// ===END PRIVATE DOMAINS==="
MAX_SOURCE_BYTES = 5 * 1024 * 1024

VERSION_METADATA_PREFIX = "// VERSION: "
COMMIT_METADATA_PREFIX = "// COMMIT: "


@dataclass(frozen=True)
class SourceManifest:
    schema_version: int
    source_name: str
    source_url: str
    source_revision: str
    git_blob_sha1: str
    license: str
    license_url: str
    idna_package: str
    idna_version: str
    idna_wheel_sha256: str


@dataclass(frozen=True)
class PreparationStats:
    source_sha256: str
    normalized_sha256: str
    exact_rules: int
    wildcard_rules: int
    exception_rules: int
    output_size: int


def load_manifest(path: Path) -> SourceManifest:
    manifest = SourceManifest(**json.loads(path.read_text(encoding="utf-8")))
    if manifest.schema_version != 1:
        raise ValueError(
            f"Unsupported Public Suffix source schema: {manifest.schema_version}"
        )
    if not manifest.source_url.startswith("https://publicsuffix.org/"):
        raise ValueError(
            "Public Suffix source URL must use publicsuffix.org over HTTPS"
        )
    _require_lowercase_hash(
        manifest.source_revision,
        40,
        "Public Suffix source revision",
    )
    _require_lowercase_hash(
        manifest.git_blob_sha1,
        40,
        "Public Suffix git blob",
    )
    _require_lowercase_hash(
        manifest.idna_wheel_sha256,
        64,
        "IDNA wheel hash",
    )
    if manifest.license != "MPL-2.0":
        raise ValueError("Public Suffix source license must be MPL-2.0")
    return manifest


def _require_lowercase_hash(value: str, length: int, description: str) -> None:
    if len(value) != length or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError(
            f"{description} must be a lowercase {length}-character hexadecimal value"
        )


def git_blob_sha1(source: bytes) -> str:
    header = f"blob {len(source)}\0".encode("ascii")
    return hashlib.sha1(header + source).hexdigest()



def upstream_blob_source(source: bytes, manifest: SourceManifest) -> bytes:
    """Remove only the metadata added by publicsuffix.org around the Git blob."""
    text = source.decode("utf-8")
    lines: list[str] = []
    version: str | None = None
    commit: str | None = None
    section_started = False
    remove_metadata_blank = False

    for raw_line in text.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if remove_metadata_blank:
            remove_metadata_blank = False
            if line == "":
                continue
        if line.startswith(VERSION_METADATA_PREFIX):
            if section_started or version is not None:
                raise ValueError("Unexpected or duplicate Public Suffix VERSION metadata")
            version = line[len(VERSION_METADATA_PREFIX):]
            if not version:
                raise ValueError("Public Suffix VERSION metadata must not be empty")
            continue
        if line.startswith(COMMIT_METADATA_PREFIX):
            if section_started or commit is not None:
                raise ValueError("Unexpected or duplicate Public Suffix COMMIT metadata")
            commit = line[len(COMMIT_METADATA_PREFIX):]
            if commit != manifest.source_revision:
                raise ValueError(
                    "Public Suffix mirror commit mismatch: "
                    f"expected {manifest.source_revision}, found {commit}"
                )
            remove_metadata_blank = True
            continue
        lines.append(raw_line)
        if line == BEGIN_ICANN:
            section_started = True

    if (version is None) != (commit is None):
        raise ValueError(
            "Public Suffix mirror metadata must contain both VERSION and COMMIT"
        )
    return "".join(lines).encode("utf-8")


def verify_source(source: bytes, manifest: SourceManifest) -> None:
    canonical_source = upstream_blob_source(source, manifest)
    actual_blob = git_blob_sha1(canonical_source)
    if actual_blob != manifest.git_blob_sha1:
        raise ValueError(
            "Public Suffix source blob mismatch: "
            f"expected {manifest.git_blob_sha1}, found {actual_blob}"
        )

    text = source.decode("utf-8")
    if "Mozilla Public" not in text or "License, v. 2.0" not in text:
        raise ValueError("Public Suffix source is missing the MPL-2.0 notice")
    for marker in (BEGIN_ICANN, END_ICANN, BEGIN_PRIVATE, END_PRIVATE):
        if text.count(marker) != 1:
            raise ValueError(
                f"Public Suffix source must contain exactly one {marker}"
            )


def download_source(
    manifest: SourceManifest,
    timeout_seconds: int = 30,
) -> bytes:
    request = urllib.request.Request(
        manifest.source_url,
        headers={"User-Agent": "dns-shield-public-suffix-preparer/1"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        source = response.read(MAX_SOURCE_BYTES + 1)
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError(
            f"Public Suffix source exceeds {MAX_SOURCE_BYTES} bytes"
        )
    return source


def load_pinned_idna_encoder(
    manifest: SourceManifest,
) -> Callable[[str], str]:
    installed = importlib.metadata.version(manifest.idna_package)
    if installed != manifest.idna_version:
        raise RuntimeError(
            f"Expected {manifest.idna_package}=={manifest.idna_version}, "
            f"found {installed}"
        )

    import idna

    def encode(domain: str) -> str:
        return idna.encode(
            domain,
            uts46=True,
            std3_rules=True,
            transitional=False,
        ).decode("ascii").lower()

    return encode


def normalize_source(
    source: bytes,
    manifest: SourceManifest,
    encode_domain: Callable[[str], str],
) -> tuple[bytes, PreparationStats]:
    section: str | None = None
    saw_sections: list[str] = []
    normalized_lines = [
        "// DNS Shield normalized Public Suffix source.",
        f"// Upstream: {manifest.source_name}@{manifest.source_revision}",
        f"// Upstream git blob: {manifest.git_blob_sha1}",
        f"// License: {manifest.license} ({manifest.license_url})",
        f"// IDNA: {manifest.idna_package}=={manifest.idna_version}",
        "",
    ]
    counts = {"exact": 0, "wildcard": 0, "exception": 0}

    for raw_line in source.decode("utf-8").splitlines():
        line = raw_line.strip()
        if line in (BEGIN_ICANN, BEGIN_PRIVATE):
            next_section = "ICANN" if line == BEGIN_ICANN else "PRIVATE"
            expected_sections = [] if next_section == "ICANN" else ["ICANN"]
            if section is not None or saw_sections != expected_sections:
                raise ValueError(
                    f"Unexpected Public Suffix section start: {line}"
                )
            section = next_section
            saw_sections.append(next_section)
            normalized_lines.append(line)
            continue
        if line in (END_ICANN, END_PRIVATE):
            expected = "ICANN" if line == END_ICANN else "PRIVATE"
            if section != expected:
                raise ValueError(
                    f"Unexpected Public Suffix section end: {line}"
                )
            section = None
            normalized_lines.extend((line, ""))
            continue
        if not line or line.startswith("//"):
            continue
        if section is None:
            raise ValueError(
                f"Public Suffix rule outside a section: {line!r}"
            )

        prefix = ""
        value = line
        category = "exact"
        if line.startswith("!"):
            prefix = "!"
            value = line[1:]
            category = "exception"
        elif line.startswith("*."):
            prefix = "*."
            value = line[2:]
            category = "wildcard"
        if (
            not value
            or value.startswith(("!", "*."))
            or "*" in value
            or "!" in value
        ):
            raise ValueError(f"Malformed Public Suffix rule: {line!r}")

        try:
            encoded = encode_domain(value)
        except Exception as exception:
            raise ValueError(
                f"Unable to normalize Public Suffix rule {line!r}"
            ) from exception
        if (
            not encoded
            or not encoded.isascii()
            or encoded != encoded.lower()
        ):
            raise ValueError(
                f"IDNA encoder returned an invalid rule for "
                f"{line!r}: {encoded!r}"
            )
        normalized_lines.append(prefix + encoded)
        counts[category] += 1

    if section is not None:
        raise ValueError(f"Unclosed Public Suffix section: {section}")
    if saw_sections != ["ICANN", "PRIVATE"]:
        raise ValueError(
            "Public Suffix source must include ICANN then PRIVATE sections"
        )

    normalized = (
        "\n".join(normalized_lines).rstrip() + "\n"
    ).encode("ascii")
    stats = PreparationStats(
        source_sha256=hashlib.sha256(source).hexdigest(),
        normalized_sha256=hashlib.sha256(normalized).hexdigest(),
        exact_rules=counts["exact"],
        wildcard_rules=counts["wildcard"],
        exception_rules=counts["exception"],
        output_size=len(normalized),
    )
    return normalized, stats


def prepare_source(
    manifest_path: Path,
    output_path: Path,
    metadata_path: Path,
    input_path: Path | None = None,
) -> PreparationStats:
    manifest = load_manifest(manifest_path)
    source = (
        input_path.read_bytes()
        if input_path is not None
        else download_source(manifest)
    )
    verify_source(source, manifest)
    normalized, stats = normalize_source(
        source,
        manifest,
        load_pinned_idna_encoder(manifest),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(normalized)
    metadata_path.write_text(
        json.dumps(
            {
                "manifest": asdict(manifest),
                "preparation": asdict(stats),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata-output", required=True, type=Path)
    parser.add_argument(
        "--input",
        type=Path,
        help="Offline source bytes; otherwise download the pinned URL",
    )
    args = parser.parse_args()

    stats = prepare_source(
        args.manifest,
        args.output,
        args.metadata_output,
        args.input,
    )
    print(f"Source SHA-256: {stats.source_sha256}")
    print(f"Normalized SHA-256: {stats.normalized_sha256}")
    print(f"Exact rules: {stats.exact_rules}")
    print(f"Wildcard rules: {stats.wildcard_rules}")
    print(f"Exception rules: {stats.exception_rules}")
    print(f"Output size: {stats.output_size} bytes")


if __name__ == "__main__":
    main()
