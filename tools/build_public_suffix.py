#!/usr/bin/env python3
"""Build a deterministic compact Public Suffix artifact from a local PSL text file."""

from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"DNSHPS01"
FORMAT_VERSION = 1
FLAG_INCLUDES_PRIVATE = 1
HEADER_FORMAT = "<8sIIIII32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_RULE_BYTES = 0xFFFF

BEGIN_ICANN = "// ===BEGIN ICANN DOMAINS==="
END_ICANN = "// ===END ICANN DOMAINS==="
BEGIN_PRIVATE = "// ===BEGIN PRIVATE DOMAINS==="
END_PRIVATE = "// ===END PRIVATE DOMAINS==="


@dataclass(frozen=True)
class PublicSuffixRules:
    exact: tuple[str, ...]
    wildcard_suffixes: tuple[str, ...]
    exceptions: tuple[str, ...]
    includes_private: bool


@dataclass(frozen=True)
class BuildStats:
    exact_rules: int
    wildcard_rules: int
    exception_rules: int
    output_size: int
    source_sha256: str
    artifact_sha256: str


def normalize_rule(value: str) -> str:
    return value.lower().strip()


def _validate_domain(value: str) -> None:
    if not value or value == "unknown":
        raise ValueError("Public Suffix rule must not be blank or unknown")
    if value.startswith(".") or value.endswith(".") or ".." in value:
        raise ValueError(f"Malformed Public Suffix rule: {value!r}")
    if any(character.isspace() or character in "/*!" for character in value):
        raise ValueError(f"Malformed Public Suffix rule: {value!r}")
    if not value.isascii():
        raise ValueError(
            f"Public Suffix rule must be ASCII or punycode in format v1: {value!r}"
        )
    for label in value.split("."):
        if not label or label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Malformed Public Suffix rule: {value!r}")


def parse_public_suffix_list(text: str) -> PublicSuffixRules:
    exact: set[str] = set()
    wildcard_suffixes: set[str] = set()
    exceptions: set[str] = set()
    section: str | None = None
    saw_icann = False
    saw_private = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line == BEGIN_ICANN:
            if section is not None or saw_icann:
                raise ValueError("Duplicate or nested ICANN section")
            section = "ICANN"
            saw_icann = True
            continue
        if line == END_ICANN:
            if section != "ICANN":
                raise ValueError("Unexpected ICANN section end")
            section = None
            continue
        if line == BEGIN_PRIVATE:
            if section is not None or saw_private:
                raise ValueError("Duplicate or nested PRIVATE section")
            section = "PRIVATE"
            saw_private = True
            continue
        if line == END_PRIVATE:
            if section != "PRIVATE":
                raise ValueError("Unexpected PRIVATE section end")
            section = None
            continue
        if not line or line.startswith("//"):
            continue
        if section is None:
            raise ValueError(f"Rule outside ICANN or PRIVATE section: {line!r}")

        normalized = normalize_rule(line)
        if normalized.startswith("!"):
            value = normalized[1:]
            _validate_domain(value)
            exceptions.add(value)
        elif normalized.startswith("*."):
            value = normalized[2:]
            _validate_domain(value)
            wildcard_suffixes.add(value)
        else:
            _validate_domain(normalized)
            exact.add(normalized)

    if section is not None:
        raise ValueError(f"Unclosed {section} section")
    if not saw_icann:
        raise ValueError("Missing ICANN section")
    if not saw_private:
        raise ValueError("Missing PRIVATE section")

    sort_key = lambda value: value.encode("utf-8")
    return PublicSuffixRules(
        exact=tuple(sorted(exact, key=sort_key)),
        wildcard_suffixes=tuple(sorted(wildcard_suffixes, key=sort_key)),
        exceptions=tuple(sorted(exceptions, key=sort_key)),
        includes_private=True,
    )


def _encode_rules(rules: tuple[str, ...]) -> bytes:
    encoded = bytearray()
    for rule in rules:
        value = rule.encode("utf-8")
        if len(value) > MAX_RULE_BYTES:
            raise ValueError(f"Public Suffix rule is too long: {rule!r}")
        encoded.extend(struct.pack("<H", len(value)))
        encoded.extend(value)
    return bytes(encoded)


def build_artifact(source: bytes) -> tuple[bytes, PublicSuffixRules]:
    rules = parse_public_suffix_list(source.decode("utf-8"))
    flags = FLAG_INCLUDES_PRIVATE if rules.includes_private else 0
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        FORMAT_VERSION,
        flags,
        len(rules.exact),
        len(rules.wildcard_suffixes),
        len(rules.exceptions),
        hashlib.sha256(source).digest(),
    )
    artifact = b"".join(
        (
            header,
            _encode_rules(rules.exact),
            _encode_rules(rules.wildcard_suffixes),
            _encode_rules(rules.exceptions),
        )
    )
    return artifact, rules


def build_public_suffix(input_path: Path, output_path: Path) -> BuildStats:
    source = input_path.read_bytes()
    artifact, rules = build_artifact(source)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(artifact)
    return BuildStats(
        exact_rules=len(rules.exact),
        wildcard_rules=len(rules.wildcard_suffixes),
        exception_rules=len(rules.exceptions),
        output_size=len(artifact),
        source_sha256=hashlib.sha256(source).hexdigest(),
        artifact_sha256=hashlib.sha256(artifact).hexdigest(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Local PSL text input")
    parser.add_argument("--output", required=True, type=Path, help="Compact artifact output")
    args = parser.parse_args()

    stats = build_public_suffix(args.input, args.output)
    print(f"Exact rules: {stats.exact_rules}")
    print(f"Wildcard rules: {stats.wildcard_rules}")
    print(f"Exception rules: {stats.exception_rules}")
    print(f"Output size: {stats.output_size} bytes")
    print(f"Source SHA-256: {stats.source_sha256}")
    print(f"Artifact SHA-256: {stats.artifact_sha256}")


if __name__ == "__main__":
    main()
