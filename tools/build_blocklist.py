#!/usr/bin/env python3
"""Build a deterministic, versioned binary blocklist artifact from a local text file."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MAGIC = b"DNSHBL01"
FORMAT_VERSION = 1
HASH_ALGORITHM_FNV1A_64 = 1
HEADER_FORMAT = "<8sIIQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
FNV_OFFSET_BASIS = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
FNV_MASK = 0xFFFFFFFFFFFFFFFF
HOSTS_REDIRECTS = {"0.0.0.0", "127.0.0.1"}
DOMAIN_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")


@dataclass(frozen=True)
class BuildStats:
    parsed_domains: int
    unique_domains: int
    unique_hashes: int
    hash_collisions: int
    output_size: int
    sha256: str


def normalize_domain(value: str) -> str:
    """Matches the current BuiltInDomainMatcher normalization contract exactly."""
    return value.lower().strip()


def parse_domain_line(line: str) -> str | None:
    content = line.split("#", 1)[0].strip()
    if not content:
        return None

    fields = content.split()
    if len(fields) == 1:
        candidate = fields[0]
    elif len(fields) == 2 and fields[0] in HOSTS_REDIRECTS:
        candidate = fields[1]
    else:
        return None

    normalized = normalize_domain(candidate)
    if normalized in {"", "unknown"} or not DOMAIN_PATTERN.fullmatch(normalized):
        return None
    return normalized


def parse_domains(lines: Iterable[str]) -> list[str]:
    return [domain for line in lines if (domain := parse_domain_line(line)) is not None]


def fnv1a64(value: bytes) -> int:
    hash_value = FNV_OFFSET_BASIS
    for byte in value:
        hash_value ^= byte
        hash_value = (hash_value * FNV_PRIME) & FNV_MASK
    return hash_value


def build_artifact(domains: Iterable[str]) -> tuple[bytes, int, int]:
    unique_domains = sorted(set(domains))
    domains_by_hash: dict[int, str] = {}

    for domain in unique_domains:
        hash_value = fnv1a64(domain.encode("utf-8"))
        previous_domain = domains_by_hash.get(hash_value)
        if previous_domain is not None and previous_domain != domain:
            raise ValueError(
                "FNV-1a 64-bit collision between "
                f"{previous_domain!r} and {domain!r}: {hash_value:#018x}"
            )
        domains_by_hash[hash_value] = domain

    sorted_hashes = sorted(domains_by_hash)
    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        FORMAT_VERSION,
        HASH_ALGORITHM_FNV1A_64,
        len(sorted_hashes),
    )
    entries = b"".join(struct.pack("<Q", hash_value) for hash_value in sorted_hashes)
    return header + entries, len(unique_domains), len(sorted_hashes)


def build_blocklist(input_path: Path, output_path: Path) -> BuildStats:
    parsed_domains = parse_domains(input_path.read_text(encoding="utf-8").splitlines())
    artifact, unique_domains, unique_hashes = build_artifact(parsed_domains)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(artifact)
    return BuildStats(
        parsed_domains=len(parsed_domains),
        unique_domains=unique_domains,
        unique_hashes=unique_hashes,
        hash_collisions=0,
        output_size=len(artifact),
        sha256=hashlib.sha256(artifact).hexdigest(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="Local text blocklist input")
    parser.add_argument("--output", required=True, type=Path, help="Binary artifact output")
    args = parser.parse_args()

    stats = build_blocklist(args.input, args.output)
    print(f"Parsed domains: {stats.parsed_domains}")
    print(f"Unique domains: {stats.unique_domains}")
    print(f"Unique hashes: {stats.unique_hashes}")
    print(f"Hash collisions: {stats.hash_collisions}")
    print(f"Output size: {stats.output_size} bytes")
    print(f"SHA-256: {stats.sha256}")


if __name__ == "__main__":
    main()
