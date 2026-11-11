#!/usr/bin/env python3
"""Pinned derivation contract for the v1.5.0 merged production blocklist."""

from __future__ import annotations

import hashlib
import re

from build_blocklist import DOMAIN_PATTERN, normalize_domain, parse_domains

MAX_SOURCE_BYTES = 8 * 1024 * 1024
ALGORITHM = "dns-shield-merged-adblock-hosts-v1"
SOURCE_IDENTITIES = (
    (
        "badmojr/1Hosts Lite",
        "badmojr/1Hosts",
        "Lite/domains.wildcards",
        "1Hosts Lite",
    ),
    (
        "AdguardTeam/AdGuardSDNSFilter",
        "AdguardTeam/AdGuardSDNSFilter",
        "Filters/filter.txt",
        "AdGuard DNS Filter",
    ),
)

SIMPLE_BLOCK = re.compile(r"\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^", re.IGNORECASE)
SIMPLE_EXCEPTION = re.compile(
    r"@@\|\|([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)\^", re.IGNORECASE
)
HEX_40 = re.compile(r"[0-9a-f]{40}")
HEX_64 = re.compile(r"[0-9a-f]{64}")
SOURCE_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_hex(value: object, pattern: re.Pattern[str]) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _valid_size(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_source_manifest(manifest: dict[str, object]) -> None:
    if manifest.get("schema_version") != 2:
        raise ValueError(
            f"Unsupported blocklist source schema: {manifest.get('schema_version')}"
        )
    sources = manifest.get("sources")
    if not isinstance(sources, list) or len(sources) != len(SOURCE_IDENTITIES):
        raise ValueError("Merged source manifest must pin exactly two raw inputs")

    revisions: list[str] = []
    display_names: list[str] = []
    for pin, (source_name, repository, source_path, display_name) in zip(
        sources, SOURCE_IDENTITIES
    ):
        if not isinstance(pin, dict):
            raise ValueError("Merged source manifest raw pin is invalid")
        if pin.get("source_name") != source_name or pin.get("source_path") != source_path:
            raise ValueError("Merged source manifest raw source identity or path is invalid")
        revision = pin.get("source_revision")
        if not _valid_hex(revision, HEX_40):
            raise ValueError(f"Invalid pinned blocklist revision: {revision}")
        expected_url = (
            f"https://raw.githubusercontent.com/{repository}/{revision}/{source_path}"
        )
        if pin.get("source_url") != expected_url:
            raise ValueError("Raw source URL must use its immutable revision and path")
        if not SOURCE_DATE.fullmatch(str(pin.get("source_date", ""))):
            raise ValueError(f"Invalid pinned blocklist source date: {pin.get('source_date')}")
        if not _valid_size(pin.get("source_size")):
            raise ValueError(f"Invalid pinned blocklist source size: {pin.get('source_size')}")
        if not _valid_hex(pin.get("source_sha256"), HEX_64):
            raise ValueError(f"Invalid pinned blocklist SHA-256: {pin.get('source_sha256')}")
        if not _valid_hex(pin.get("git_blob_sha1"), HEX_40):
            raise ValueError(f"Invalid pinned blocklist Git blob: {pin.get('git_blob_sha1')}")
        if not isinstance(pin.get("license"), str) or not pin["license"]:
            raise ValueError("Raw source license is missing")
        if not isinstance(pin.get("license_url"), str) or not pin["license_url"]:
            raise ValueError("Raw source license URL is missing")
        revisions.append(revision)
        display_names.append(display_name)

    expected_name = " + ".join(display_names)
    expected_revision = "+".join(revisions)
    if manifest.get("source_name") != expected_name:
        raise ValueError("Merged source name does not match its two raw inputs")
    if manifest.get("source_revision") != expected_revision:
        raise ValueError("Merged source revision does not match its two raw inputs")
    if manifest.get("source_date") != sources[1]["source_date"]:
        raise ValueError("Merged source date does not match the AdGuard snapshot")
    if not _valid_size(manifest.get("source_size")):
        raise ValueError(f"Invalid merged blocklist source size: {manifest.get('source_size')}")
    if not _valid_hex(manifest.get("source_sha256"), HEX_64):
        raise ValueError(f"Invalid merged blocklist source SHA-256: {manifest.get('source_sha256')}")

    derivation = manifest.get("derivation")
    if (
        not isinstance(derivation, dict)
        or derivation.get("algorithm") != ALGORITHM
        or not isinstance(derivation.get("counts"), dict)
    ):
        raise ValueError("Merged source derivation metadata is invalid")


def validate_production_manifest(
    manifest: dict[str, object],
    source_manifest: dict[str, object] | None = None,
) -> None:
    if manifest.get("schema_version") != 2:
        raise ValueError(
            f"Unsupported production manifest schema: {manifest.get('schema_version')}"
        )
    if source_manifest is not None:
        validate_source_manifest(source_manifest)
        for field in (
            "source_name",
            "source_revision",
            "source_date",
            "source_sha256",
            "source_size",
        ):
            if manifest.get(field) != source_manifest[field]:
                raise ValueError(f"Production/source manifest mismatch for {field}")
    if not _valid_size(manifest.get("artifact_size")):
        raise ValueError(f"Invalid production artifact size: {manifest.get('artifact_size')}")
    if not _valid_size(manifest.get("entry_count")):
        raise ValueError(f"Invalid production entry count: {manifest.get('entry_count')}")
    if not _valid_hex(manifest.get("artifact_sha256"), HEX_64):
        raise ValueError(f"Invalid production artifact SHA-256: {manifest.get('artifact_sha256')}")
    if manifest.get("unique_domains") != manifest.get("entry_count"):
        raise ValueError("Production unique domain count does not match entry count")


def verify_raw_source(pin: dict[str, object], source: bytes) -> None:
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError(f"Blocklist source exceeds {MAX_SOURCE_BYTES} bytes")
    if len(source) != pin["source_size"]:
        raise ValueError(
            f"Blocklist source size mismatch for {pin['source_name']}: "
            f"expected {pin['source_size']}, found {len(source)}"
        )
    source_sha256 = sha256(source)
    if source_sha256 != pin["source_sha256"]:
        raise ValueError(
            f"Blocklist source SHA-256 mismatch for {pin['source_name']}: "
            f"expected {pin['source_sha256']}, found {source_sha256}"
        )
    git_blob_sha1 = hashlib.sha1(
        f"blob {len(source)}\0".encode("ascii") + source
    ).hexdigest()
    if git_blob_sha1 != pin["git_blob_sha1"]:
        raise ValueError(
            f"Blocklist source Git blob mismatch for {pin['source_name']}: "
            f"expected {pin['git_blob_sha1']}, found {git_blob_sha1}"
        )


def ancestors(domain: str):
    labels = domain.split(".")
    return (".".join(labels[index:]) for index in range(len(labels)))


def simple_adguard_rules(source: bytes) -> tuple[list[str], list[str], int]:
    block_rules: list[str] = []
    exception_rules: list[str] = []
    ignored_rule_lines = 0
    for raw_line in source.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("!", "#")):
            continue

        match = SIMPLE_BLOCK.fullmatch(line)
        if match:
            domain = normalize_domain(match.group(1))
            if DOMAIN_PATTERN.fullmatch(domain):
                block_rules.append(domain)
                continue

        match = SIMPLE_EXCEPTION.fullmatch(line)
        if match:
            domain = normalize_domain(match.group(1))
            if DOMAIN_PATTERN.fullmatch(domain):
                exception_rules.append(domain)
                continue

        ignored_rule_lines += 1

    return block_rules, exception_rules, ignored_rule_lines


def builtin_matches(domain: str) -> bool:
    """Port of the current BuiltInDomainMatcher.shouldBlock semantics."""
    normalized = domain.lower().strip()
    if not normalized or normalized == "unknown":
        return False

    exact_blocks = {
        "doubleclick.net",
        "admob.com",
        "pagead2.googlesyndication.com",
        "googleads.g.doubleclick.net",
        "analytics.google.com",
        "crashlytics.com",
    }
    if normalized in exact_blocks:
        return True

    suffix_blocks = (
        ".doubleclick.net",
        ".admob.com",
        ".analytics.google.com",
        ".adnxs.com",
        ".adcolony.com",
        ".adservice.google.com",
        ".scorecardresearch.com",
        ".hotjar.com",
        ".telemetry.mozilla.org",
        ".adjust.com",
        ".appsflyer.com",
    )
    if any(normalized.endswith(suffix) for suffix in suffix_blocks):
        return True

    contains_blocks = (
        "adservice",
        "adsystem",
        "googleads",
        "pagead",
        "amazon-adsystem",
        "telemetry-",
        "analytics-",
    )
    if any(fragment in normalized for fragment in contains_blocks):
        return True

    exact_blocked_labels = {"ads", "tracker", "telemetry", "analytics", "crashlytics"}
    return any(label in exact_blocked_labels for label in normalized.split("."))


def canonical_domain_bytes(domains: set[str]) -> bytes:
    return ("".join(f"{domain}\n" for domain in sorted(domains))).encode("ascii")


def derive_source(base_source: bytes, adguard_source: bytes) -> tuple[bytes, dict[str, int]]:
    base_parsed = parse_domains(base_source.decode("utf-8").splitlines())
    base_domains = set(base_parsed)
    block_rules, exception_rules, ignored_rule_lines = simple_adguard_rules(adguard_source)
    block_domains = set(block_rules)
    exception_domains = set(exception_rules)

    excluded_by_base = {
        domain
        for domain in block_domains
        if any(parent in base_domains for parent in ancestors(domain))
    }
    after_base = block_domains - excluded_by_base
    excluded_by_builtin = {
        domain for domain in after_base if builtin_matches(domain)
    }
    after_builtin = after_base - excluded_by_builtin
    excluded_by_exception = {
        domain
        for domain in after_builtin
        if any(parent in exception_domains for parent in ancestors(domain))
    }
    extra_domains = after_builtin - excluded_by_exception
    merged_domains = base_domains | extra_domains
    canonical = canonical_domain_bytes(merged_domains)

    counts = {
        "base_parsed_domains": len(base_parsed),
        "base_domains": len(base_domains),
        "simple_block_rule_lines": len(block_rules),
        "simple_block_domains": len(block_domains),
        "simple_exception_rule_lines": len(exception_rules),
        "simple_exception_domains": len(exception_domains),
        "ignored_noncomment_rule_lines": ignored_rule_lines,
        "excluded_by_base": len(excluded_by_base),
        "excluded_by_builtin_matcher": len(excluded_by_builtin),
        "excluded_by_simple_exceptions": len(excluded_by_exception),
        "extra_domains": len(extra_domains),
        "merged_domains": len(merged_domains),
        "merged_hashes": len(merged_domains),
    }
    return canonical, counts


def merge_sources(
    manifest: dict[str, object],
    base_source: bytes,
    adguard_source: bytes,
) -> bytes:
    validate_source_manifest(manifest)
    pins = manifest["sources"]
    verify_raw_source(pins[0], base_source)
    verify_raw_source(pins[1], adguard_source)
    canonical, counts = derive_source(base_source, adguard_source)
    if counts != manifest["derivation"]["counts"]:
        raise ValueError(f"Merged blocklist derivation counts changed: {counts}")
    if len(canonical) != manifest["source_size"]:
        raise ValueError(f"Merged source size mismatch: found {len(canonical)}")
    canonical_sha256 = sha256(canonical)
    if canonical_sha256 != manifest["source_sha256"]:
        raise ValueError(f"Merged source SHA-256 mismatch: found {canonical_sha256}")
    return canonical


def verify_derived_source(manifest: dict[str, object], source: bytes) -> None:
    validate_source_manifest(manifest)
    if len(source) != manifest["source_size"]:
        raise ValueError(
            f"Blocklist source size mismatch: expected {manifest['source_size']}, "
            f"found {len(source)}"
        )
    source_sha256 = sha256(source)
    if source_sha256 != manifest["source_sha256"]:
        raise ValueError(
            "Blocklist source SHA-256 mismatch: expected "
            f"{manifest['source_sha256']}, found {source_sha256}"
        )
