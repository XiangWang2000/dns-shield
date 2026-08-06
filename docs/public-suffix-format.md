# Compact Public Suffix artifact

`tools/build_public_suffix.py` converts a local Public Suffix List text file into a deterministic compact artifact for `CompiledPublicSuffixList`. The compiler never downloads a source; callers must provide a locally pinned input.

## Pinned upstream preparation

`tools/public_suffix_source.json` pins the upstream list by repository commit and Git blob identity while retaining the supported download URL on `publicsuffix.org`. The manifest also records the MPL-2.0 license and the exact IDNA dependency used for Unicode normalization.

`tools/prepare_public_suffix_source.py` performs these steps:

1. Download from the pinned HTTPS URL, or read bytes supplied with `--input` for an offline run.
2. Validate and remove the official URL's `// VERSION` and `// COMMIT` metadata when present, then recompute the standard Git blob SHA-1 over the remaining upstream bytes and require it to equal the manifest value.
3. Require the MPL-2.0 notice and one complete ICANN section followed by one complete PRIVATE section.
4. Remove non-semantic upstream comments.
5. Convert each exact, wildcard, and exception rule to lowercase ASCII using `idna==3.18`, UTS #46 mapping, STD3 rules, and non-transitional processing.
6. Write deterministic normalized source plus JSON metadata containing the upstream and normalized SHA-256 values, rule counts, toolchain version, and pinned source identity.

The IDNA dependency is locked with wheel and source-distribution hashes in `tools/requirements-public-suffix.txt`. Routine `verify.ps1` remains offline and does not install this dependency or download the production list; its unit tests inject a deterministic encoder. Source refresh is an explicit maintainer operation.

## Source requirements

The normalized input must contain both standard PSL section markers:

```text
// ===BEGIN ICANN DOMAINS===
...
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
...
// ===END PRIVATE DOMAINS===
```

Exact rules, wildcard rules such as `*.ck`, and exception rules such as `!www.ck` are normalized with `lowercase().trim()`. Wildcards are stored without `*.` and exceptions without `!`. Rules are sorted by their UTF-8 bytes before encoding.

Format version 1 accepts ASCII and punycode rules only. Raw Unicode upstream rules must pass through the pinned preparation step before compilation. The Kotlin reader likewise treats non-ASCII query names and encoded rules as unusable.

The shared compatibility fixture pins its source revision, source SHA-256, artifact SHA-256, rule counts, and size in `tools/tests/fixtures/public_suffix.metadata.json`. It proves format and resolver interoperability but is not the complete production dataset.

## Binary layout

All integer fields are little-endian.

| Offset | Size | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII magic `DNSHPS01` |
| 8 | 4 | Format version (`1`) |
| 12 | 4 | Flags; bit 0 means PRIVATE rules are included |
| 16 | 4 | Exact-rule count |
| 20 | 4 | Wildcard-suffix count |
| 24 | 4 | Exception-rule count |
| 28 | 32 | SHA-256 of the exact normalized source bytes |
| 60 | variable | Exact, wildcard, then exception rule tables |

Each rule table entry is:

```text
uint16 UTF-8 byte length
N bytes UTF-8 rule
```

Every table must be strictly sorted by unsigned UTF-8 bytes. The reader rejects missing PRIVATE coverage, unsupported flags, malformed UTF-8, non-ASCII rules, invalid domains, duplicates, unsorted tables, truncation, and trailing bytes.

## Resolution behavior

`CompiledPublicSuffixList` applies the standard rule categories:

- the longest matching exact or wildcard rule prevails;
- a matching exception rule overrides wildcard or exact matches;
- when no rule matches, the default `*` rule treats the final label as the public suffix;
- a domain that is itself a public suffix has no registrable domain.

The compatibility fixture covers multi-label ICANN suffixes (`co.uk`), PRIVATE suffixes (`github.io`, `blogspot.com`), wildcard rules (`*.ck`, `*.kawasaki.jp`), and exceptions (`!www.ck`, `!city.kawasaki.jp`).

## Usage

Run the offline repository tests normally:

```powershell
python -m unittest discover tools/tests
```

Perform an explicit pinned source refresh in an isolated environment:

```powershell
python -m pip install --require-hashes -r tools/requirements-public-suffix.txt
python tools/prepare_public_suffix_source.py `
  --manifest tools/public_suffix_source.json `
  --output build/public-suffix.normalized.dat `
  --metadata-output build/public-suffix.source.json
python tools/build_public_suffix.py `
  --input build/public-suffix.normalized.dat `
  --output build/public-suffix.bin
```

Pass `--input <downloaded-file>` to reproduce normalization without network access; the preparer accepts either the raw Git source or the official URL bytes, validating and removing only the official `VERSION`/`COMMIT` metadata before checking the pinned Git blob.

The complete normalized list and production artifact are not committed or wired into `DomainPolicyAssembler` or `DnsVpnService` in this change. Measure production artifact size, startup time, retained memory, and lookup latency before activating parent-domain matching.
