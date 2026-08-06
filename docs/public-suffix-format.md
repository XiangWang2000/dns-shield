# Compact Public Suffix artifact

`tools/build_public_suffix.py` converts a local Public Suffix List text file into a deterministic compact artifact for `CompiledPublicSuffixList`. The compiler never downloads a source; callers must provide a locally pinned input.

## Source requirements

The input must contain both standard PSL section markers:

```text
// ===BEGIN ICANN DOMAINS===
...
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
...
// ===END PRIVATE DOMAINS===
```

Exact rules, wildcard rules such as `*.ck`, and exception rules such as `!www.ck` are normalized with `lowercase().trim()`. Wildcards are stored without `*.` and exceptions without `!`. Rules are sorted by their UTF-8 bytes before encoding.

Format version 1 accepts ASCII and punycode rules only. Raw Unicode rules are rejected rather than being encoded with a platform-dependent IDNA implementation. A future production pipeline must add one reviewed, reproducible Unicode-to-punycode normalization step before compiling the complete upstream PSL. The Kotlin reader likewise treats non-ASCII query names and encoded rules as unusable.

The shared compatibility fixture pins its source revision, source SHA-256, artifact SHA-256, rule counts, and size in `tools/tests/fixtures/public_suffix.metadata.json`. A future production source must provide equivalent pinned metadata and must include both ICANN and PRIVATE sections.

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
| 28 | 32 | SHA-256 of the exact source bytes |
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

```powershell
python -m unittest discover tools/tests
python tools/build_public_suffix.py `
  --input tools/tests/fixtures/public_suffix_list.dat `
  --output build/test-public-suffix.bin
```

This format and resolver are not yet wired into `DomainPolicyAssembler` or `DnsVpnService`. Do not activate parent-domain matching until a reviewed production PSL source, deterministic IDNA policy, artifact loading strategy, startup cost, and memory measurements are available.
