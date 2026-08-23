# Blocklist binary format

`tools/build_blocklist.py` converts a local text blocklist into a deterministic binary artifact. `CompiledBlocklist` validates and queries the artifact from Kotlin, `CompiledBlocklistLoader` opens a private local override through a read-only memory mapping, and `ProductionBlocklistAssetLoader` verifies and caches the pinned production artifact packaged in the APK.

## Input normalization

The compiler accepts one domain per line or hosts-file entries using `0.0.0.0 domain` or `127.0.0.1 domain`. It removes comments beginning with `#`, ignores invalid lines, lowercases the selected domain, and trims surrounding whitespace.

This deliberately matches the current `BuiltInDomainMatcher` and `CompiledBlocklistMatcher` contract: `lowercase().trim()`. It does not remove `www.`, convert IDNA, strip a trailing period, or apply Public Suffix logic.

## Layout

All integer fields are little-endian.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII magic `DNSHBL01` |
| 8 | 4 | Format version (`1`) |
| 12 | 4 | Hash algorithm (`1` = FNV-1a 64-bit) |
| 16 | 8 | Entry count (`uint64`) |
| 24 | N × 8 | Unsigned 64-bit FNV-1a hashes, strictly sorted |

The output size is `24 + entryCount × 8` bytes. The artifact contains hashes only and stores exact domains from the input. Runtime policy adds parent-domain lookup only through the verified Public Suffix boundary.

## Integrity and collision handling

The compiler fails if distinct normalized domains produce the same 64-bit hash. It reports the output SHA-256 so builds can be reproduced and compared.

The Kotlin reader validates magic, format version, hash algorithm, entry count, and exact file size before accepting the artifact. Lookup uses unsigned `Long` comparison and absolute little-endian reads. `validateSorted()` is available for tests and build-time validation, but is intentionally not called during construction because scanning a memory-mapped production list would eagerly touch every file page at startup.

`CompiledBlocklistLoader.fromFile()` requires an existing non-empty regular file, opens it read-only, memory maps the complete artifact, and then delegates all format validation to `CompiledBlocklist`. The loader does not download, replace, or select blocklists and does not modify VPN policy.

## Usage

```powershell
python -m unittest discover tools/tests
python tools/build_blocklist.py --input tools/tests/fixtures/blocklist.txt --output build/test-blocklist.bin
powershell -NoProfile -ExecutionPolicy Bypass -File .\prepare-active-blocklist-production.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-active-blocklist-asset.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

`tools/active_blocklist_source.json` pins the source repository, commit, path, byte size, Git blob SHA-1, SHA-256, and license. `tools/active_blocklist_production.json` pins the deterministic artifact size, SHA-256, and entry count. Preparation downloads only the exact pinned GitHub revision and verifies every identity field before compilation. Routine verification is offline and rejects a missing, tampered, malformed, or unsorted packaged artifact.

The production source is 1Hosts Lite under MPL-2.0. Its exact source revision and license are recorded in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
