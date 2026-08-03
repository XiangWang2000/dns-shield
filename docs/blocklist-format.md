# Blocklist binary format

`tools/build_blocklist.py` converts a local text blocklist into a deterministic binary artifact. `CompiledBlocklist` can validate and query this artifact from Kotlin, but the reader is not wired into the VPN yet.

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

The output size is `24 + entryCount × 8` bytes. The artifact contains hashes only and stores exact domains from the input; parent-domain lookup belongs to a future matcher policy.

## Integrity and collision handling

The compiler fails if distinct normalized domains produce the same 64-bit hash. It reports the output SHA-256 so builds can be reproduced and compared.

The Kotlin reader validates magic, format version, hash algorithm, entry count, and exact file size before accepting the artifact. Lookup uses unsigned `Long` comparison and absolute little-endian reads. `validateSorted()` is available for tests and build-time validation, but is intentionally not called during construction because scanning a future memory-mapped production list would eagerly touch every file page at startup.

## Usage

```powershell
python -m unittest discover tools/tests
python tools/build_blocklist.py --input tools/tests/fixtures/blocklist.txt --output build/test-blocklist.bin
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

Do not add remote downloads, production-scale source lists, memory mapping, parent-domain policy, or VPN integration until the reader and compiler remain compatible under the shared golden vectors and fixtures.
