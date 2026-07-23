# Blocklist binary format

`tools/build_blocklist.py` converts a local text blocklist into a deterministic binary artifact. The Android app does not read this file yet.

## Input normalization

The compiler accepts one domain per line or hosts-file entries using `0.0.0.0 domain` or `127.0.0.1 domain`. It removes comments beginning with `#`, ignores invalid lines, lowercases the selected domain, and trims surrounding whitespace.

This deliberately matches the current `BuiltInDomainMatcher` contract: `lowercase().trim()`. It does not remove `www.`, convert IDNA, strip a trailing period, or apply Public Suffix logic.

## Layout

All integer fields are little-endian.

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII magic `DNSHBL01` |
| 8 | 4 | Format version (`1`) |
| 12 | 4 | Hash algorithm (`1` = FNV-1a 64-bit) |
| 16 | 8 | Entry count (`uint64`) |
| 24 | N × 8 | Unsigned 64-bit FNV-1a hashes, strictly sorted |

The output size is `24 + entryCount × 8` bytes. The artifact contains hashes only and stores exact domains from the input; parent-domain lookup belongs to a future reader/matcher.

## Integrity and collision handling

The compiler fails if distinct normalized domains produce the same 64-bit hash. It reports the output SHA-256 so builds can be reproduced and compared. Future Kotlin readers must use unsigned `Long` comparison and the same little-endian encoding.

## Usage

```powershell
python -m unittest discover tools/tests
python tools/build_blocklist.py --input tools/tests/fixtures/blocklist.txt --output build/test-blocklist.bin
```

Do not add remote downloads, production-scale source lists, memory mapping, or VPN integration until the compiler and future reader share golden vectors and fixtures.
