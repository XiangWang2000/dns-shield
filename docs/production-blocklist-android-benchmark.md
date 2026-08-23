# Production blocklist Android benchmark

This benchmark compares the built-in-only domain policy with the packaged production `active.bin` in the same Android instrumentation process. It verifies the pinned artifact before building, installs the debug and test APKs, runs one benchmark class, and pulls a JSON report.

## Run

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-production-blocklist-android.ps1
```

The report is written to:

```text
build/production-blocklist.android-benchmark.json
```

The test removes any app-private `blocklists/active.bin` for the measurement and restores a previous regular file in `finally`. It does not download or update blocklist data on the device.

## ASUS_Z01RD characterization

Device: ASUS_Z01RD / Android 10 / API 29 / arm64-v8a. Each lookup result is the per-operation time from 30 batches of 1,000 calls; assembly distributions use 100 iterations.

| Metric | Result |
| --- | ---: |
| Built-in-only assembly median / p95 | 0.090 / 0.108 ms |
| First production assembly | 275.815 ms |
| Cached production assembly median / p95 | 0.101 / 0.121 ms |
| Built-in miss lookup median / p95 | 2.505 / 2.601 us |
| Production exact blocked lookup median / p95 | 5.397 / 5.510 us |
| Production parent blocked lookup median / p95 | 20.188 / 25.049 us |
| Production allowed lookup median / p95 | 11.439 / 16.467 us |

The first production assembly includes reading and SHA-256 verification of the 823,800-byte blocklist, its first sorted scan, and the existing first Public Suffix asset verification and resolver construction. The 275.815 ms result is about 0.7% above the previous upper four-entry observation of 273.798 ms and remains consistent with that roughly 270-276 ms cold path, so the 102,972-entry artifact does not show a material cold-start regression.

After lifecycle caching, production policy assembly adds about 0.010 ms median over the built-in-only control. The extra per-domain lookup work is measured in single- or low-double-digit microseconds, below the existing 50 us parent-lookup review budget and small relative to an upstream DNS exchange measured in milliseconds.

## Size and power interpretation

The debug APK grew from 20,487,946 to 21,337,834 bytes: 849,888 bytes or 4.15%. The hashed production asset occupies 823,800 bytes uncompressed and 805,385 bytes in the APK.

The asset loader retains one byte array per VPN service lifecycle, roughly 0.79 MiB plus object overhead, and reuses the parsed `CompiledBlocklist`. Successful sorted validation is also cached, so tunnel restarts do not rescan 102,972 hashes. The production list introduces no timer, polling loop, background download, or per-idle-cycle work; its CPU cost occurs at first policy construction and during DNS lookups rather than while the VPN is idle.

These are device observations, not cross-device pass thresholds. Repeat the benchmark on the same device and firmware when changing the artifact format, source size, asset verification, parent matching, or lifecycle caching.
