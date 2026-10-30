# Android benchmark 歷史紀錄

> 本頁合併原有三份報告，保留量測條件、數據與限制。現行重跑方式見[benchmark 指南](../benchmarks.md)。

<a id="production-blocklist"></a>

## Production blocklist

原文件：`docs/production-blocklist-android-benchmark.md`。

This benchmark compares the built-in-only domain policy with the packaged production `active.bin` in the same Android instrumentation process. It verifies the pinned artifact before building, installs the debug and test APKs, runs one benchmark class, and pulls a JSON report.

### Run

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-production-blocklist-android.ps1
```

The report is written to:

```text
build/production-blocklist.android-benchmark.json
```

The test removes any app-private `blocklists/active.bin` for the measurement and restores a previous regular file in `finally`. It does not download or update blocklist data on the device.

### ASUS_Z01RD characterization

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

### Size and power interpretation

The debug APK grew from 20,487,946 to 21,337,834 bytes: 849,888 bytes or 4.15%. The hashed production asset occupies 823,800 bytes uncompressed and 805,385 bytes in the APK.

The asset loader retains one byte array per VPN service lifecycle, roughly 0.79 MiB plus object overhead, and reuses the parsed `CompiledBlocklist`. Successful sorted validation is also cached, so tunnel restarts do not rescan 102,972 hashes. The production list introduces no timer, polling loop, background download, or per-idle-cycle work; its CPU cost occurs at first policy construction and during DNS lookups rather than while the VPN is idle.

These are device observations, not cross-device pass thresholds. Repeat the benchmark on the same device and firmware when changing the artifact format, source size, asset verification, parent matching, or lifecycle caching.

<a id="public-suffix"></a>

## Public Suffix

原文件：`docs/public-suffix-android-benchmark.md`。

`benchmark-public-suffix-android.ps1` turns the previously one-off device check into a repeatable, repository-owned instrumented benchmark. It validates the production outputs before installing anything, copies the reviewed compact artifact into a generated **androidTest-only** asset directory, runs one named test through adb, and pulls a JSON report back to `build/`.

The generated asset is not part of the main APK source set. This workflow does not enable parent-domain matching and does not change `DomainPolicyAssembler`, `RuntimeDomainPolicy`, or `DnsVpnService`.

### Prerequisites

- one connected adb device, or an explicit `-Serial` value;
- Android Studio JBR and Android SDK tools on the development machine;
- the pinned outputs already generated at:
  - `build/public-suffix.normalized.dat`;
  - `build/public-suffix.bin`.

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-public-suffix-android.ps1
```

When more than one device is connected:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-public-suffix-android.ps1 `
  -Serial <adb-serial>
```

The command writes:

```text
build/public-suffix.android-validation.json
build/public-suffix.android-benchmark.json
```

### What is measured

The instrumented test records:

- Android model, release, API level, and primary ABI;
- artifact size, rule counts, and embedded normalized-source SHA-256;
- `first_load_nanos`: the first asset-read, validation, parsing and resolver construction in the instrumentation process, before any loader warm-up;
- `warm_load_median_nanos` and `warm_load_p95_nanos`: repeated resolver construction across 12 later samples after classes and the artifact have already been touched;
- `cached_load_nanos`: a second `load()` call through the same loader instance, which must return the identical cached resolver;
- approximate retained Java heap for one held resolver;
- median and p95 lookup time across 12 batches of 20,000 representative lookups.

The lookup set covers ordinary ICANN rules, `co.uk`, PRIVATE suffixes, wildcard rules, exception rules, and a punycode suffix.

### Interpretation

Timing and heap values are observations, not universal test limits. Compare results only when the device, Android build, power state, generated artifact, and command are held constant. The heap value is a GC-assisted before/after approximation rather than an exact object graph size.

`first_load_nanos` is the first resolver load inside an already-running instrumentation process. It intentionally runs before any `PublicSuffixAssetLoader.load()` warm-up, but it is not a complete cold application-process or VPN-service startup measurement. The warm-load values should not be presented as first-start latency, and cached-load timing should only be used to verify that lifecycle-scoped reuse is inexpensive.

The initial ad hoc ASUS_Z01RD result can be used only as a rough reference because it predates this committed runner:

```text
Android 10 / API 29 / arm64-v8a
load median 210.77 ms, p95 216.19 ms
lookup median 11.23 us, p95 14.00 us
approximate heap 690,000 bytes
```

The first committed post-merge run on the same ASUS_Z01RD established the baseline for storage-layout changes:

```text
Android 10 / API 29 / arm64-v8a
artifact 153,740 bytes; rules 9,950 / 281 / 8
first load 273.81 ms
warm load median 163.59 ms, p95 169.59 ms
cached load 1.666 us
approximate retained heap 4,221,200 bytes
lookup median 8.733 us, p95 11.282 us
```

The large difference between the old ad hoc heap estimate and the committed benchmark means the absolute heap number should still be treated as approximate. However, use the committed 4,221,200-byte result as the A/B baseline when evaluating resolver storage changes because it was produced by the repository-owned runner.

### Post-PR20 sorted-array baseline

After PR #20 replaced the three `LinkedHashSet<String>` rule tables with sorted `Array<String>` tables and binary search, the same ASUS_Z01RD produced two post-merge runs with the validated 153,740-byte production artifact (`9950 / 281 / 8` rules):

```text
Run 1
first load 261.69 ms
warm load median 158.80 ms, p95 171.81 ms
cached load 1.615 us
approximate retained heap 1,311,520 bytes
lookup median 10.065 us, p95 13.287 us

Run 2
first load 259.66 ms
warm load median 159.95 ms, p95 175.05 ms
cached load 1.875 us
approximate retained heap 0 bytes
lookup median 10.327 us, p95 15.244 us
```

Run 1 shows a large retained-heap reduction relative to the 4,221,200-byte A/B baseline while lookup remains comfortably below the 50 us review budget. Run 2's zero-byte heap delta must not be interpreted as zero resolver memory; it demonstrates that the GC-assisted before/after metric is noisy enough that relative trends across repeated same-device runs are more trustworthy than one absolute value. First/warm load time changed much less than retained memory, so further representation work is not justified solely to chase load latency on this older device.

Run the committed benchmark multiple times before using these comparisons. Give the first-load value from each independent instrumentation run its own sample set; do not calculate a first-load p95 from warm samples in one process. The resolver is suitable for later packaging only when loading remains a once-per-service-lifecycle cost and does not cause repeated parsing during DNS queries, network changes, Activity recreation, or duplicate service starts.

### Boundary recorded by the original characterization

This section preserves the boundary at the time of that report, before the later production packaging and runtime integration. Current behavior is described in [Public Suffix](../public-suffix.md).

`PublicSuffixAssetLoader` validates the artifact size, artifact SHA-256, embedded normalized-source SHA-256, and all three rule counts before exposing a resolver. It also caches one successfully loaded resolver per loader instance. The production artifact itself is still not checked into `app/src/main/assets`, and the loader is not used by runtime policy.

A lifecycle-scoped runtime owner may be added before production packaging so successful and rejected loads both become one-shot decisions for that service or policy lifecycle. Runtime parent-domain blocking remains a separate change after asset packaging and lifecycle ownership are independently verified.

<a id="runtime-domain-policy"></a>

## Runtime domain policy

原文件：`docs/runtime-domain-policy-android-benchmark.md`。

This benchmark characterizes the production policy path introduced by PR #24 without changing VPN behavior.

It uses:

- the checked-in production `app/src/main/assets/public_suffix.bin`;
- `RuntimeDomainPolicy.assemble()`;
- `PublicSuffixResolverOwner.fromAssets()`;
- the same deterministic four-entry `active.bin` fixture used by `ActiveBlocklistRuntimeInstrumentedTest`.

The benchmark is intentionally an observation tool. It does not enforce device-dependent latency or heap thresholds.

### What it measures

The report separates the important paths instead of collapsing them into one startup number.

Assembly and lookup distributions use 20 measured samples/batches after two unmeasured lookup warm-up batches, so the reported p95 is not simply the maximum of a small sample set.

- `missing_assembly_median_nanos` / `missing_assembly_p95_nanos`: policy assembly when `active.bin` is absent. The resolver provider must not be called, so the packaged PSL stays unconstructed.
- `first_active_assembly_nanos`: first valid active-policy assembly in the instrumentation process. This includes active.bin loading and validation, the first verified production PSL asset load, resolver construction, and policy composition.
- `cached_active_assembly_median_nanos` / `cached_active_assembly_p95_nanos`: later policy assemblies using the same lifecycle-scoped resolver owner. The active blocklist is loaded again, but the Public Suffix resolver is reused.
- `approximate_active_policy_retained_heap_bytes`: compatibility field retained from PR #25. Its baseline is taken before the first production PSL load, so it is a **cold-inclusive heap delta** that can include one-time class/static/crypto/parser initialization in addition to retained policy objects. Do not compare it directly with the older warmed resolver-only heap benchmark.
- `steady_exact_policy_retained_heap_median_bytes`: median of five GC-assisted retained-heap measurements for a validated exact-only compiled policy after all relevant code paths have already been warmed.
- `steady_parent_policy_retained_heap_median_bytes`: median of five GC-assisted retained-heap measurements for a fresh lifecycle-scoped PSL owner plus one parent-aware active policy after first-use initialization has already occurred.
- `steady_parent_incremental_heap_median_bytes`: median paired difference between parent-aware and exact-only steady measurements. This is the best benchmark-level estimate of the incremental retained Java-heap cost of enabling the PSL-backed parent boundary, while still remaining approximate.
- exact, parent-aware, and unrelated lookup median/p95 nanoseconds. Parent lookup uses `cdn.github.com`, which is blocked through the compiled `github.com` entry and the production PSL boundary.

The four-entry active fixture keeps this benchmark focused on PSL/policy integration overhead. It does not represent the load time or memory footprint of a future large production compiled blocklist.

`first_active_assembly_nanos` is also not full cold process, foreground-service, VPN permission, TUN establishment, Room, or upstream-DNS startup time. It runs inside an already-started Android instrumentation process.

### Why heap is split into cold and steady metrics

The two post-PR25 ASUS_Z01RD runs both reported exactly `8,630,928` bytes for `approximate_active_policy_retained_heap_bytes`, while the earlier post-PR20 warmed resolver benchmark had observed roughly `1.31 MB` in one run and a noisy zero delta in another.

Those measurements used different baselines. PR #25 sampled heap before the first production PSL asset load and therefore included first-use initialization retained by the process. The older resolver benchmark warmed the loader/resolver path before taking its retained-heap baseline.

The benchmark now preserves the PR #25 cold-inclusive number for historical comparison, then explicitly warms the active policy path, releases that policy, forces GC, and measures exact-only and parent-aware steady-state object retention separately across five samples.

These are still `Runtime.totalMemory() - Runtime.freeMemory()` before/after observations. ART heap growth, GC timing, instrumentation allocations, and runtime-version differences can affect the result. Same-device repeated runs remain more important than any one absolute number.

### Run

Connect one Android device and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-runtime-domain-policy-android.ps1
```

When multiple devices are attached:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-runtime-domain-policy-android.ps1 `
  -Serial <adb-serial>
```

The runner verifies the checked-in Public Suffix asset contract, installs the debug and test APKs, runs only `RuntimeDomainPolicyInstrumentedBenchmarkTest`, and pulls:

```text
build/runtime-domain-policy.android-benchmark.json
```

The instrumented test creates and removes its app-private `blocklists/active.bin` fixture inside `try/finally` so the device is returned to the missing-active-file state after a successful or failed run.

### Interpretation

Compare repeated runs on the same device, Android build, thermal state, and power state. One sample should not become a universal threshold.

For the ASUS_Z01RD / Android 10 characterization, the main questions are:

1. Is the missing-`active.bin` path still effectively unchanged and free of PSL construction?
2. Is the first active-policy assembly consistent with the previously measured roughly 260 ms first PSL construction rather than showing a materially larger integration penalty?
3. Are cached policy reloads much cheaper than the first active assembly?
4. Is `steady_parent_policy_retained_heap_median_bytes` substantially below the PR #25 cold-inclusive ~8.63 MB observation and closer to the earlier warmed resolver range?
5. How large is `steady_parent_incremental_heap_median_bytes` relative to the exact-only policy control?
6. Does parent-aware lookup p95 remain comfortably below the earlier 50 microsecond review budget?

Do not use the PR #25 `approximate_active_policy_retained_heap_bytes` field alone to decide whether the runtime integration regressed memory. If the new steady parent-aware measurement remains multi-megabyte across repeated same-device runs, then memory representation should be revisited before further runtime work. If the steady measurement returns near the earlier warmed resolver range, the 8.63 MB value should be treated mainly as cold first-use process initialization rather than recurring retained policy cost.

After this benchmark is stable, battery impact should be measured separately with an 8-10 hour same-device A/B run. Battery characterization should not be inferred from microbenchmark timings alone.
