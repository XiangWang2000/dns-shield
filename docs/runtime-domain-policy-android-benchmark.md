# Runtime domain-policy Android benchmark

This benchmark characterizes the production policy path introduced by PR #24 without changing VPN behavior.

It uses:

- the checked-in production `app/src/main/assets/public_suffix.bin`;
- `RuntimeDomainPolicy.assemble()`;
- `PublicSuffixResolverOwner.fromAssets()`;
- the same deterministic four-entry `active.bin` fixture used by `ActiveBlocklistRuntimeInstrumentedTest`.

The benchmark is intentionally an observation tool. It does not enforce device-dependent latency or heap thresholds.

## What it measures

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

## Why heap is split into cold and steady metrics

The two post-PR25 ASUS_Z01RD runs both reported exactly `8,630,928` bytes for `approximate_active_policy_retained_heap_bytes`, while the earlier post-PR20 warmed resolver benchmark had observed roughly `1.31 MB` in one run and a noisy zero delta in another.

Those measurements used different baselines. PR #25 sampled heap before the first production PSL asset load and therefore included first-use initialization retained by the process. The older resolver benchmark warmed the loader/resolver path before taking its retained-heap baseline.

The benchmark now preserves the PR #25 cold-inclusive number for historical comparison, then explicitly warms the active policy path, releases that policy, forces GC, and measures exact-only and parent-aware steady-state object retention separately across five samples.

These are still `Runtime.totalMemory() - Runtime.freeMemory()` before/after observations. ART heap growth, GC timing, instrumentation allocations, and runtime-version differences can affect the result. Same-device repeated runs remain more important than any one absolute number.

## Run

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

## Interpretation

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
