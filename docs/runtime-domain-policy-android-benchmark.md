# Runtime domain-policy Android benchmark

This benchmark characterizes the production policy path introduced by PR #24 without changing VPN behavior.

It uses:

- the checked-in production `app/src/main/assets/public_suffix.bin`;
- `RuntimeDomainPolicy.assemble()`;
- `PublicSuffixResolverOwner.fromAssets()`;
- the same deterministic four-entry `active.bin` fixture used by `ActiveBlocklistRuntimeInstrumentedTest`.

The benchmark is intentionally an observation tool. It does not enforce device-dependent latency or heap thresholds.

## What it measures

The report separates the important paths instead of collapsing them into one startup number:

- `missing_assembly_median_nanos` / `missing_assembly_p95_nanos`: policy assembly when `active.bin` is absent. The resolver provider must not be called, so the packaged PSL stays unconstructed.
- `first_active_assembly_nanos`: first valid active-policy assembly in the instrumentation process. This includes active.bin loading and validation, the first verified production PSL asset load, resolver construction, and policy composition.
- `cached_active_assembly_median_nanos` / `cached_active_assembly_p95_nanos`: later policy assemblies using the same lifecycle-scoped resolver owner. The active blocklist is loaded again, but the Public Suffix resolver is reused.
- `approximate_active_policy_retained_heap_bytes`: GC-assisted before/after heap delta for the retained resolver owner plus one active `DomainPolicyAssembly`. Treat this as an A/B characterization, not an exact object-size measurement.
- exact, parent-aware, and unrelated lookup median/p95 nanoseconds. Parent lookup uses `cdn.github.com`, which is blocked through the compiled `github.com` entry and the production PSL boundary.

The four-entry active fixture keeps this benchmark focused on PSL/policy integration overhead. It does not represent the load time or memory footprint of a future large production compiled blocklist.

`first_active_assembly_nanos` is also not full cold process, foreground-service, VPN permission, TUN establishment, Room, or upstream-DNS startup time. It runs inside an already-started Android instrumentation process.

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
4. Does approximate retained heap remain in the same order of magnitude as the post-PR20 resolver measurements rather than returning to the earlier multi-megabyte `LinkedHashSet` baseline?
5. Does parent-aware lookup p95 remain comfortably below the earlier 50 microsecond review budget?

After this benchmark is stable, battery impact should be measured separately with an 8-10 hour same-device A/B run. Battery characterization should not be inferred from microbenchmark timings alone.
