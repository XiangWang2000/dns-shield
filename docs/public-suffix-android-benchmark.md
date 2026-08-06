# Android Public Suffix characterization

`benchmark-public-suffix-android.ps1` turns the previously one-off device check into a repeatable, repository-owned instrumented benchmark. It validates the production outputs before installing anything, copies the reviewed compact artifact into a generated **androidTest-only** asset directory, runs one named test through adb, and pulls a JSON report back to `build/`.

The generated asset is not part of the main APK source set. This workflow does not enable parent-domain matching and does not change `DomainPolicyAssembler`, `RuntimeDomainPolicy`, or `DnsVpnService`.

## Prerequisites

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

## What is measured

The instrumented test records:

- Android model, release, API level, and primary ABI;
- artifact size, rule counts, and embedded normalized-source SHA-256;
- `first_load_nanos`: the first asset-read, validation, parsing and resolver construction in the instrumentation process, before any loader warm-up;
- `warm_load_median_nanos` and `warm_load_p95_nanos`: repeated resolver construction across 12 later samples after classes and the artifact have already been touched;
- `cached_load_nanos`: a second `load()` call through the same loader instance, which must return the identical cached resolver;
- approximate retained Java heap for one held resolver;
- median and p95 lookup time across 12 batches of 20,000 representative lookups.

The lookup set covers ordinary ICANN rules, `co.uk`, PRIVATE suffixes, wildcard rules, exception rules, and a punycode suffix.

## Interpretation

Timing and heap values are observations, not universal test limits. Compare results only when the device, Android build, power state, generated artifact, and command are held constant. The heap value is a GC-assisted before/after approximation rather than an exact object graph size.

`first_load_nanos` is the first resolver load inside an already-running instrumentation process. It intentionally runs before any `PublicSuffixAssetLoader.load()` warm-up, but it is not a complete cold application-process or VPN-service startup measurement. The warm-load values should not be presented as first-start latency, and cached-load timing should only be used to verify that lifecycle-scoped reuse is inexpensive.

The initial ad hoc ASUS_Z01RD result can be used only as a rough reference because it predates this committed runner:

```text
Android 10 / API 29 / arm64-v8a
load median 210.77 ms, p95 216.19 ms
lookup median 11.23 us, p95 14.00 us
approximate heap 690,000 bytes
```

Run the committed benchmark multiple times before using that comparison. Give the first-load value from each independent instrumentation run its own sample set; do not calculate a first-load p95 from warm samples in one process. The current loader is suitable for later packaging only when it remains a once-per-service-lifecycle cost and does not cause repeated parsing during DNS queries, network changes, Activity recreation, or duplicate service starts.

## Current boundary

`PublicSuffixAssetLoader` validates the artifact size, artifact SHA-256, embedded normalized-source SHA-256, and all three rule counts before exposing a resolver. It also caches one successfully loaded resolver per loader instance. The production artifact itself is still not checked into `app/src/main/assets`, and the loader is not used by runtime policy.

A later PR may package the reviewed artifact as a main APK asset after repeated device measurements are reviewed. Runtime parent-domain blocking remains a separate change after asset loading and lifecycle ownership are independently verified.
