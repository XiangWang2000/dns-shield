# Android Public Suffix benchmark

`PublicSuffixArtifactLoader` verifies the reviewed production artifact before parsing it. The loader checks the pinned size, artifact SHA-256, embedded normalized-source SHA-256, and rule counts. It is not connected to `DomainPolicyAssembler` or `DnsVpnService` in this change.

Generate the pinned files described in `docs/public-suffix-format.md`, connect one debuggable Android device, and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-public-suffix-android.ps1
```

The script verifies the artifact, installs the debug and test APKs, places the artifact in app-private storage, runs the instrumented benchmark, and retrieves `build/public-suffix.android-benchmark.json`.

The report records device model, API level, ABI, artifact identity, rule counts, load median and p95, approximate heap delta, and lookup median and p95. These are observations rather than universal pass or fail thresholds.

Use at least 10 independent runs when comparing changes, while keeping device, Android build, power state, thermal state, and background workload consistent. Future runtime integration must retain one loaded resolver per service or policy lifecycle instead of rebuilding it for each query.

The artifact remains external to the APK, parent-domain matching remains disabled, and no VPN, DNS cache, blocklist cache, DoH, UDP, or query-coalescing behavior changes in this PR.
