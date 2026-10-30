# 1.2 系列候選版與驗證紀錄

> 本頁合併原有兩份紀錄；未勾選項目、候選版狀態與量測限制均保留，不代表已完成發版。現行流程見[開發指南](../development.md)。

<a id="v1-2-0"></a>

## 1.2.0

This document is the release gate for DNS Shield 1.2.0 (`versionCode 3`). The release-candidate PR intentionally adds no new VPN or DNS runtime behavior.

### Release highlights

- Production Public Suffix List packaging and contract verification.
- Lifecycle-scoped PSL loading only when a validated app-private `blocklists/active.bin` needs parent-domain matching.
- Bounded parent-domain matching for compiled blocklists without changing exact allowlist semantics or built-in matcher behavior.
- Fail-safe fallback: missing or malformed compiled blocklists keep built-in protection; PSL load failure keeps a validated compiled blocklist exact-only.
- Reduced steady PSL-backed policy memory after the sorted-array resolver work.
- Repeatable Android instrumentation benchmarks for production asset loading and runtime policy composition.

### PR #26 device characterization

ASUS_Z01RD / Android 10 / API 29 / arm64-v8a, two independent runs:

- missing-`active.bin` assembly p95: 0.173 / 0.166 ms
- first active-policy assembly: 273.798 / 270.161 ms
- cached active-policy assembly p95: 0.972 / 0.970 ms
- parent-aware lookup p95: 18.010 / 17.525 us
- steady exact-policy heap median: 16 / 16 KiB
- steady parent-policy heap median: 576 / 0 KiB
- steady parent incremental heap median: 560 / 0 KiB

The steady heap metric is GC-assisted; the zero result is measurement noise rather than zero memory. The repeated runs support a low-memory steady-state characterization and close the PSL optimization gate for this release.

### Automated release gate

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

`release.ps1` now runs the same repository verification before attempting the signed release build.

### Manual smoke checklist

Before tagging `v1.2.0`:

- [ ] Upgrade a signed 1.1.0 installation to the 1.2.0 release candidate without uninstalling; confirm settings remain available.
- [ ] Start, stop, and restart DNS Shield; confirm the foreground VPN notification and running state stay consistent.
- [ ] Resolve a normal domain through at least one built-in DoH resolver.
- [ ] Confirm a known built-in blocked domain receives the expected blocked/NXDOMAIN behavior.
- [ ] Switch DNS resolver while the VPN is running and confirm subsequent queries use the new resolver without stale cached state.
- [ ] Exercise a custom DNS server so the UDP path still resolves normally.
- [ ] Confirm an excluded App remains outside the DNS Shield VPN path.
- [ ] Background and foreground the UI; confirm statistics/log display resumes without affecting DNS resolution.
- [ ] Turn the screen off and wake the device; confirm the VPN continues to resolve DNS after wake.
- [ ] Switch between available network transports (for example Wi-Fi and mobile data) and confirm DNS recovers.
- [ ] With no `blocklists/active.bin`, confirm built-in-only behavior.
- [ ] If using a test fixture, confirm a valid `active.bin` blocks a subdomain through bounded parent matching and a malformed artifact safely falls back.
- [ ] Complete one 8-10 hour same-device battery observation and compare against the current approximately 27% / 10-hour reference rather than accepting a clear regression.

### Signed artifact gate

With the existing release signing key configured, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\release.ps1
```

Before publishing GitHub Release `v1.2.0`:

- [ ] `app/build/outputs/apk/release/app-release.apk` exists.
- [ ] `apksigner verify --verbose --print-certs` passes through `release.ps1`.
- [ ] `app-release.apk.sha256` is generated and matches the APK.
- [ ] The signed APK upgrades the existing 1.1.0 installation successfully.
- [ ] Attach the APK and checksum to the GitHub Release and use the release highlights above as the release-note basis.

<a id="v1-2-1"></a>

## 1.2.1

This document is the release gate for DNS Shield 1.2.1 (`versionCode 4`).

### Release highlights

- Cache DNS query-key hashes used by response caching and in-flight deduplication.
- Stamp the client transaction ID while building the IPv4/UDP response packet, avoiding an intermediate DNS response copy.
- Remove allocation-heavy label splitting and redundant normalization from built-in domain matching.
- Align OkHttp per-host concurrency with the service's 24-query throttle.
- Bootstrap built-in DoH endpoint hostnames without routing their lookup recursively through the VPN.

### Performance evidence

The paired JVM benchmark on the release-candidate source measured:

- built-in matcher: 253.13 to 237.02 ns/query (1.07x; directional only)
- query-key hash: 244.08 to 74.13 ns/query (3.29x)

The repository also includes Android benchmarks for the same hot paths, response packet construction, and DoH bursts. These microbenchmarks exclude VPN, network, cache-lock, and UI logging latency.

The rejected 64-slot coroutine limiter was tested separately with three 256-query TUN bursts on an ASUS_Z01RD. It capped the coroutine peak at 64 but increased median completion time from 1,883 ms to 2,097 ms (11.4%) and did not improve response count, so it is not part of this release.

### Automated release gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\release.ps1
```

### Manual smoke checklist

Before tagging `v1.2.1`:

- [x] Upgrade the signed 1.2.0 installation without uninstalling; the package first-install time and selected Google DNS setting were preserved.
- [x] Start, stop, and restart DNS Shield; the VPN network appeared and disappeared consistently.
- [x] Resolve normal domains through Google DoH with Private DNS disabled for the test.
- [x] Confirm `ads.example.com` receives the expected NXDOMAIN response.
- [ ] Exercise a custom DNS server so the protected UDP path still resolves normally.
- [x] Confirm cached and shared responses preserve the requesting client's DNS transaction ID through unit and packet-equivalence tests.
- [x] Background and foreground the UI; DNS resolution remained active and the UI resumed normally.
- [x] Confirm the signed APK reports `versionName 1.2.1` and `versionCode 4` after the in-place upgrade.

### Signed artifact gate

- [x] `app/build/outputs/apk/release/app-release.apk` exists.
- [x] `apksigner verify --verbose --print-certs` passes through `release.ps1`.
- [x] `app-release.apk.sha256` exists and matches the APK.
- [x] The signed APK upgrades the installed 1.2.0 build successfully.
- [ ] Attach both files to GitHub Release `v1.2.1`.
