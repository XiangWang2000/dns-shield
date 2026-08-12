# DNS Shield 1.2.1 Release Candidate

This document is the release gate for DNS Shield 1.2.1 (`versionCode 4`).

## Release highlights

- Cache DNS query-key hashes used by response caching and in-flight deduplication.
- Stamp the client transaction ID while building the IPv4/UDP response packet, avoiding an intermediate DNS response copy.
- Remove allocation-heavy label splitting and redundant normalization from built-in domain matching.
- Align OkHttp per-host concurrency with the service's 24-query throttle.
- Bootstrap built-in DoH endpoint hostnames without routing their lookup recursively through the VPN.

## Performance evidence

The paired JVM benchmark on the release-candidate source measured:

- built-in matcher: 253.13 to 237.02 ns/query (1.07x; directional only)
- query-key hash: 244.08 to 74.13 ns/query (3.29x)

The repository also includes Android benchmarks for the same hot paths, response packet construction, and DoH bursts. These microbenchmarks exclude VPN, network, cache-lock, and UI logging latency.

The rejected 64-slot coroutine limiter was tested separately with three 256-query TUN bursts on an ASUS_Z01RD. It capped the coroutine peak at 64 but increased median completion time from 1,883 ms to 2,097 ms (11.4%) and did not improve response count, so it is not part of this release.

## Automated release gate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\release.ps1
```

## Manual smoke checklist

Before tagging `v1.2.1`:

- [x] Upgrade the signed 1.2.0 installation without uninstalling; the package first-install time and selected Google DNS setting were preserved.
- [x] Start, stop, and restart DNS Shield; the VPN network appeared and disappeared consistently.
- [x] Resolve normal domains through Google DoH with Private DNS disabled for the test.
- [x] Confirm `ads.example.com` receives the expected NXDOMAIN response.
- [ ] Exercise a custom DNS server so the protected UDP path still resolves normally.
- [x] Confirm cached and shared responses preserve the requesting client's DNS transaction ID through unit and packet-equivalence tests.
- [x] Background and foreground the UI; DNS resolution remained active and the UI resumed normally.
- [x] Confirm the signed APK reports `versionName 1.2.1` and `versionCode 4` after the in-place upgrade.

## Signed artifact gate

- [x] `app/build/outputs/apk/release/app-release.apk` exists.
- [x] `apksigner verify --verbose --print-certs` passes through `release.ps1`.
- [x] `app-release.apk.sha256` exists and matches the APK.
- [x] The signed APK upgrades the installed 1.2.0 build successfully.
- [ ] Attach both files to GitHub Release `v1.2.1`.
