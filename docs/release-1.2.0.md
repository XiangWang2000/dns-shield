# DNS Shield 1.2.0 Release Candidate

This document is the release gate for DNS Shield 1.2.0 (`versionCode 3`). The release-candidate PR intentionally adds no new VPN or DNS runtime behavior.

## Release highlights

- Production Public Suffix List packaging and contract verification.
- Lifecycle-scoped PSL loading only when a validated app-private `blocklists/active.bin` needs parent-domain matching.
- Bounded parent-domain matching for compiled blocklists without changing exact allowlist semantics or built-in matcher behavior.
- Fail-safe fallback: missing or malformed compiled blocklists keep built-in protection; PSL load failure keeps a validated compiled blocklist exact-only.
- Reduced steady PSL-backed policy memory after the sorted-array resolver work.
- Repeatable Android instrumentation benchmarks for production asset loading and runtime policy composition.

## PR #26 device characterization

ASUS_Z01RD / Android 10 / API 29 / arm64-v8a, two independent runs:

- missing-`active.bin` assembly p95: 0.173 / 0.166 ms
- first active-policy assembly: 273.798 / 270.161 ms
- cached active-policy assembly p95: 0.972 / 0.970 ms
- parent-aware lookup p95: 18.010 / 17.525 us
- steady exact-policy heap median: 16 / 16 KiB
- steady parent-policy heap median: 576 / 0 KiB
- steady parent incremental heap median: 560 / 0 KiB

The steady heap metric is GC-assisted; the zero result is measurement noise rather than zero memory. The repeated runs support a low-memory steady-state characterization and close the PSL optimization gate for this release.

## Automated release gate

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

`release.ps1` now runs the same repository verification before attempting the signed release build.

## Manual smoke checklist

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

## Signed artifact gate

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
