# D04 lifecycle fault validation

The production service uses `establishVpnTunnel`, `runVpnTunnelReader`, and
`closeVpnTunnelThenJoin` for null establishment, reader termination, and shutdown.
Unexpected EOF/read errors report failure while active; EOF caused by shutdown
does not publish a stale failure. Descriptor close precedes session join.

Validation on 2026-09-26:
- `verify.ps1`: 151 JVM tests (30 suites), 29 Python tests, lint, debug and isolated
  D04 APK builds passed. `VpnTunnelIoTest`: 5/5.
- ASUS_Z01RD Android 10: `VpnTunnelIoInstrumentedTest` passed 3/3 in 0.056 seconds:
  actual ParcelFileDescriptor socket EOF, closed-descriptor read error, and close
  interrupting a blocked read before join. Raw local record:
  `captures/d04-pfd-device.txt`.

Run the isolated D04 instrumentation package with the exact class
`io.github.xiangwang2000.dnsshield.service.VpnTunnelIoInstrumentedTest`.
These tests use real Android descriptors but do not inject faults into a live
VPN interface or prove notification/UI behavior during every platform fault.
Existing real-service start/stop/restart/revoke evidence remains separate.

## D07 main integration on Android 15 emulator (2026-09-27)

The D04 branch merged main after D07 PR #55 (`3d52a6c`). The merge keeps D04's
serialized lifecycle and generation checks, D07's user-rule reload mutex and
Room policy rules, and reloads rules again after VPN establishment before
starting the TUN reader. A live rule change checks the service lifecycle flow
directly so a delayed ViewModel collection cannot skip the reload.

With Android Studio JBR, `verify.ps1` passed: 29 Python tests, production
assets, 168 JVM tests in 33 suites with zero failures/errors, lint, Debug
and D04 isolated APK builds. Both D07 isolated APKs built separately. On
`dns_shield_api35`, merged D07 migration/persistence/live TUN passed 3/3,
including BLOCK -> ALLOW -> BLOCK and cache invalidation. D04 real PFD
faults and rapid start/stop/restart passed 5/5 on a fresh `.d04test` install.
Raw ignored outputs: `captures/d04-d07-verify-final.log`,
`captures/d04-d07-api35-instrument.txt`, and
`captures/d04-d07-api35-lifecycle-clean.txt`.

An initial D04 emulator run passed 4/5; start timed out because a previously
installed `.d04test` package from a later integration had a Room v3 database,
while this D04/D07 build is v2. Logcat identified the missing 3 -> 2 downgrade.
Only the isolated `.d04test` and test package were reinstalled, then 5/5 passed.
This was stale test data, not a production migration. No new physical-device
run was possible. The remaining live VPN fault, FD-count and UI/notification
matrix is still unverified; Issue #37 and PR #52 stay In Progress / Draft.
