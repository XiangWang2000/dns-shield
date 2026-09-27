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
