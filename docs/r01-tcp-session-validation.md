# R01 TCP session cancellation validation (#64)

Base main: `1dbd49df6a788a894c1e3e65e1b5357bb211f569`.

Root cause: `SocksDnsServer.Session.run()` had only `try/finally`. The blocking coroutine DNS handler could throw timeout/cancellation or be interrupted by `shutdownNow()`, escaping as an uncaught worker failure even though finally released resources.

The fix classifies expected timeout cancellation, cancellation, interruption and recoverable I/O at the session boundary. Interruption restores the worker interrupt flag. No catch-all `Throwable` was added; the original exactly-once `finish()` guard still owns session/socket/permit cleanup.

## Checks

- Before fix, the blocking-handler timeout regression recorded uncaught `TimeoutCancellationException`.
- `:app:testDebugUnitTest --tests 'io.github.xiangwang2000.dnsshield.service.SocksDnsServerTest'`: PASS, 11 tests. Added deterministic blocked-handler timeout, close/interruption plus fresh server restart, upstream IOException and peer RST; replacement sessions verify capacity is released.
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`: PASS (Python/assets/JVM/lint/Debug/D04 APKs).
- Android10 ASUS_Z01RD (`JCAZB7604377HFP`), isolated `.d04test` `DnsTcpTunTest`: **OK (4 tests)**, 14.783s. Real TUN multi-frame/half-close/STOP, UDP truncation -> TCP/shared cache, idle close/replacement, 32-session capacity/overflow.
- APK SHA256 `7B9B238E6C122730C1B00D761A9A75884D8B44A188139D1553C9A61173480962`.
- `git diff --check`: PASS, CRLF preserved.

Raw local ignored evidence: `captures/r01-final-verify.log`, `captures/r01-android10-tcp-tun.txt`; focused worker output and XML under app/build. This does not claim true LMK, power acceptance or common integration; #72 tracks final common candidate and #73 tracks unavailable environments. Existing D04 test package retained for planned D15 cross-VPN validation; production data preserved. No automatic merge/release.