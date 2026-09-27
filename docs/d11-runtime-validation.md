# D11 runtime implementation and validation — 2026-09-27

PR #62 / issue #44; depends on D04, D05 and D10. This is a draft feature branch,
not a release or a completed whole-project acceptance claim.

## Implemented

- Pinned Hev e802f02bae0fc55cbf681466a60e89c2e6773401 and recursive dependencies;
  JNI bridge, NDK 27.2.12479018, arm64-v8a/armeabi-v7a/x86/x86_64 builds.
- One TUN reader demultiplexes IPv4 TCP/53 destined for 10.0.0.1 to the native
  stack through a bounded nonblocking packet socket. UDP keeps its existing path.
- Authenticated loopback SOCKS bridge only permits CONNECT to the virtual DNS
  endpoint. Native stack handles sequence/retransmission; Kotlin framing shares
  the policy, cache, admission/deadline and resolver pipeline with UDP.
- 32 native/bridge sessions, 10-second bridge timeouts, explicit stop/FD cleanup,
  and process-wide native ownership prevent overlapping native runtimes.
- Resolved TCP and UDP response I/O occurs outside the resolver-state lock.
  UDP truncation remains at its packet writer; full TCP answers remain available
  to both cache consumers.
- Windows symlink placeholders are converted to forwarding includes only in the
  generated build copy. Upstream sample JNI is excluded. Dependency notices are
  packaged in `app/src/main/assets/native-tcp-NOTICES.txt`.

## Observed validation

ASUS_Z01RD / Android 10, isolated `.d04test`: 4/4 tests passed in 3.025 s
(`captures/d11-complete-device.txt`, local ignored evidence).
`DnsTcpTunTest` covers real Android sockets through VPN, multiple frames,
half-close/EOF, stop with an idle TCP connection, upstream UDP TC -> TCP full
answer >2000 bytes, client UDP truncation -> TCP retry and shared full-response
cache with different transaction IDs. The fake upstream sees one target UDP and
one TCP query. UDP clients retry within a bounded deadline during VPN startup.
`NativeDnsTcpRuntimeTest` covers native SYN/data, reordered/duplicate segments,
FIN, reset/malformed input and repeated native startup/shutdown.

This exposed a production D10 bug: `protect(Socket)` failed before the unbound
socket had an allocated descriptor. Binding an ephemeral local endpoint before
protection fixed it; a JVM regression checks bound-before-prepare, pre-connect.
The same fix is committed on D10 as 403b266.

`verify.ps1` passed after final changes: 29 Python tests, assets, 192 JVM tests,
lint and APK builds. The seven SOCKS tests include session capacity, credential/
destination rejection, idle/malformed frames and shutdown. A full listener may
reject before accept on Windows; the capacity test verifies the first admitted
connection remains usable. Earlier Android 15 emulator native/basic TUN tests
passed 3/3; the final large-response/fix combination has not been rerun there.

## Remaining before merge/readiness

- Integrate latest D04/D05 helper changes and later validated D08 dependency
  updates, resolving service lifecycle changes and rerunning affected checks.
- Complete independent review findings and real-TUN capacity-exhaustion/idle
  acceptance; current capacity/idle coverage is at the SOCKS boundary.
- Recheck final CI and dependency order before merging. No main merge or release
  is included in this checkpoint. Broader network/power matrices remain separate.

## UDP response lock review resolution

The inherited UDP response writer performed blocking TUN I/O under
`dnsStateLock` (`sendResolvedResponseIfCurrent` -> `sendResponsePacket`), which
could delay resolver and policy updates. The response path now checks the
resolver generation and policy assembly and commits an immutable response with
the client's transaction ID under that lock. TUN I/O runs after the commit,
outside the lock, matching the existing TCP handoff. An update before commit
rejects the old response and returns SERVFAIL; a response committed before an
update may finish writing afterward as an in-flight response. The separate
plaintext fallback fence still prevents new UDP/TCP upstream plaintext sends
after strict mode takes effect.

`DnsResolvedResponseCommitterTest` reproduced the lock blockage before the fix
and passed afterward. It also checks stale-response rejection during a blocked
write and transaction-ID preservation. Existing strict-mode fence and transport
tests passed. Full `verify.ps1` passed with 195 JVM tests, zero failures/errors,
lint and APK builds (`captures/d11-udp-lock-verify.log`, local ignored evidence).
This slice does not complete the remaining D11 integration or device matrix.
