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

## Remaining at the UDP lock checkpoint

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

## Integrated D11 acceptance checkpoint — 2026-09-27

D05's latest D04 tunnel I/O helper is merged into D11 at 60ec52e. The reader
keeps native TCP ownership active until before the TUN output stream closes.
D08's later TLS through-TUN test is also integrated; its isolated build uses
the existing test-only loopback UDP port setting. The disposable PKCS12
fixture is generated locally and ignored.

A real TUN capacity test exposed Hev's limit semantics: it evicts the oldest
session when count reaches the configured threshold. The previous threshold
of 32 therefore retained only 31 sessions. Configuring 33 retains 32; the
Android 15 test verified the 32nd client, overflow behavior and continued
service for an active connection. The real TUN idle test verified timeout and
a subsequent fresh client. The SOCKS shutdown path now iterates its concurrent
session set directly; a prior full verification caught a race while copying
that set to a list. The unsupported SOCKS request path now consumes known
address forms before sending rejection, avoiding Windows TCP resets with
unread request bytes.

Android 15 emulator dns_shield_api35, isolated .d04test: 9/9 tests
passed in 17.855 s (captures/d11-api35-final-device2.txt). This includes
native segment order/retransmission, malformed/reset packets, real TUN client
TCP, UDP truncation and shared full-response cache, multiple frames, half-close,
stop, capacity, idle timeout and descriptor cleanup. Isolated .d08test:
strict TLS failure sent zero plaintext UDP queries, while allowed fallback sent
one matching UDP query; 2/2 passed in 2.137 s
(captures/d11-api35-d08-final.txt). The first D08 emulator attempt
timed out waiting for Android VPN consent; granting the test package VPN
permission and rerunning passed. The earlier Android 10 physical-device D11
4/4 result remains separate evidence.

Final local verify.ps1 passed 29 Python tests, both production assets,
201 JVM tests with zero failures/errors, Android lint, and Debug plus isolated
D04 app/test APK builds (captures/d11-final-integrated-verify2.log).
D08 isolated app/test APKs built separately with the local test certificate
(captures/d11-d08-final-apk.log). The immediately preceding verification
caught the SOCKS concurrent-close race; the final run passed after its fix.

Remaining release steps: check CI on the pushed head, refresh the PR and issue
descriptions, review dependency PR order and merge readiness. This checkpoint
does not merge main or claim the broader D03/D04/D05/D08 network and UI matrices
are complete.
## D10 integration and Android 10 rerun — 2026-09-28

D10 PR #60 merged into main as `6c71b12`; its head `0194b50` passed exact-head
Windows CI run 36378746434, full `verify.ps1`, and the Android 10 TUN
TC→upstream TCP/cache test. The existing D11 worktree merged that D10 head,
retaining the D11 lock-safe response commit and plaintext fallback fence.
The merge resolved the D05/D10 test-port contract to one
`BuildConfig.DNS_UPSTREAM_PORT`: 15353 in isolated test builds and 53 in
production. Both UDP and TCP upstream endpoints now use it, including the
D11 `.d04test` and D08 `.d08test` fake servers. No local TUN TCP acceptance is
inferred from a localhost ServerSocket alone.

The integrated D11 `verify.ps1` passed: 29 Python tests, both packaged
production assets, 219 JVM tests / 43 suites, Android lint, Debug and
isolated D04 app/test APKs (`captures/d11-d10-integration-verify.log`, ignored).
The D08 isolated app/test APKs also built with the ignored disposable PKCS12
fixture (`captures/d11-d10-d08-build.log`). On ASUS_Z01RD / Android 10,
`DnsTcpTunTest` passed 4/4 in 14.923 s, including multiple framed client
queries, half-close, stop, UDP TC→TCP/full shared cache, 32-session capacity,
overflow, and idle timeout. `DohTlsFallbackInstrumentedTest` plus
`DnsUpstreamTcpTunInstrumentedTest` passed 5/5 in 15.596 s on the same
integrated service: invalid certificate/slow TLS handshake kept strict-mode
matching UDP at zero, allowed fallback sent one matching UDP query, and a
separate TC→TCP answer was cached across transaction IDs. Raw ignored logs:
`captures/d11-d10-android10-tcp-final.txt` and
`captures/d11-d10-android10-strict-tcp-final.txt`.

The D10 device test first exposed a cached transaction-ID validation issue;
D10 stamps a response copy before truncation, and D11's immutable commit also
stamps each client ID before its writer handles the response. D11's
`DnsResolvedResponseCommitterTest` retains stale-state, blocked-writer and
transaction-ID regression coverage. The D08 TLS device fixture tests a slow
handshake, not a delayed HTTP response body. The Android 15 9/9 TUN/native
and 2/2 strict-mode results above remain evidence from the previous D11 head;
they were not rerun after this D10 integration.