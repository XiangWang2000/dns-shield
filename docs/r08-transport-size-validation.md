# R08 Transport Size Validation

## Supported bounds

- Client DNS query messages are limited to 4,096 wire bytes by the shared parser. This applies to queries arriving over UDP or TCP and to queries sent upstream over DoH. Larger queries are unsupported.
- UDP upstream responses remain limited to the advertised payload, clamped to 4,096 bytes. The receive buffer keeps one overflow byte so oversized non-TC datagrams can be rejected. Client UDP output remains capped by EDNS or 512 bytes and the 1,472-byte IPv4/TUN MTU budget; truncation keeps complete records and sets TC.
- A complete DNS response received over upstream TCP or DoH may be up to 65,535 bytes. TCP query frames remain limited to 4,096 bytes. DoH rejects a known content length above the limit before reading; unknown-length bodies consume at most 65,536 bytes to detect overflow.

## Cache and admission estimates

The DNS answer cache uses a 2,048,000-byte estimated-weight budget. An entry weighs the larger of 4,096 bytes or its stored response bytes plus 256 bytes of fixed entry overhead and 64 bytes per cached TTL field. The 4,096-byte floor preserves capacity for up to 500 small entries. This estimates cached response payloads and TTL metadata, not total heap or RSS. Stored query keys are separately bounded by 500 entries x 4,096 bytes = 2,048,000 wire bytes; JVM object headers, map nodes, policy references and network/TLS buffers are not included in the estimate.

Admission permits at most 24 unique in-flight leaders and eight coalesced waiters per key. That allows at most 24 x (1 leader + 8 waiters) = 216 recipient responses. At 65,535 bytes each, the recipient response payload copies total 14,155,560 bytes (about 13.5 MiB) if every recipient receives a maximum-size response. This arithmetic excludes leaders' retained results, parser objects, network buffers, TLS/HTTP buffers, and the cache; it is not a process-memory measurement.

## Focused JVM validation

On 2026-10-06, the selected JVM task passed 80 tests across 11 suites with zero failures, errors, or skips. It covered the R08 validator, TCP, UDP, DoH, response-cache, query-parser, TCP-frame, and transport-policy suites, plus VpnTunnelIoTest.

Coverage includes the 65,535/65,536-byte response boundary, full-size cache metadata and response copying, local TCP and HTTPS delivery, bounded DoH reads, malformed RDLENGTH, compression loops, legal UDP TC truncation, strict transport policy, TLS, bad framing, and cancellation.

## Common source and device regression (2026-10-06)

Baseline: merged main `f985f9b6012ecea64c09c3bbb357f2782b89fa80`. Candidate source: `fa59069c06218ee7b6e35d0f4c4bca08c99da474`, shared with the [API26 STOP repair](api26-tun-stop-validation.md). The report commit only adds documentation.

The original product code failed the enlarged real-TUN fixture on Android 10: upstream returned 30 TXT answers (>4,096 bytes), but the client TCP response was only 40 bytes. `captures/r08-large-tun-before-fix.txt` records one test/one failure, including upstream UDP=2/TCP=1. The unchanged assertion now passes with the complete answer count, UDP <=512 bytes and TC, independent transaction IDs, and one shared full-response cache hit.

| Environment | Test classes | Result |
| --- | --- | --- |
| ASUS_Z01RD, Android 10/API29, serial JCAZB7604377HFP | DnsTcpTunTest, VpnTunnelIoInstrumentedTest, R08CacheInstrumentedTest | 8/8, 16.296s |
| Same phone | DohTlsFallbackInstrumentedTest, DnsUpstreamTcpTunInstrumentedTest | 5/5, 26.399s |
| Android 8.0/API26 default x86_64 AVD, emulator-5556 | VpnTunnelIoInstrumentedTest, R08CacheInstrumentedTest | 4/4, 0.174s |
| Same API26 AVD | DnsTcpTunTest | 4/4, 16.124s |

`R08CacheInstrumentedTest` reads the actual service's Android LruCache, inserts 64 maximum-size answers and verifies weighted eviction, then inserts 501 small entries and verifies the 500-entry capacity. It restores the prior cache snapshot in finally. This tests production sizeOf wiring; the JVM estimator test alone does not establish eviction.

The final complete `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1` passed 29 Python and 283 JVM tests/48 suites, zero failures/errors/skips, assets, lint and APK checks. It includes a structurally valid EDNS-padded query at exactly 4,096 bytes and rejection at 4,097. The existing D09 allNetworks deprecation warning is retained; this slice added no warning. Raw log: `captures/r08-r10-final-verify.log`.

### Reproduction commands

Use the bundled Android Studio JBR and set ANDROID_HOME/ANDROID_SDK_ROOT to the installed SDK. Build the selected isolated test variant before each corresponding instrument command.

```powershell
.\gradlew.bat --no-daemon --console=plain -PandroidTestBuildType=d04DeviceTest :app:assembleD04DeviceTest :app:assembleD04DeviceTestAndroidTest
adb -s JCAZB7604377HFP shell am instrument -w -e class 'io.github.xiangwang2000.dnsshield.service.DnsTcpTunTest,io.github.xiangwang2000.dnsshield.service.VpnTunnelIoInstrumentedTest,io.github.xiangwang2000.dnsshield.service.R08CacheInstrumentedTest' io.github.xiangwang2000.dnsshield.d04test.test/androidx.test.runner.AndroidJUnitRunner
.\gradlew.bat --no-daemon --console=plain -PandroidTestBuildType=d08test :app:assembleD08test :app:assembleD08testAndroidTest
adb -s JCAZB7604377HFP shell am instrument -w -e class 'io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest,io.github.xiangwang2000.dnsshield.service.DnsUpstreamTcpTunInstrumentedTest' io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

### APK SHA256

| Artifact | SHA256 |
| --- | --- |
| app/build/outputs/apk/d04DeviceTest/app-d04DeviceTest.apk | `46e7279c423ab97d19a83b5664d1851cdc1780792cc4c3f3186b81c1faa12295` |
| app/build/outputs/apk/androidTest/d04DeviceTest/app-d04DeviceTest-androidTest.apk | `3afff4de687a82cd859596fd1f7de76b95ed5b39e9a091ee7e61e6ddafbf234c` |
| app/build/outputs/apk/d08test/app-d08test.apk | `6f1a24bbc249c024de43911ad8cd5c777120515e3a3d5bddee01f059d126b08d` |
| app/build/outputs/apk/androidTest/d08test/app-d08test-androidTest.apk | `ef5738e61870a8fd63b68e65afad6c268ccc05af7e79bbd63027c2af4525362b` |

### Scope and cleanup

The phone used IPv4 Wi-Fi while AC charging. This validates local fixtures and transport/policy behavior; it is not IPv6-only/NAT64, real portal, RSS or power acceptance. Client queries over 4,096 bytes remain unsupported. No shared-UDP-socket redesign or new dependency was introduced. Generation, strict-mode and send/write commit fences are unchanged.

The phone retains its pre-existing formal/D04/D15 apps and user battery exemptions; only this round's D08 app/test were removed. All isolated VPN services are stopped, Always-on is null, lockdown=0, Wi-Fi=1 and flight mode=0. The task-owned AVDs were shut down after testing; their reusable AVD data/system images and all ignored evidence remain. The API26 AVD's temporary root diagnostics were reverted to shell UID2000 before final acceptance tests. See issue #73 for the remaining environmental matrix; these tests do not close it.
