# R17–R19 background work validation

Date: 2026-10-09. Issues: [#95](https://github.com/XiangWang2000/dns-shield/issues/95), [#96](https://github.com/XiangWang2000/dns-shield/issues/96), [#97](https://github.com/XiangWang2000/dns-shield/issues/97).

Source: `eba51bb048f7d033b7df89731084eab1ec81b9e4`; baseline main: `ee16fb40d59849ab0960d2e99cf5157966fec1f4`. Later documentation commits do not change the tested application source. The related [R20 evaluation](issue98-r20-response-parse-evaluation.md) retains the production parser.

## Cause and changes

- R17: successful UDP/TCP fallback messages bypassed the background log gate. Every success could format timestamps, append a log and write Logcat. `BackgroundDnsLogPolicy` emits the first background plaintext result immediately, then coalesces plaintext successes and transport/resolver transitions under one 60-second monotonic window. The next successful query emits a due summary; no timer runs. Repeated DoH successes are quiet. Foreground logging does not reset the background window. Suppressed messages are not formatted. A summary describes the latest observed outcome, not continuous recovery.
- R18: every blocked event copied and published the newest 100 events even in the background. `DnsDecisionEventBuffer` retains facts in a bounded deque without background copies, publication or timers. Foreground entry publishes the latest immutable snapshot immediately; subsequent events use one 300-ms batch, including the last event. Clear, visibility and publication share one lock, and generation tokens prevent a canceled flush from publishing or clearing a replacement batch. Existing counters, rule operations and DNS decisions remain in their original paths.
- R19: sequential primary and secondary UDP attempts each allocated a 4,097-byte receive buffer. They now lazily share one buffer within that single fallback call. Concurrent calls remain independent, and returned responses are copied. There is no global buffer or pool. The extra overflow byte, validation, deadline and cancellation semantics remain intact.

## Host verification

Windows with Android Studio JBR. Commands ran from the project root:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat --no-daemon --console=plain :app:testDebugUnitTest --tests '*BackgroundDnsLogPolicyTest' --tests '*DnsDecisionEventBufferTest' --tests '*DnsUdpUpstreamClientTest' --tests '*DnsResponseParseBenchmarkTest'
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

- Focused run: 26 tests, no failures/errors/skips; elapsed 40.323 seconds.
- Full `verify.ps1`: exit 0, elapsed 301.484 seconds; 37 Python and 322 JVM tests in 52 suites, no failures/errors/skips. All required APK build groups and lint passed. No compiler warning was emitted in this run; unchanged cached tasks are not a fresh warning audit.
- Controlled-clock log tests cover 10,000 UDP/TCP outcomes, transport/resolver alternation, DoH recovery and foreground/background changes without suppressed formatting.
- Buffer tests cover 10,000 background events, bounded foreground batches, immutable snapshots, concurrent clear/record/visibility, and a deterministically resumed noncancellable stale flush.
- UDP tests count allocations for primary timeout/secondary success and both failures, independent concurrent calls, and response-copy ownership. Both-attempt receive-buffer bytes are 8,194 before versus 4,097 now; these figures exclude all other query allocations.
- Independent source review found no remaining concrete R17/R18/R19 production defect. Review prompted alignment of the Android old-reference benchmark's lock, clock and ID operations before the final source commit.

Initial focused failures were harness defects: an invalid TC fixture declared a missing answer, and an XOR benchmark sink canceled to zero. Both were corrected without relaxing production validation; the final focused and full runs above passed.

## API35 integration

AVD `dns_shield_api35`, serial `emulator-5556`; isolated `.d08test` packages. The local APK SHA-256 values match the installed `base.apk` files:

| APK | SHA-256 |
|---|---|
| D08 app | `2c83fc39d3111a201061d519a72cdb22a8c178f4fcd26b02bbeb140f72185357` |
| D08 instrumentation | `0e60b1f9ab4a5db04fdb7222bd95bc5249b39c20bacc07a2da07069773066366` |

`BackgroundDiagnosticsInstrumentedTest`: 2/2 passed, 3.818 seconds. The service recorder → companion event flow → real ViewModel state path verifies background silence, immediate newest-100 publication on foreground entry, and no resurrection after clear. It does not write user rules or count synthetic records as actual DNS requests.

Safety confirmation: 11/11 passed in 49.594 seconds, with no skipped tests. Together with the new class, 13 selected API35 tests passed. The selected 11 existing tests exercise real TUN delivery, same-resolver/equal-row ALLOW convergence, resolver round-trip and stale intents, held plaintext send callbacks, bootstrap-specific DoH backoff, late old-generation failures, invalid TLS and slow-handshake ALLOW/STRICT behavior, and ViewModel resolver selection.

The first 11-case run had one failure: the first backoff query received SERVFAIL; its service log explicitly recorded admission-capacity rejection. An unchanged-APK isolated rerun passed 1/1. This establishes the observed rejection branch, not its underlying load source. A complete unchanged-APK confirmation was required; no retry or weakened assertion was added to the tests.

```powershell
$adb = 'C:\Users\User\AppData\Local\Android\Sdk\platform-tools\adb.exe'
& $adb -s emulator-5556 install -r app\build\outputs\apk\d08test\app-d08test.apk
& $adb -s emulator-5556 install -r app\build\outputs\apk\androidTest\d08test\app-d08test-androidTest.apk
& $adb -s emulator-5556 shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.BackgroundDiagnosticsInstrumentedTest io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
& $adb -s emulator-5556 shell am instrument --user 0 -w -r -e class io.github.xiangwang2000.dnsshield.service.DohFailureBackoffTunInstrumentedTest,io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#strictModeReturnsServFailWithoutUdpAfterInvalidTlsCertificate,io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterTheSameInvalidTlsCertificate,io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterSlowDohHandshake,io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#strictModeDoesNotUseUdpAfterSlowDohHandshake,io.github.xiangwang2000.dnsshield.service.ResolverSelectionTunInstrumentedTest io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

Local raw evidence is retained under ignored `captures/`: `r17-r18-api35-background-diagnostics.txt`, `r17-r18-api35-benchmark.jsonl`, `r17-r20-api35-safety-regression.txt`, `r17-r20-api35-backoff-diagnostic.txt`, `r17-r20-api35-backoff-logcat.txt`, and `r17-r20-api35-safety-confirmation.txt`.

## API35 fixed-workload component measurements

One warmup pair and three measured pairs, alternating old/current, current/old, old/current. Each blocked-event sample records 10,000 events with the same domains/reasons, clock and ID operations; the old reference models the original synchronized list copy plus StateFlow publication. Each successful-log sample processes 5,000 UDP/TCP outcomes within one controlled window. Its old reference models timestamp formatting and the in-memory sink, not Logcat or networking.

The current log workload formats/emits one detail. One additional outcome outside the timed workload crosses the interval and verifies one summary, for two total sink calls including that probe. The old workload formats/emits 5,000 details. Background blocked-event snapshots/publications drop from 10,000 to zero; foreground entry then publishes one newest-100 snapshot.

### Medians per sample

| Component | Implementation | Wall ms | Instrumentation thread CPU ms | Process ART allocated bytes delta | Process ART GC count delta |
|---|---|---:|---:|---:|---:|
| 10,000 blocked events | Old reference | 180.887 | 175.242 | 6,520,832 | 0 |
| 10,000 blocked events | Current | 80.021 | 78.181 | 2,228,224 | 0 |
| 5,000 successful outcomes | Old reference | 403.027 | 370.956 | 24,982,240 | 7 |
| 5,000 successful outcomes | Current | 14.456 | 13.408 | 295,760 | 1 |

### All measured samples

| Component | Pair | Implementation | Wall ns | Thread CPU ns | Process allocated bytes delta | Process GC delta |
|---|---:|---|---:|---:|---:|---:|
| Blocked events | 0 | Old reference | 155187046 | 153076165 | 6520832 | 0 |
| Blocked events | 0 | Current | 80021209 | 78180621 | 2260992 | 0 |
| Blocked events | 1 | Current | 57071644 | 54406678 | 2228224 | 0 |
| Blocked events | 1 | Old reference | 180887122 | 175241723 | 6520832 | 0 |
| Blocked events | 2 | Old reference | 198368950 | 187030666 | 6553600 | 0 |
| Blocked events | 2 | Current | 86615581 | 85393638 | 2228224 | 0 |
| Successful outcomes | 0 | Old reference | 466376163 | 427885057 | 24949488 | 7 |
| Successful outcomes | 0 | Current | 19044440 | 13408113 | 295760 | 1 |
| Successful outcomes | 1 | Current | 14455905 | 13562734 | 262992 | 0 |
| Successful outcomes | 1 | Old reference | 310636027 | 272943967 | 25047776 | 8 |
| Successful outcomes | 2 | Old reference | 403027489 | 370956448 | 24982240 | 7 |
| Successful outcomes | 2 | Current | 13154426 | 10603199 | 295760 | 1 |

Thread CPU uses `Debug.threadCpuTimeNanos`; allocation and GC use ART process-wide counters and can include other threads and instrumentation. These are small same-AVD component samples, with no performance pass/fail threshold. They do not measure end-to-end DNS latency, whole-app CPU, sustained throughput or battery savings. The R20 parse measurements are JVM-only and cannot be substituted for Android parser measurements.

## Limits and follow-up

[#73](https://github.com/XiangWang2000/dns-shield/issues/73) remains deferred for special networks, device/OEM coverage, true low-memory reclamation and unplugged long-duration power A/B. No release APK, version bump, physical-device claim, parser fast path or policy-safety relaxation is included here.
