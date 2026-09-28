# D10 upstream TCP and large-answer acceptance

Run date: 2026-09-28
Device: ASUS_Z01RD, Android 10 (API 29)
Branch: `codex/d10-upstream-tcp`, after integrating D05/D08 main

## Real TUN test

`DnsUpstreamTcpTunInstrumentedTest` uses the isolated `.d08test` package and
local fake UDP/TCP upstream on 127.0.0.2:15353. The DNS client sends an IPv4
UDP query through the running VPN/TUN without EDNS. The fake UDP upstream
replies with TC=1. The service retries the same upstream over TCP/53 within
the original deadline; the test TCP server splits the framed reply into two
writes and returns an 18-record TXT response larger than 512 bytes but below
the supported 4096-byte DNS-message limit. The client receives a valid
<=512-byte response cut at a whole RR boundary with TC=1. A second query
for the same key but a different transaction ID receives the cached complete
TCP result, cut again for the new client, without another upstream UDP/TCP
query. This checks that an upstream truncated UDP reply is not cached as a
complete answer.

The final instrumented run passed 1/1 in 0.946 s. Its raw local output is
`captures/d10-tcp-cache-device-final.txt` (ignored).

To repeat with a device that has granted VPN consent to `.d08test`:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat -PandroidTestBuildType=d08test :app:assembleD08test :app:assembleD08testAndroidTest
adb install -r app\build\outputs\apk\d08test\app-d08test.apk
adb install -r app\build\outputs\apk\androidTest\d08test\app-d08test-androidTest.apk
adb shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.DnsUpstreamTcpTunInstrumentedTest io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

Check the instrumentation `OK (1 test)` line. Android's `am instrument`
command can return exit code 0 even when the test output says `FAILURES`.

## Failure found and fixed

The first test fixture generated a >4096-byte TCP answer. The TCP client
correctly rejected its length; the original TC UDP answer was returned and
not cached. An existing JVM socket test checks this oversized-frame boundary.
With a legal large answer, the device test then exposed a separate cache-hit
bug: cached bytes carried the original transaction ID until packet building,
but the client truncation validator ran before that ID rewrite. It rejected
the cached response and sent SERVFAIL. `sendResponsePacket` now makes a copy
with the current transaction ID before validation/truncation. The same real
TUN test passed after the fix.

The JVM suite additionally covers oversized/short TCP frames, partial
length/body reads, timeout, UDP TC fallback, and EDNS/no-EDNS truncation.
Strict mode's zero-plaintext UDP/TCP boundary is covered by the D08 physical
TLS/TUN cases and transport-policy tests. Client-facing DNS/TCP is a separate
D11 feature; until D11 is integrated, only upstream TCP fallback is supported.