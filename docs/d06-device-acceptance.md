# D06 diagnostics acceptance

## Integrated behavior

D06 is integrated with the D05/D08/D10/D11 mainline DNS pipeline. One client DNS request starts one diagnostics request for UDP or TCP. A terminal result is recorded once, including cancellation and overload; cache hits, coalescing, transport attempts, and fallback are separate classifications. The response commit still checks resolver state under the DNS state lock and writes immutable bytes outside that lock. Strict-mode plaintext checks remain in front of UDP and TCP upstream I/O.

DoH calls queued counts calls accepted by OkHttp's queue, not confirmed wire writes. UDP attempts counts completed socket sends; TCP attempts count permitted query-frame sends. Fallback counts begin only after the current resolver and strict-mode gates allow the path. The 128-sample latency window and foreground-only batched Flow refresh do not retain an unbounded per-domain history. Saved traffic remains labeled as an estimate.

## Local and Android 10 device verification, 2026-09-28

- verify.ps1 passed after integration, including Python tests, packaged assets, JVM tests, lint, Debug/AndroidTest APKs, and isolated D04 device-test APKs. Final verification after the last source/test edit passed: 29 Python tests and 222 JVM tests across 44 suites, plus assets, lint, and APK builds.
- On ASUS_Z01RD, Android 10, the isolated .d04test package ran DnsDiagnosticsDeviceTest.backgroundQueryAppearsWhenDashboardReturns: 1/1 passed in 9.747 seconds. The test opens the rendered Compose diagnostics card, clears session totals, backgrounds the activity, sends a blocked DNS query through the real TCP/TUN path, confirms the diagnostics Flow remains unchanged while backgrounded, then resumes the dashboard and matches rendered totals to the service snapshot.
- The same integrated APK ran DnsTcpTunTest: 4/4 passed in 15.846 seconds, covering real TUN TCP frames/half-close/stop, UDP truncation to TCP and shared cache, 32-session capacity/overflow, and idle closure.
- The isolated .d08test package then ran DohTlsFallbackInstrumentedTest 4/4 and DnsUpstreamTcpTunInstrumentedTest 1/1 together: 5/5 passed in 16.395 seconds. Invalid certificates and slow TLS handshakes preserve strict zero matching plaintext UDP, while allowed fallback sends one matching UDP query; TC-to-TCP and shared full-answer cache also passed. The first attempt failed before TLS setup because this worktree lacked the intentionally ignored disposable PKCS#12 fixture. The local fixture was copied from the prior D11 worktree, confirmed ignored, packaged into the test APK, and the complete run passed. Raw output: ignored captures/d06-device-strict-tcp-final.txt.
- The earlier D14 physical run mucl1t9b checked 42 received, 5 rejected, a parser-reason count of 5, and terminal conservation. That run was on an earlier D06 integration head; it supports the original workload scenarios but does not substitute for this final-head UI run.
- Raw local outputs: ignored captures/d06-device-ui-test.txt, captures/d06-device-tcp-test.txt, and captures/d06-d11-verify.log. The test package stops its VPN in finally; no production application data was replaced.

## Evidence boundary

These physical checks use Android 10 and the available IPv4 Wi-Fi. Android 15 was not rerun on the final integrated D06 head. The D14 long power A/B remains separate work. Before declaring D06 Done, require successful exact-head Windows CI and a review of the current PR/Issue/Project state.
