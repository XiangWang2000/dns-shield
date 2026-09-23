# D14 device validation

The D14 build is isolated as `io.github.xiangwang2000.dnsshield.d14test`; release keeps the production application ID. The D14 VPN is restricted to the `.d14test` app and its instrumentation package with `addAllowedApplication`, so other apps on the handset do not use the test tunnel. The D14 service accepts only a loopback IP literal and a valid test port. Debug and release builds do not read the D14 preferences and continue to use DNS port 53.

## Build and run the short end-to-end workload

Run from the repository root on Windows:

```powershell
.\tools\d14-device-test.ps1 -Action Build
.\tools\d14-device-test.ps1 -Action Install
.\tools\d14-device-test.ps1 -Action Run
```

The script requires exactly one connected ADB device unless `-Serial` is supplied. `Install` validates Gradle's APK metadata against the exact `.d14test` package before calling `adb install -r`; it never uninstalls or updates the production package. `Uninstall` targets only `.d14test`:

```powershell
.\tools\d14-device-test.ps1 -Action Uninstall
```

`Run` launches the D14 instrumentation class. If Android has not authorized the isolated package as a VPN, the test opens the system consent activity and waits up to two minutes for the user to approve it. The test checks the permission and waits until `DnsVpnService` reports `RUNNING`; it does not bypass consent.

The client sends UDP DNS packets to `10.0.0.1:53`, which is routed into the production TUN packet loop. The service's protected upstream socket targets the fake DNS server at `127.0.0.1` and its ephemeral port. The workload covers unique misses, a cache hit, a built-in blocked domain, coalesced misses, a unique-query burst, UDP fallback, and all fake upstream attempts dropping packets. It then prompts for a real network handoff and verifies that the service observed it, invalidated its DNS cache, and resolved a fresh query. It records per-scenario latency samples and p50/p95/p99, DNS diagnostics, error and client timeout rates, upstream request counts, coalesced-wait samples, app-process-to-VPN startup, policy assembly, heap, PSS, GC, and process CPU time plus one-core-equivalent utilization.

The test stores its JSON report in the D14 app's private files directory. The script reads it from the debuggable test package and saves it under `captures/d14/`. The coalesced-wait metric covers only callers waiting on an identical in-flight DNS query; it is not a measurement of the total worker or admission queue. A short run establishes that the harness works and provides an initial sample. Repeat runs are required before comparing latency distributions.

## Network handoff and power A/B

During `Run`, keep USB connected and switch Wi-Fi off and back on (or hand off between Wi-Fi and cellular) when the instrumentation prints `D14_NETWORK_SWITCH_REQUIRED`. The test first records the service-selected validated physical network, then waits up to 90 seconds for a different selected network ID or transport and verifies that selection is still validated. It checks that the previously cached name causes a new fake-upstream request and records both network identities in the report.

The 8–10 hour power A/B remains a separate measurement. Use the same handset, app build, network, screen state, and workload for both runs; separate idle and active periods; start with comparable battery state; and avoid charging during either run. Preserve timestamps, battery start/end readings, device/build details, and the generated D14 workload reports. Do not infer power savings from the short DNS latency workload or from a microbenchmark.

Neither the real network handoff nor the long power A/B is reported as passed until it has been run on the device and its evidence has been saved.
