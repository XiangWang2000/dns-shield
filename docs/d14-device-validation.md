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

The integrated short run below records a real Wi-Fi handoff. The long power A/B remains pending.

## Integrated D09/D11 run on Android 10 (2026-09-29)

The existing D14 worktree now includes D09 network recovery and the merged D06/D11 DNS path. The isolated ASUS_Z01RD / Android 10 run `mumn4fdp` passed (`OK (1 test)`, 70.836 seconds). The raw ignored report is `captures/d14/d14-e2e-mumn4fdp.json`, SHA-256 `4C03A98CB69BD42E0E3E2EF26BDDC6DB246C787B01C90063060E51FA231C88FF`; the instrumentation output is `captures/d14-d09-device-instrument-rerun.txt`.

Eight identical clients shared one fake-upstream request and produced seven coalesced-wait samples (p50/p95/p99 428/432/432 ms). Cache hit, block, unique miss, burst, total-upstream-failure SERVFAIL, UDP fallback, and service cleanup passed. Wi-Fi off/on changed the selected validated network ID from `1614018433037` to `1622608367629`; the service observed five transitions and re-queried the previously cached name. Diagnostics ended with 43 received, 35 resolved, one blocked, one expected failed, six rejected (all `INVALID_VERSION`), zero client timeouts, and no pending requests. The test restored Wi-Fi and stopped the VPN; the two isolated packages were then removed while the production package remained installed.

The first integrated run `mummyw78` failed only the coalesced-wait assertion: its early diagnostics-flow snapshot had seven coalesced requests but zero wait samples, while the final raw snapshot already contained seven samples. The test now waits for the wait samples before taking its scenario snapshot. Its raw ignored report is `captures/d14/d14-e2e-mummyw78.json`, SHA-256 `2A6A2DACBC0F05F2352A675840FEEB30B801E511DCA5A6BF53C79C8E9CCF1CF3`; this failed run is retained as diagnostic evidence, not counted as a pass.

This is one short candidate run with the handset AC powered. No paired baseline/candidate latency comparison or 8–10 hour idle/active battery A/B was performed. The reported latency values are workload observations, not improvement estimates. Keep D14 in progress until those comparisons are measured and reviewed.

## Android 10 repeated short runs on 2026-10-01 UTC

Candidate `09f4c23` passed three runs on ASUS_Z01RD / Android 10 with IPv4 Wi-Fi. The phone was AC powered. Each run used the real app TUN, loopback fake upstream, and actual Wi-Fi off/on handoff. No client DNS timeout occurred; cache, blocking, misses, eight-client coalescing, burst, expected all-upstream-failure SERVFAIL, fallback, and cleanup assertions passed. Each handoff observed five service transitions and re-queried the cached name.

| Run | Service startup ms | Cache hit ms | Unique miss p95 ms | Burst p95 ms | Post-handoff query ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| muppx2id | 625.63 | 1.12 | 46.71 | 17.62 | 34.74 |
| muppz5p5 | 556.11 | 2.62 | 83.25 | 57.38 | 22.29 |
| muppzo35 | 550.24 | 2.42 | 67.27 | 47.81 | 27.31 |

Raw ignored reports: `captures/d14/d14-e2e-{muppx2id,muppz5p5,muppzo35}.json`; instrumentation: `captures/d14-android10-20261001-run{1,2,3}.txt`. The first run took 85.028 seconds because the operator waited for its network prompt; the subsequent runs detected the prompt in logcat and took 18.141 and 16.565 seconds. The runner buffers `println` output until completion, so host stdout is unsuitable for live prompt detection. A host report-extraction error after run 1 was corrected by reading its private JSON file; the instrumentation itself passed. Preserve that distinction.

Diagnostics include one deliberate upstream failure per run plus 5/3/4 rejected non-DNS packets, all `INVALID_VERSION`; these are not unexpected client timeouts. Latencies are small-sample candidate observations, not baseline/candidate improvement estimates. No battery savings or 8-10-hour power A/B result is claimed. Both newly installed D14 packages were removed, Wi-Fi remained enabled, and production/D15 packages were preserved. D14 stays In Progress pending paired comparisons.

## Updated scoped benchmark workflow (2026-10-04; supersedes earlier Run instructions)

The short automatic workload and manual network handoff now use separate instrumentation methods and reports. Default `Run` executes only the fixed automatic workload; it never requests a radio switch. The manual method seeds/verifies a cached answer, requests a real handoff, verifies cache requery, then cleans up. Its waiting time is labeled `manual_network_handoff` and is not compared as automatic CPU/latency data.

```powershell
.\tools\d14-device-test.ps1 -Action Run -Serial JCAZB7604377HFP -BenchmarkLabel baseline
.\tools\d14-device-test.ps1 -Action Run -Serial JCAZB7604377HFP -BenchmarkLabel candidate
.\tools\d14-device-test.ps1 -Action Run -Serial JCAZB7604377HFP -ManualNetworkHandoff -BenchmarkLabel candidate
```

The script records source revision (with `+dirty` if tracked changes are present) and the supplied label. Reports add `run_kind`, `benchmark_label`, `source_revision` and explicitly identify the protected loopback UDP workload. It does not measure successful DoH connection/TLS counts; the independent pinned-version HTTPS/EventListener comparison is documented with R03/R06 and must not be relabeled as this device TUN benchmark.

For manual handoff, watch `D14_NETWORK_SWITCH_REQUIRED` in the target process's logcat before changing Wi-Fi. Instrumentation stdout may be buffered until completion. `Run` now requires an `OK (N test[s])` result and absence of explicit failure markers; `INSTRUMENTATION_CODE: -1` is Android's successful completion code and is not itself a failure.

Following updated #47/#72, paired baseline/candidate repeats on the same device/fixed automatic workload remain required; the separate manual case is acceptance coverage. The unavailable 8–10 hour power A/B is tracked in #73 and is deferred at the user's request. It is not a hard blocker for the scoped core completion; no power savings claim is made. New split workload results are not yet recorded in this section.
Split-workload validation: `verify.ps1` PASS and isolated D14 app/test build PASS. Script syntax and `git diff --check` PASS. The baseline APK/harness will be retained with SHA256 for paired automatic runs against the common #72 candidate; split manual handoff is verified separately. Earlier mixed workload results remain historical and are not reused as the new paired baseline.