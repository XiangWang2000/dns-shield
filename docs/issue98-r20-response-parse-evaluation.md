# Issue #98 / R20: DNS response parse evaluation

**Status:** Evaluation complete. Keep the production parser unchanged this round.

**Primary source SHA:** `eba51bb048f7d033b7df89731084eab1ec81b9e4`

**Measurement environment:** Windows, bundled Android Studio JBR; JVM component baseline only. The primary run passed 26/26 tests. Gradle elapsed time was 40.323 seconds; the benchmark test XML reports 0.581 seconds. Captured output: `captures/r20-response-parse-final-jvm-output.txt` (ignored local evidence).

## Question

Measure the current DNS response path before considering parser or validation changes. The path is `DnsDohResponseValidator.readValidatedBody` → service response validation → `DnsResponseCacheEntry.create` / `DnsMessageValidator.parseCacheRecordMetadata` → `DnsMessageValidator.truncateResponseForClient`.

## Structural call counts

The call counts below are derived from that call graph and the harness operations; they are not runtime instrumentation counters. Validation counts mean calls to `isValidResponse`. Cache metadata RR visits count only the records visited by `parseCacheRecordMetadata`; they do not sum the separate response-validation traversals. A truncation scan pass means truncation walked records because the response exceeded the client limit; it is not a count of records walked.

An uncached DoH response delivered to one client has four structural validations: body reading, service validation, cache-entry creation, and client truncation. It also has one cache metadata pass. A cache hit has one validation at client truncation. An uncached leader with four waiters has three leader validations plus five per-client truncation validations, with one metadata pass. The five clients each receive their own truncation check.

## JVM workload and measurement

`DnsResponseParseBenchmarkTest` reuses `DnsTestMessages` and measures single A, single AAAA, negative with SOA, A with RRSIG, a 60-record AAAA response, an A cache hit, and one leader with four waiters. The five response fixtures each have a direct-validation scenario and a full uncached-path scenario, for 12 scenarios total.

Each scenario uses 2 warmup rounds and 7 measured rounds of 500 batches. Reported wall time, CPU time, and allocated bytes are medians per batch. Allocation is measured from the current JVM thread with `ThreadMXBean`; it is not an estimate. The waiter scenario includes admission setup and immediate deferred completion on one thread. It does not measure concurrent scheduling or queue wait time.

On this Windows JBR run, 11 of 12 median CPU deltas were below the CPU timer resolution. They are labeled `below_resolution`, not zero CPU cost or `unsupported`. The sole resolved median is 31,250.0 ns per batch for the full 60-record response path. The observed timer quantum was approximately 15.625 ms, so the CPU figures for other workloads cannot distinguish their costs at this sample size.

The focused command used for the primary run was:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat --no-daemon --console=plain :app:testDebugUnitTest --tests '*BackgroundDnsLogPolicyTest' --tests '*DnsDecisionEventBufferTest' --tests '*DnsUdpUpstreamClientTest' --tests '*DnsResponseParseBenchmarkTest'
```

The benchmark is an ordinary JVM unit test and also runs as part of the full unit-test suite. The measurements include local `ByteArrayInputStream` body handling and exclude HTTP/TLS/network time, the service LRU lookup/state check, transaction-ID rewriting, and real TUN delivery.

## Results

All counts in the final three columns are structural call-graph counts per batch. CPU values marked `below_resolution` are under the Windows JBR timer resolution described above.

| Workload | Median wall ns/batch | Median CPU ns/batch | Median allocated bytes/batch | Structural `isValidResponse` calls | Structural cache metadata passes / RR visits | Structural truncations / RR scan passes |
|---|---:|---:|---:|---:|---:|---:|
| Single validation, A | 2,049.2 | below_resolution | 2,712.1 | 1 | 0 / 0 | 0 / 0 |
| Uncached DoH, A | 5,447.4 | below_resolution | 13,040.1 | 4 | 1 / 1 | 1 / 0 |
| Single validation, AAAA | 977.2 | below_resolution | 2,176.1 | 1 | 0 / 0 | 0 / 0 |
| Uncached DoH, AAAA | 2,617.6 | below_resolution | 12,824.1 | 4 | 1 / 1 | 1 / 0 |
| Single validation, negative with SOA | 581.2 | below_resolution | 3,888.1 | 1 | 0 / 0 | 0 / 0 |
| Uncached DoH, negative with SOA | 8,238.8 | below_resolution | 21,488.1 | 4 | 1 / 1 | 1 / 0 |
| Single validation, A with RRSIG | 1,280.4 | below_resolution | 3,712.1 | 1 | 0 / 0 | 0 / 0 |
| Uncached DoH, A with RRSIG | 8,302.6 | below_resolution | 19,728.1 | 4 | 1 / 2 | 1 / 0 |
| Single validation, 60-record AAAA | 6,170.8 | below_resolution | 52,144.1 | 1 | 0 / 0 | 0 / 0 |
| Uncached DoH, 60-record AAAA | 35,080.2 | 31,250.0 | 270,160.1 | 4 | 1 / 60 | 1 / 1 |
| A cache hit | 1,015.0 | below_resolution | 2,240.1 | 1 | 0 / 0 | 1 / 0 |
| Uncached DoH leader plus four waiters | 11,868.0 | below_resolution | 22,768.1 | 8 | 1 / 1 | 5 / 0 |

The direct-validation measurements are calibration points only. Do not multiply them by the structural validation count to estimate removable time: each isolated call omits body buffering, cache metadata and TTL work, truncation, or other path costs. This benchmark measures only the current implementation; it does not measure a candidate optimization or an end-to-end service gain.

## Decision

Keep the production parser and validation path unchanged this round. The baseline shows full-path component costs, including 35,080.2 ns per batch for the 60-record response, but it does not show the benefit of a proposed change. No trusted fast path or alternative parser was implemented and measured, and no Android end-to-end gain was demonstrated.

Sharing validation or parser state would have to remain correct across mutable response bytes, differing queries and transaction IDs, resolver generations, cache TTL adjustment, and per-client truncation. The component-only measurements do not justify adding that trusted-result complexity or taking on those correctness and security risks. This decision does not claim repeated validation is negligible; it records that an optimization benefit has not been established.

## Android and power limits

These are JVM component measurements, not Android timings. They do not establish Android CPU cost, device latency, VPN throughput, background-process behavior, battery use, or power savings. No device or battery claim follows from this run. An Android comparison would require a measured candidate and the same fixtures on a specified device/API level; JVM and Android timings should not be treated as equivalent.