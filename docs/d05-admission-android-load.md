# D05 admission load check

Run date: 2026-09-21  
Device: ASUS_Z01RD, Android 10 (API 29)  
Instrumentation: `DnsBoundedAdmissionDeviceLoadTest`

## Workload and result

Eight worker threads submitted 10,000 distinct keys and then 24,000 requests spread over the 24 admitted keys.

| Measurement | Result |
| --- | ---: |
| Unique keys admitted | 24 |
| Same-key waiters admitted | 192 (8 per key) |
| Maximum pending requests | 216 |
| P50 admission latency | 36 µs |
| P95 admission latency | 437 µs |
| P99 admission latency | 935 µs |
| Reported post-GC retained-heap increase | 0 bytes |

All configured bound assertions passed; after releasing the admitted leases, the registry returned to zero pending requests. The heap figure is a coarse `Runtime.totalMemory() - freeMemory()` delta, floored at zero. It does not mean the requests allocated no objects and is not a PSS measurement.

The chosen cap keeps the existing maximum of 24 concurrent unique upstream leaders and adds at most 8 coalesced waiters per key. That bounds admitted work at 216 requests without expanding upstream concurrency. The device run exercises the admission registry under concurrent bursts; it does not run the VPN/TUN service or measure service-wide heap, cache/block fast paths, transports, or stop behavior. Keep those Issue #38 checks open for service-level and device acceptance.

The test APK was run with a temporary `.codexdevice` application ID suffix because the handset had the release-signed v1.2.2 package installed. That local build setting was reverted after the run.

## Integrated real TUN run (2026-09-28)

Branch `codex/d05-bounded-admission` integrated the merged D04 and D07 main branch in `f1c02be`. The first Android 10 isolated `.d07test` TUN regression exposed a merge error: D05's UDP fallback endpoints used port 53 instead of the build-configured test port 15353. Both primary and secondary endpoints now use `BuildConfig.DNS_UPSTREAM_PORT`; `LiveUserDomainRuleTunInstrumentedTest` then passed 1/1. The production build still uses port 53.

`DnsAdmissionTunInstrumentedTest` uses the same isolated `.d07test` package and a local fake UDP upstream. Five revised runs passed 1/1 each. The final run used 40 simultaneous distinct client queries; 22 reached the fake upstream and the rest received SERVFAIL. Another run reached 23. No run exceeded the 24 unique-leader limit. The test also checks 8 same-key waiters share one upstream request, a ninth waiter receives immediate SERVFAIL, all unresponsive-upstream clients receive SERVFAIL by their deadline, the primary failure falls through to a responding secondary, and a pending UDP receive does not delay VPN stop. Observed pending-stop times were 148, 166, and 167 ms; the final run found zero TUN descriptors after stop. The app's blocked/cache TUN path was checked by the merged D07 regression. The first 24/24-arrival version was timing sensitive because not every client held a free admission slot; the revised overload assertion checks the actual cap under 40 clients.

Final isolated APK SHA-256: app `122438B028015455DBAFA3F505BD0F7B54F8E37B06DFA74EDFA9CBC7C915533D`, instrumentation `92DD1B144060E145A2BF411CD1E205A70A752913E9FFE8ED52D43037CE6AC995`. Raw reports: ignored `captures/d05-port-fix-d07-live-tun.txt`, `captures/d05-tun-load-device4.txt`, `captures/d05-tun-load-device5.txt`, and `captures/d05-tun-load-device6.txt`, and `captures/d05-tun-load-device7.txt`, and `captures/d05-tun-load-device8.txt`; Android `System.out` logcat has the per-run counts and timings.

One final-run process sample, in bytes unless stated otherwise: heap used before/during/after load 4,986,640 / 7,463,344 / 8,255,392; PSS 152,472 / 157,683 / 157,110 KB; post-stop FD count 71. These are observations from one run, without a same-state baseline or GC normalization. They do not establish a leak or a power/performance improvement. The admission-registry device test above provides the exact 24 leaders × 8 waiters bound; this TUN test demonstrates the service ceiling with background device traffic present. Slow/failing DoH is covered by deadline/fallback unit tests and the separate D08 TLS failure device test, but a controlled slow DoH request has not yet been exercised through this D05 TUN build.