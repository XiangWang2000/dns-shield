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
