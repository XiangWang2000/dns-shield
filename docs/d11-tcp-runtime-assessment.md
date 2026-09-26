# D11 client-facing TCP runtime assessment

Issue #44 / PR #62. Original assessment: 2026-09-23. The historical
assessment below is superseded by the implementation record in
[d11-runtime-validation.md](d11-runtime-validation.md), dated 2026-09-27.

## Candidates and decision

| Candidate | Upstream evidence | Integration consequence |
| --- | --- | --- |
| [HevSocks5Tunnel](https://github.com/heiher/hev-socks5-tunnel/tree/e802f02bae0fc55cbf681466a60e89c2e6773401) | MIT; Android NDK build and JNI/TUN-fd API; uses lwIP | Candidate for a prototype, but its public API forwards to SOCKS. It is not a DNS callback library. |
| [tun2socks](https://github.com/xjasonlyu/tun2socks/tree/5d9fac67bb1095a5d2bd959216f85e6434524731) | MIT; Go and gVisor netstack; README lists desktop/server platforms | Requires an Android/Go binding and a proxy adapter. Android packaging and shutdown behavior must be demonstrated. |
| [gVisor](https://github.com/google/gvisor) netstack directly | Apache-2.0 per upstream license | Avoids a SOCKS abstraction but still adds a Go/native build and a custom packet-to-stream adapter. |

Prefer a bounded Hev prototype over writing a new TCP state machine. This is an
engineering inference from its documented Android support, not a completed
compatibility or performance evaluation. Pin all native/submodule sources and
review their own notices before adoption; the top-level MIT license does not
replace a dependency license inventory. No dependency is added by this assessment.

## Required DNS-only adapter

- Keep one owner of the TUN read loop. Giving both the current UDP reader and a
  native stack the same descriptor would distribute packets unpredictably.
- Preserve routes only for virtual DNS addresses. A proxy sample's default-route
  configuration must not broaden this application's routing scope.
- If using Hev, bound a local SOCKS adapter to DNS destinations/port 53 only and
  feed accepted TCP streams through the existing framing, policy, cache, and
  resolver pipeline. A localhost listener alone cannot process TUN TCP packets.
- Keep UDP and TCP on the same rule/cache/strict-encryption decision path; do not
  let the native proxy open its own DNS upstream and bypass the Kotlin policy.
- Apply D05 admission/deadline limits to sessions and requests; stop/revoke must
  close adapters, wake pending I/O, stop native processing, and release the TUN
  descriptor exactly once. Define ownership before implementing the JNI bridge.

## Proof required before enabling the runtime

First integrate the D04/D05/D10 prerequisites. Then build an isolated prototype
with synthetic TUN input and a fake DNS upstream. Exercise SYN/ACK, reordered and
retransmitted data, multiple framed requests, FIN half-close, RST, idle expiry,
capacity exhaustion, malformed packets, and stop with pending reads/writes.
Require bounded memory, no leaked sessions or file descriptors, and matching DNS
policy/cache results for UDP and TCP. Android ABI/API builds and an emulator run
must precede a real-client TCP query and UDP-TC retry acceptance run.

No device throughput, power, Android compatibility, or runtime correctness result
is claimed here. README must continue to describe UDP-only client support until
these tests and the real-client end-to-end acceptance pass.
