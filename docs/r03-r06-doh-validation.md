# R03 / R06 local DoH validation

## R03 endpoint bootstrap (#66)

Baseline: `main` commit `1dbd49df6a788a894c1e3e65e1b5357bb211f569`, pinned OkHttp 5.4.0. `DohBootstrapDns.forEndpoints` associated addresses by hostname; a same-host secondary replaced the primary configuration, including an empty secondary.

A local HTTPS test reproduced the defect before the fix: requesting the primary hostname/path reached the server bound to the secondary IP. The original test failed its primary-server request assertion. The fix creates the DoH client/DNS for the specific endpoint being attempted; primary and secondary retain their individual bootstrap addresses. The URL hostname and the normal certificate/hostname verification remain intact. Redirects remain disabled and unknown bootstrap hostnames never use system DNS.

The JVM HTTPS fixture is self-signed and trusted only by the test client. `app/src/test/resources/doh-local-test.p12` is public test key material, with test-only password `test-only-password`; it is never loaded by production code or placed in Android main assets.

Checks:

- `:app:testDebugUnitTest --tests '*DohEndpointHttpsTest' --tests '*DohEndpointConfigurationTest' --tests '*DnsDohHttpClientTest'`: PASS after the fix. Covers same hostname with distinct IP/path/port, empty secondary isolation, another hostname, a built-in hostname, certificate hostname mismatch, unknown DNS rejection, HTTP errors and redirect prohibition.
- `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`: PASS (Python/packaged assets/JVM/lint/Debug and isolated D04 APKs). An old reused worktree initially lacked the already-pinned native submodule; initialized the recorded submodule revisions without changing dependency versions before full verification.
- `git diff --check`: PASS.

Local ignored raw logs: `captures/r03-https-baseline.log` (one expected failure), `captures/r03-https-candidate.log`, `captures/r03-https-final-focused.log`, `captures/r03-final-verify.log`.

## R06 connection reuse investigation (#69)

Five sequential **different DNS questions**, sent to the local HTTPS DNS server without a DNS-response cache, each rebuilt the endpoint client/DNS. EventListener observed 5 connection acquisitions and **5 TLS handshakes**. This reproduces connection reuse failure in the locked OkHttp version; it does not measure battery consumption.

[OkHttp 5.4.0 Address source](https://github.com/square/okhttp/blob/parent-5.4.0/okhttp/src/commonJvmAndroid/kotlin/okhttp3/Address.kt#L182-L192) includes DNS equality in connection address compatibility. Each new endpoint DNS lambda has a different identity, consistent with the measured result.

The R03 endpoint-binding change alone still has 5 handshakes. R06 client reuse, configuration/network invalidation, cancellation and integrated strict-mode tests remain pending. No latency/power improvement is claimed. Common candidate/device integration remains tracked in #72; unavailable environment and power A/B remain tracked in #73. No automatic merge or release is performed.