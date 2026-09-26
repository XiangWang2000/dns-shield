# D08 isolated migration acceptance

Related: #41, #33, PR #58.

Set JAVA_HOME to Android Studio JBR and ANDROID_HOME to the installed SDK.
Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`.

```powershell
.\gradlew.bat --no-daemon --console=plain :app:assembleD08test :app:assembleD08testAndroidTest
adb install -r app\build\outputs\apk\d08test\app-d08test.apk
adb install -r app\build\outputs\apk\androidTest\d08test\app-d08test-androidTest.apk
adb shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.data.DnsServerMigrationTest io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

The application ID suffix `.d08test` preserves the production package and database.
The existing migration test creates a legacy database and reopens it through Room's
actual migration/validation path. Remove only the isolated application and test
packages after the run.

## Observed 2026-09-23

ASUS_Z01RD / Android 10 / JCAZB7604377HFP: `OK (1 test)`, 0.287 s.
Resolver ID, name, primary and secondary addresses survived migration; the legacy
plaintext-fallback behavior was preserved and new custom DoH endpoints defaulted
to null. `verify.ps1` and both isolated APK builds passed.

This result does not establish strict-mode zero-plaintext behavior through TUN,
TLS/error handling, or UI transport status. Those acceptance items remain pending.

## Schema integration update (2026-09-23)

D08 must be integrated after D07 (#40 / PR #55). Schema v2 is reserved for
D07 user rules; D08 is now v3. Register both D07 1-to-2 and DoH 2-to-3 migrations.
The v3 entity list retains the rules table so Room validates it and preserves it.
The former standalone D08 v2 schema was never released; isolated test packages
were removed. It is not a supported production migration starting point.

DnsServerMigrationTest now covers production v1-to-v3 and D07 v2-to-v3 through
Room's actual opening and schema validation, preserving resolver and bypass rows,
and existing rule content plus its unique domain/scope constraint.
The historical one-test device result above tested the former D08 v2 schema;
it does not validate the new chain. Reproduce the two updated instrumentation cases
with the isolated commands above before merging D08. APK compilation alone is
not a passing Room runtime migration test.

## Observed v3 migration acceptance (2026-09-23)

Code commit: 4fda522. ASUS_Z01RD / Android 10 / JCAZB7604377HFP:
`OK (2 tests)`, 0.510 s. Both production v1-to-v3 and D07 v2-to-v3 opened
successfully through Room. Resolver custom/active flags, addresses, fallback
defaults, bypass state, and existing user rules plus their unique index passed.
Both isolated APKs built successfully; the application and instrumentation packages
were removed after the run. The production package remained installed; this run
did not start a VPN or reboot the device. Strict TUN/TLS/UI acceptance is unchanged.


## TLS policy through TUN (2026-09-27)

ASUS_Z01RD / Android 10: `DohTlsFallbackInstrumentedTest` passed 2/2 in
10.884 s. Both cases reach a loopback TLS server with a self-signed certificate
using the production trust checks. Strict mode returns SERVFAIL with zero
matching plaintext UDP queries; allowed fallback returns the fake UDP answer
with exactly one matching query. No production trust override was added.

The fixture uses legacy PKCS12 encryption compatible with Android 10. The
unprivileged loopback port 15353 applies only to `.d08test`. Client UDP uses
bounded retries during VPN startup; ambient phone DNS does not affect QNAME
counts. `verify.ps1` and both isolated APK builds passed; the final retry-only
instrumentation edit was compiled and exercised on the phone.
Raw local result: `captures/d08-tls-device-retry.txt` (not tracked).
Custom endpoint UI, bootstrap failure and network/error matrices remain pending.
