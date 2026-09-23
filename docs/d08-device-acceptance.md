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
it does not validate the new chain. Run the two updated instrumentation cases
with the isolated commands above before merging D08. APK compilation alone is
not a passing Room runtime migration test.
