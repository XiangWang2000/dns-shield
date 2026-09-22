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
