# D07 isolated device acceptance

Related: #40, #33, PR #55.

Set JAVA_HOME to Android Studio JBR and ANDROID_HOME to the installed Android SDK.
Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1` first.

```powershell
.\gradlew.bat --no-daemon --console=plain :app:assembleD07test :app:assembleD07testAndroidTest
adb install -r app\build\outputs\apk\d07test\app-d07test.apk
adb install -r app\build\outputs\apk\androidTest\d07test\app-d07test-androidTest.apk
adb shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.data.AppDatabaseMigrationTest,io.github.xiangwang2000.dnsshield.data.UserDomainRulePersistenceInstrumentedTest io.github.xiangwang2000.dnsshield.d07test.test/androidx.test.runner.AndroidJUnitRunner
```

Only the `.d07test` application and its test package are installed. Production data
is not migrated or replaced. After testing, uninstall only these isolated packages.

## Observed 2026-09-23

ASUS_Z01RD / Android 10 / JCAZB7604377HFP: `OK (2 tests)`, 0.425 s.
The migration test preserved preexisting resolver and bypass rows. The persistence
test used a file-backed Room database, closed and reopened it, verified allow removal
restores blocking, exact/subdomain distinctions, lookalike rejection, IDN matching,
more-specific conflicts, and revision-guarded undo.

`verify.ps1` passed (29 Python tests, both assets, JVM tests, Debug/AndroidTest builds).
The isolated application and instrumentation APKs compiled successfully.

This is database and policy acceptance, not a TUN/UI integration run. Immediate
application to live DNS traffic, live cache invalidation, UI add/delete/undo, and
process-recreation behavior still require the service/UI matrix. Keep the issue
open and In Progress until that evidence is complete.


## Live TUN acceptance (2026-09-27)

ASUS_Z01RD / Android 10: `LiveUserDomainRuleTunInstrumentedTest` passed
1/1 in 0.898 s. The actual VPN path changed BLOCK -> ALLOW -> BLOCK;
the repeated allowed query used the positive cache, and reload discarded that
cache entry before blocking again. The fake UDP server runs on loopback port
15353 only in `.d07test`, continuously answers, and counts the test QNAME only.
The test awaits Android VPN network readiness. Build both app and test APKs;
building only the instrumentation APK does not update app manifest permissions.

`verify.ps1`, both isolated APK builds, and `git diff --check` passed.
Raw local result: `captures/d07-live-policy-device2.txt` (not tracked).
UI add/delete/undo and process recreation remain separate pending acceptance.
