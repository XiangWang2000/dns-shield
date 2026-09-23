# D12 isolated device acceptance

Related: #45, #33, PR #53.

## Reproduce

Use Android Studio JBR as JAVA_HOME and set ANDROID_HOME to the installed SDK.
Run `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1`.

```powershell
.\gradlew.bat --no-daemon --console=plain :app:assembleD12test :app:assembleD12testAndroidTest
adb install -r app\build\outputs\apk\d12test\app-d12test.apk
adb install -r app\build\outputs\apk\androidTest\d12test\app-d12test-androidTest.apk
adb shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.blocking.RulePolicyStatusInstrumentedTest io.github.xiangwang2000.dnsshield.d12test.test/androidx.test.runner.AndroidJUnitRunner
```

The `.d12test` application ID isolates the test from the production installation.
The test operates only on a disposable cache directory. It verifies real packaged
assets, a valid private override, invalid-override fallback, failure of both sources,
matching decisions, and preservation of the invalid override file.

For UI smoke, launch the isolated MainActivity, grant its VPN consent, enable protection,
and inspect the rules card. Stop protection afterwards and uninstall only the two
isolated packages. Do not uninstall the production app to resolve signing conflicts.

## Observed 2026-09-23

ASUS_Z01RD, Android 10, serial JCAZB7604377HFP: instrumentation `OK (1 test)`, 0.077 s.
`verify.ps1` passed (29 Python tests, both packaged assets, JVM tests, Debug and
AndroidTest APKs). Isolated APK compilation passed.

UI smoke while running the actual isolated VPN displayed APK source
`badmojr/1Hosts Lite`, revision `273a6bcdcc3585bc47f1ebb6823db05ec5b7b409`, date
`2026-08-23`, 102972 rules, verified integrity, and PSL 9950/281/8.
The full revision wrapped within the card and the card remained readable.
Local screenshots: main checkout `captures/issue-review-2026-09-23/d12-ui.png` and
`d12-active.png` (ignored, not distributed with this document).

The optional independent downloader remains deferred. This does not validate
signed downloads or cross-version Android UI behavior.
