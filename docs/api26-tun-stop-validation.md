# API26 TUN STOP validation

## Reproduced defect and cause

Tracked as [#80](https://github.com/XiangWang2000/dns-shield/issues/80), found while adding feasible coverage to [#73](https://github.com/XiangWang2000/dns-shield/issues/73). Baseline was merged main `f985f9b6012ecea64c09c3bbb357f2782b89fa80`; candidate source is `fa59069c06218ee7b6e35d0f4c4bca08c99da474`.

A new Android 8.0/API26 default x86_64 AVD reproduced a real defect: two START/STOP tests in the same process stalled at the second STOP. The lifecycle stayed STOPPING beyond the 15-second test limit. A single isolated STOP test passed, so the repeated-session condition matters. The original two-test loop failed twice; the initial complete lifecycle suite also failed during stop/cleanup. These failures are retained, not treated as an unavailable environment.

Kernel diagnostics during the failure showed a DefaultDispatcher thread in `__skb_recv_datagram`, syscall read(fd49, length4096), after stop had closed the raw ParcelFileDescriptor. Main was in epoll and the native TCP/output workers had exited. Sending SIGQUIT incidentally woke the reader and made the same loop pass; that was only a diagnostic intervention and does not count as a product pass.

The API26 [FileInputStream source](https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/ojluni/src/main/java/java/io/FileInputStream.java) marks a stream constructed from a supplied FD as non-owning. Closing the raw PFD does not provide the stream read's blocked-thread signal. The standard [FileChannelImpl close path](https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/ojluni/src/main/java/sun/nio/ch/FileChannelImpl.java) calls threads.signalAndWait before its parent close. This lets the application wake the registered read without hidden Android APIs or polling.

## Repair and ownership

- The reader uses Channels.newInputStream(FileInputStream(fd).channel). VpnTunnelInputOwner owns that session input and closes it on STOP or native reader failure.
- STOP first invalidates the tunnel generation, requests native stop, cancels the session and closes its input channel. It then joins the session. The shared PFD is closed by the session completion handler after every child and native output cleanup have exited, preventing premature descriptor reuse.
- STOP racing with input open records the stopped state; a late stream is immediately closed and never read. Channel close is outside the registration lock.
- Destruction and partial-start cleanup use the same cancellation ownership. The unused raw-PFD-first helper was removed and its tests now exercise the actual owned-input path.
- The policy generation and response send/write fences, strict-mode rules, durable intent receipts, and output serialization are unchanged. No join timeout masks the defect.

Independent lifecycle review found no blocking deadlock, descriptor-reuse or late-open finding. The requested real-PFD validity assertion was added: closing the input channel and joining the reader must leave the shared PFD valid until its owner releases it.

## Red and green evidence

| Stage | Environment | Result | Raw artifact |
| --- | --- | --- | --- |
| Baseline repeated START/STOP | API26 AVD | 2 tests failed | captures/r10-api26-two-stop-repro.txt |
| Baseline blocked-read kernel probe | API26 AVD | Reader blocked after PFD close; 2 tests failed | captures/r10-api26-stop-kernel-threads.txt; captures/r10-api26-kernel-repro.txt |
| First repaired original repeated loop, no SIGQUIT | API26 AVD | 2/2, 3.008s | captures/r10-api26-channel-fix-two-stop.txt |
| Final source lifecycle + persistent intent/XML | API26 AVD | 4/4, 2.921s | captures/r08-r10-final-d15-emulator-5556.txt |
| Final source same classes | Android10 ASUS_Z01RD phone | 4/4, 3.943s | captures/r08-r10-final-d15-JCAZB7604377HFP.txt |
| Final source same classes | API35 AVD | 4/4, 2.811s | captures/r08-r10-final-d15-emulator-5554.txt |
| Actual channel/PFD + service cache | API26 AVD | 4/4, 0.174s | captures/r08-r10-api26-cache-reader.txt |
| Client TCP through native TUN | API26 AVD | 4/4, 16.124s | captures/r08-r10-api26-tcp-tun.txt |

The final lifecycle APK was rebuilt after the source commit and installed on each exact serial. API26 final acceptance ran non-root (shell UID2000). The earlier API35 run failed its explicit VpnService.prepare prerequisite because previous testing had revoked that isolated app's consent; it was not a lifecycle failure. The exact `.d15test` package was reauthorized and the full suite passed. Both failure and correction remain in ignored captures.

Three new JVM tests cover stop-before-open, stop racing with open, and actual Java NIO Pipe read wakeup. The original blocked-reader unit test now uses the production input owner. The Android socket-PFD test exercises the same Channels path and checks join, end notification, null failure, and valid shared FD. The service's original repeated-session test remains the API26 TUN failure regression.

Full verify passed 29 Python and 283 JVM tests/48 suites, zero failure/error/skip, assets/lint/APKs. See [R08 shared transport report](r08-transport-size-validation.md) for common strict/TCP/cache regressions. The existing D09 allNetworks deprecation warning is unchanged; no new warning was introduced.

## Commands and APKs

```powershell
.\gradlew.bat --no-daemon --console=plain -PandroidTestBuildType=d15test :app:assembleD15test :app:assembleD15testAndroidTest
adb -s emulator-5556 shell am instrument -w -e class 'io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest#explicitStartAndStopUseOnlyTheIsolatedD15PackageState,io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest#explicitStopSuppressesNullActionRecovery' io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
adb -s emulator-5556 shell am instrument -w -e class 'io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest,io.github.xiangwang2000.dnsshield.service.VpnUserIntentInstrumentedTest' io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
```

Set JAVA_HOME to the bundled Android Studio JBR, ANDROID_HOME/ANDROID_SDK_ROOT to the installed SDK, and install both selected APKs on the specified serial. The isolated test app must have VPN consent before the service tests. The test suites explicitly stop and clear only their isolated persistent intent; they do not change the formal app's data.

| Artifact | SHA256 |
| --- | --- |
| app/build/outputs/apk/d15test/app-d15test.apk | `3f143cb827583a637bc4c44a384cb39c099b12fffe8d14fd16ae37ae412653bc` |
| app/build/outputs/apk/androidTest/d15test/app-d15test-androidTest.apk | `2b1d993735be5e0a6cbda1b3a7e245d257d69c066f9a83912220d617611eec8b` |

## Environment and limits

The API26 AVD was created from official system-images;android-26;default;x86_64, with the existing SDK/emulator toolchain and headless WHPX execution. It is representative API26 coverage, not the full API24–27 matrix or an old OEM phone. API35 results are emulator results. Existing Android10 default-background-policy failures, battery exemption conditions and true LMK gaps remain documented in #73 and the D15 report.

This repair does not claim Always-on reboot, external cross-VPN revoke, real LMK, IPv6-only/NAT64, captive-portal login or unplugged power acceptance for this new source. The prior core version's evidence is retained with its exact scope; SIGKILL is not LMK. DNS-only lockdown remains unsupported. No release or main merge is implied by local validation.

Cleanup: all test VPN services were stopped; AVD Always-on remained null. This round's API26 D04/D15 and API35 D15 app/test packages were removed. Existing API35 D04/D07/D08 packages were preserved. Task-owned emulators were shut down; reusable AVDs/system images and ignored source/stack/kernel/log evidence were retained. The phone's formal/D04/D15 apps and user battery exemptions remain, and its Always-on=null, lockdown=0, Wi-Fi=1, flight=0. No active screen-awake helper was started.
