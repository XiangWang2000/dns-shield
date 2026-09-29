# D03 dual-stack acceptance

The isolated `d03test` build uses application ID `io.github.xiangwang2000.dnsshield.d03test`.
It leaves production app data intact. Grant VPN consent only to that test package.
Build with `./gradlew.bat -PandroidTestBuildType=d03test :app:assembleD03test :app:assembleD03testAndroidTest`.
Install both APKs on an explicitly selected `adb -s SERIAL` target and run:

```powershell
adb -s SERIAL shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.Ipv6PassThroughTest io.github.xiangwang2000.dnsshield.d03test.test/androidx.test.runner.AndroidJUnitRunner
```

The test runs ordinary IPv4 and IPv6 TCP connections plus AAAA DNS queries to
IPv4 and IPv6 resolvers before VPN startup, with VPN running, and after shutdown.
It additionally queries AAAA through the VPN virtual IPv4 DNS address. It does
not bind sockets to an underlying network or call protect, so those connections
exercise the application's ordinary VPN routing behavior.

## 2026-09-25 result

ASUS_Z01RD / Android 10, USB-connected and charging, Wi-Fi dual-stack network:
external IPv6 reachability and global address/default route were confirmed.
`dualStackVpnOffOnOff` passed (1/1, 2.028 seconds). Raw local evidence is in
`captures/d03-dualstack-device.txt`. No physical-device power result is claimed.

This closes the dual-stack slice only. IPv4-only and IPv6-only/NAT64 networks
must be tested separately; this network does not demonstrate those environments.
IPv6 transit remains pass-through, not IPv6 DNS interception or an IPv6 upstream
configuration feature. CI builds the harness but does not reproduce this network.

Test APK SHA-256: `f98414be6aca6501b70140a31b1eb5f58da9998c3460828ae689454e32964af5`.
Full `verify.ps1` passed, including 98 JVM tests and lint.

## 2026-09-29 current-main integration and IPv4-only run

The existing D03 worktree merged current `main` (`1dbd49d`), retaining the one-line `Builder.allowFamily(AF_INET6)` change in the current VPN lifecycle and D11 UDP/TCP TUN implementation. The isolated `d03test` variant and `verify.ps1` build step were preserved. `Ipv6PassThroughTest` now uses the current lifecycle flow and adds an IPv4-only off/on/off case.

On ASUS_Z01RD / Android 10, the current Wi-Fi had an IPv4 address and only an IPv6 link-local address, with no IPv6 default route (`adb shell ip -6 route show default` returned no route). After granting consent to the reinstalled isolated `.d03test` package, `ipv4OnlyVpnOffOnOff` passed 1/1 (1.536 seconds): direct IPv4 TCP and IPv4 UDP AAAA queries succeeded before, during, and after VPN; AAAA via the virtual IPv4 DNS also succeeded while VPN was on. The first run failed before the test because reinstalling the isolated APK required fresh Android VPN consent; no test behavior failed. Raw ignored output: `captures/d03-main-ipv4-only-device-consented.txt`.

Full `verify.ps1` passed: 29 Python, 222 JVM tests / 44 suites with zero failures/errors, assets, lint, Debug/D04/D03 APKs. Raw ignored output: `captures/d03-main-final-verify.log`. The earlier dual-stack result above was on an older head and is not a claim for this integrated head. IPv6-only/NAT64 cannot be tested on the current network; D03 remains Draft / In Progress pending that matrix; the exact-head CI result is tracked on PR #50.
