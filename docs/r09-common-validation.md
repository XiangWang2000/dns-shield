# R09 Common Integration and Validation

Observed 2026-10-05. This note records the common integration and the validation evidence available in this worktree.

## Integration

- Integration merge: `598c124` (`Merge branch 'codex/d15-always-on' into codex/r09-common-validation`).
- Regression test update: `b573974` (`test: validate common resolver ordering and stale policy fence`).
- `verify.ps1` passed, including the isolated D14, D04, and D03 APK builds. Raw output: [`captures/r09-common-fixture-final-verify.log`](../captures/r09-common-fixture-final-verify.log) (`Verification passed.`). This is build/host verification; it does not turn pending device runs into passes.

## Completed runtime evidence

| Target | Result | Raw evidence |
| --- | --- | --- |
| Android 10 resolver selection through ViewModel, Room, Service, and TUN | 1/1 passed | [`r09-android10-resolver-tun-steady-final.txt`](../captures/r09-android10-resolver-tun-steady-final.txt) |
| Android 10 strict DoH with upstream TCP fixture | 5/5 passed | [`r09-android10-doh-strict-upstream-tcp-fixture-final.txt`](../captures/r09-android10-doh-strict-upstream-tcp-fixture-final.txt) |
| Android 10 client TCP through TUN | 4/4 passed | [`r09-android10-client-tcp-tun.txt`](../captures/r09-android10-client-tcp-tun.txt) |
| Android 10 repeated Wi-Fi flight | 1/1 passed | [`r09-android10-wifi-repeat-flight.txt`](../captures/r09-android10-wifi-repeat-flight.txt) |
| Android 10 live rules persistence | 2/2 passed | [`r09-android10-live-rules-persistence.txt`](../captures/r09-android10-live-rules-persistence.txt) |
| API 35 service smoke and persisted intent | 4/4 passed | [`r09-api35-d15-smoke-persistence.txt`](../captures/r09-api35-d15-smoke-persistence.txt) |
| API 35 revoked/unapproved persistence | 2/2 passed | [`r09-api35-revoked-unapproved-persistence.txt`](../captures/r09-api35-revoked-unapproved-persistence.txt) |

## API 35 explicit always-on reboot evidence

The `r09-api35-explicit-always-on-*` captures bracket an AVD reboot: the before/after boot identifiers differ. After boot, the service snapshot shows the VPN TUN service (`DnsVpnService`) and recovery helper (`VpnRecoveryService`), both marked foreground; the DNS probe resolves `example.org` and receives its ICMP reply (1/1, 0% loss). See [`boot-before`](../captures/r09-api35-explicit-always-on-boot-before.txt), [`boot-after`](../captures/r09-api35-explicit-always-on-boot-after.txt), [`services-after`](../captures/r09-api35-explicit-always-on-services-after.txt), and [`dns`](../captures/r09-api35-explicit-always-on-dns.txt). The connectivity snapshots are [`before`](../captures/r09-api35-explicit-always-on-connectivity-before.txt) and [`after`](../captures/r09-api35-explicit-always-on-connectivity-after.txt).

## Pending or not accepted

- **D03 initial-network fixture first failure (resolved).** Keep the initial failure: the first AAAA query received RCODE 2 (SERVFAIL) where the test expects RCODE 0. The captured run is [`r09-android10-d03-ipv4-off-on-off.txt`](../captures/r09-android10-d03-ipv4-off-on-off.txt). The fresh underlay-ready gate keeps the original NOERROR/AAAA assertions. Final Android10 IPv4-only off/on/off passed 1/1 (2.266 seconds): `captures/r09-android10-d03-ipv4-off-on-off-steady-final.txt`. IPv6-only/NAT64 remains not_run (#73).
- **D15 process-death helper first failure (resolved).** The AVD reopened the test Activity after the deliberate process termination and caused a restart loop. The isolated helper now calls `finish()` before its worker can kill the process. API35 direct-store STOP killed once without a relaunch loop; actual Android10 ACTION_STOP completed at 22:14:53.727 and SIGKILL followed at .730, with six 5-second samples showing no PID, durable false/explicit=true, no VPN or service. See `captures/r09-android10-actual-stop-death-*`; this is controlled SIGKILL, not LMK.
- Android10 latest Always-on reboot, sticky process recreation and immediate cross-VPN revoke death are completed below; environment-only gaps remain not_run.

## Test fixture scope

`d08-test-server.p12` is an AndroidTest TLS fixture at `app/src/androidTestD08test/assets/d08-test-server.p12`; it is not part of the production source set or production APK. The separate JVM fixture `doh-local-test.p12` is under `app/src/test/resources` and is also test-only.

## Final code and host verification

Final code/test head: `796952371b7d60bdcbd3228256703a36e32f59d7`; the documentation commit is a descendant with no additional code change. Independent merge/test reviews completed; test cleanup uses ordinary startService for STOP and always cleans up partial starts. Full `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1` passed after the last change (`captures/r09-revoke-latch-final-verify.log`): 29 Python tests, 275 JVM tests / 48 suites, zero failures/errors/skips, production assets, lint and APKs. The initial missing fixture and initial underlay failures were retained and fixed; no production response or strict fence was weakened. Existing allNetworks deprecation warnings remain; no new warning reported in the final incremental run.

Android10 D15 smoke/XML also passed 4/4 (4.019s), `captures/r09-android10-d15-smoke-persistence-final.txt`; final resolver TUN cleanup rerun 1/1 (3.076s), `captures/r09-android10-resolver-tun-final.txt`.

## D14 paired short workload

ASUS_Z01RD / Android10 API29, JCAZB7604377HFP, same IPv4 Wi-Fi and AC charging. Six automatic runs alternated baseline1/candidate1/baseline2/candidate2/baseline3/candidate3, all OK(1 test), all scenario assertions and cleanup passed. Baseline is `02d18028ba43e40bb756e755a25af190f4b493e0`; candidate report source is `d3ff57f8f9198054a95a3f749d5ca020b18c01c7`. D14 app/harness sources did not change between the candidate APK build and this commit. The baseline includes the same split automatic/manual harness and D09 pre-R05 implementation; it is not an unrelated released APK.

| Median across 3 runs | Baseline | Candidate |
| --- | ---: | ---: |
| cache hit p50 (ms) | 2.112 | 2.438 |
| unique miss p50 (ms) | 57.835 | 56.933 |
| coalesced miss p50 (ms) | 433.321 | 435.320 |
| burst p95 (ms) | 63.576 | 44.292 |
| process CPU elapsed (ms) | 1866 | 1838 |
| used heap increase (bytes) | 14801792 | 15141392 |
| PSS after (KB) | 167326 | 167385 |

Each run had 28 fake-upstream requests and GC count delta 0. These are small-sample mixed changes, not proof of an overall improvement. Expected all-upstream-failure queries returned asserted SERVFAIL and are retained in workload timing. This protected UDP loopback benchmark does not measure DoH connections, TCP performance or unplugged power. R06 real HTTPS component tests separately establish handshake 5→1 and configuration/network/client reset behavior; D08/D11 TUN suites separately exercise strict/fallback/TCP.

APK SHA256 baseline app `F55FDD9E8D53C6894BE5682ECC3139FBD43ED53C0DE0772B0B7F6B4C72EC8074`, test `CF5DFF8E0A8012D20F50286256FD1322E1A7C52C61FE0D0B5C2E3A479CFF5A9B`; candidate app `E7CE875A912BF91214F28ED13DCE892831020A6EE0B3C7201923824573D8B65F`, test `FE9A2215BF33BDDF40DD038628C61FCDA0E04219E9A1ABDB73168BDA7706F60B`.

Command: `powershell -NoProfile -ExecutionPolicy Bypass -File tools/d14-device-test.ps1 -Action Run -Serial JCAZB7604377HFP -BenchmarkLabel r09-{baseline|candidate}-p{1|2|3}`. Raw outputs `captures/r09-baseline-p*.txt`, `captures/r09-candidate-p*.txt`; local aggregate `captures/r09-d14-paired-summary.json` links the six original JSON files (baseline reports remain in the reused D14 worktree).

Separate manual command adds `-ManualNetworkHandoff -BenchmarkLabel r09-candidate-manual-wifi`. After the observed D14_NETWORK_SWITCH_REQUIRED prompt, Wi-Fi was disabled/enabled via adb; final OK(1 test), 56.038s. Report `captures/d14/d14-e2e-muvc83if.json` records five service transitions, changed selected network IDs, cache_requeried=true and cleanup without fallback stop. Raw `captures/r09-d14-manual-handoff.txt`. This is not cellular handoff or captive portal.

## Deferred scope and repository boundary

IPv6-only/NAT64, real captive portal, full API/OEM/true LMK and long unplugged battery A/B remain not_run in #73; the user asked to schedule power measurement separately. Android10 default-background-policy negative evidence is preserved; current testing retains the user's existing D15 battery exemption. DNS-only lockdown is not claimed. No main merge, release, production VPN setting/data change, or deletion of unmerged branches is authorized by the new issue text. Draft common PR: https://github.com/XiangWang2000/dns-shield/pull/79 .

## Final D15 common device acceptance

Android10/API29 ASUS_Z01RD/JCAZB7604377HFP remains on IPv4 Wi-Fi and AC charging with the user-existing VPN-app battery exemption. Ordinary default-setting failures remain in the earlier D15 report; this does not claim they are fixed. The isolated D15 APK SHA256 is `0D492B170D1D3651B064EEBA96B2299ABEFE452EBF114BC1DD4A555C553CA026`, AndroidTest `2B1D993735BE5E0A6CBDA1B3A7E245D257D69C066F9A83912220D617611EEC8B`. Main production logic is unchanged after common merge; the later D15 changes only improve the test helper. API35 results above cover that same production code; the new immediate-revoke helper mode was validated on Android10.

- Android10 real Settings Always-on reboot: detail package ID was verified from AppManagementFragment before changing the isolated setting. boot `3ef3b4b3-edff-4946-b362-4d188313bcf4` → `17ce9efc-8ea5-48d5-a3f3-ffac4260afff`; system recovered process PID3640, both foreground services and tun0, example.org DNS/ping1/1. Evidence `captures/r09-android10-alwayson-*`. Settings were restored to Always-on=null, lockdown0; no production VPN setting was changed.
- Same-boot sticky recreation with Always-on=null: retained user exemption, removed the VPN temporary whitelist, returned HOME, and used the no-extra self-SIGKILL helper. PID15126 SIGKILL at 22:41:20.059; AMS scheduled recovery helper restart, new PID15430 at 22:41:21.358. The ~10-second sample shows the new PID and both foreground services, retained through the ~40-second window; tun0 and example.org DNS/ping1/1 also passed. Evidence `captures/r09-android10-sticky-death-*`. This is controlled SIGKILL, not LMK or a promise of immediate recovery under every policy.
- Real ACTION_STOP: completed 22:14:53.727; verified disk false/explicit=true and SIGKILL at .730. Six 5-second samples had no PID, no VPN/service and unchanged false intent. Evidence `captures/r09-android10-actual-stop-death-*`.
- Real cross-VPN revoke immediate death: `service_revoke` only arms a wait while RUNNING, finishes its Activity, and never sends ACTION_STOP. The caller then starts isolated D04 from a freshly verified UI; Android delivers onRevoke. Revoke at 22:44:43.455, STOP completed .578, independently verified durable false/explicit=true and SIGKILL .586 (8ms after completion). Six 5-second samples had no D15 PID/recovery. Evidence `captures/r09-android10-immediate-revoke-death-{observations,logcat,services,connectivity}-final.txt`. D04 was the active VPN; D15 and its helper were absent. Cold-open D15 also retains explicit stopped state.
- API35 actual Settings Forget VPN cleared Always-on, durable false and both services. The first deliberate-death helper loop was caused by the Activity record being relaunched, not VPN recovery; negative logs remain. finish-before-worker fixed it; API35 direct-store STOP then killed once with no Activity loop and no service/TUN. Explicitly distinguish the direct-store case from real system onRevoke.

The earlier cross-VPN observation had a 46-second host gap before termination and is retained as such (`captures/r09-android10-actual-revoke-death-*`), not labeled immediate. The first pre-armed attempt returned to D15's own task rather than D04, so the UI guard rejected it; the waiter timed out and did not kill. The corrected command explicitly brings D04 forward and checks its package, power bounds and stopped label before tapping. Raw negative log `captures/r09-revoke-armed-precondition-failure-logcat.txt` remains.

For immediate revoke reproduction, start isolated D15 to RUNNING, arm `adb -s JCAZB7604377HFP shell am start -n io.github.xiangwang2000.dnsshield.d15test/io.github.xiangwang2000.dnsshield.D15ProcessDeathActivity --es intent_operation service_revoke`, then enable another approved isolated VPN within 15 seconds. If the waiter times out it refuses death; the caller must clean up the running VPN. Test-only helper requires DUMP permission and does not exist in the production source set. Independent review found no new product defect.

## Final cleanup and CI

Temporary D03/D07/D08/D14 app/test packages were removed. Existing production, D04 and D15 app/test packages and the user's battery exemptions were retained. Phone finishes with test VPNs stopped, desired_enabled=false, Always-on=null, lockdown0, Wi-Fi1 and airplane0. Newly installed AVD D15 app/test removed; task-owned emulator PID41556 exited, previous AVD D04/D07/D08 retained. All existing worktrees, ignored evidence and the untracked root handoff are preserved. No current local feature branch is already merged into the existing main, so no unmerged branch is deleted.

Full final verify and local isolated APK builds passed, with 275 JVM tests /48 suites and zero failure/error/skip. Earlier exact code head `d3ff57f` Windows verification CI [37323263644](https://github.com/XiangWang2000/dns-shield/actions/runs/37323263644) succeeded. The final descendant head's exact CI is recorded in [common PR #79 checks](https://github.com/XiangWang2000/dns-shield/pull/79/checks) and issue #72; no old-head result is substituted. Device raw artifacts named above are local ignored captures, preserved in the reused worktrees.
