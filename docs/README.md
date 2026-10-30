# 文件索引

使用者功能與安裝見 [README](../README.md)，版本異動見 [CHANGELOG](../CHANGELOG.md)，資料處理與授權見 [隱私說明](../PRIVACY.md)和[第三方聲明](../THIRD_PARTY_NOTICES.md)。

## 目前維護的文件

| 要做的事 | 入口 |
| --- | --- |
| 建置、驗證、程式結構與簽章 | [開發指南](development.md) |
| 查封鎖／允許順序、規則與降級策略 | [Blocking policy](blocking-policy.md) |
| 更新或重建 APK 防護清單 | [Blocklist 格式與來源](blocklist-format.md) |
| 維護 Public Suffix 來源、格式與 APK 資產 | [Public Suffix](public-suffix.md) |
| 了解網路狀態與斷網恢復 | [網路恢復](network-change-recovery.md) |
| 重跑效能量測及解讀結果 | [Benchmarks](benchmarks.md) |

## 歷史驗證

[archive/](archive/) 保存當時的環境、數據、失敗原因與未完成項目。它不是目前版本已通過驗收的宣告；現行指令以開發與 benchmark 指南為準。未納入某次實測的特殊網路、平台矩陣或長時間耗電，不能從短測試或建置結果推定完成。

<details>
<summary>查看全部歷史紀錄</summary>

- [Android benchmark 歷史紀錄](archive/android-benchmarks.md)
- [API26 TUN STOP validation](archive/api26-tun-stop-validation.md)
- [CI 快取與 JVM 重用驗證（2026-10-14）](archive/ci-cache-validation.md)
- [D03 dual-stack acceptance](archive/d03-dualstack-validation.md)
- [D04 lifecycle fault validation](archive/d04-fault-validation.md)
- [D05 admission load check](archive/d05-admission-android-load.md)
- [D06 diagnostics acceptance](archive/d06-device-acceptance.md)
- [D07 isolated device acceptance](archive/d07-device-acceptance.md)
- [D08 isolated migration acceptance](archive/d08-device-acceptance.md)
- [D10 upstream TCP and large-answer acceptance](archive/d10-device-acceptance.md)
- [D11 runtime implementation and validation — 2026-09-27](archive/d11-runtime-validation.md)
- [D12 isolated device acceptance](archive/d12-device-acceptance.md)
- [D14 device validation](archive/d14-device-validation.md)
- [D15 Always-on／系統恢復驗證紀錄](archive/d15-device-acceptance.md)
- [Issue #98 / R20: DNS response parse evaluation](archive/issue98-r20-response-parse-evaluation.md)
- [網路變更復原的能力邊界](archive/network-change-recovery.md)
- [R01 TCP session cancellation validation (#64)](archive/r01-tcp-session-validation.md)
- [R02 user-rule assembly validation (#65)](archive/r02-user-rule-validation.md)
- [R03 / R06 local DoH validation](archive/r03-r06-doh-validation.md)
- [R04 resolver command ordering validation](archive/r04-resolver-command-validation.md)
- [R08 Transport Size Validation](archive/r08-transport-size-validation.md)
- [R09 Common Integration and Validation](archive/r09-common-validation.md)
- [R10 Wi-Fi／行動數據實機驗收（2026-10-06–07）](archive/r10-cellular-handoff-validation.md)
- [R11–R14 解析器修正驗證](archive/r11-r14-resolver-validation.md)
- [R15／R16：解析器政策收斂與非阻塞提交驗證](archive/r15-r16-policy-convergence-validation.md)
- [R17–R19 background work validation](archive/r17-r19-background-work-validation.md)
- [1.2 系列候選版與驗證紀錄](archive/release-1.2-validation.md)
- [1.3.0 候選優化與實機驗收（2026-10-12）](archive/release-1.3.0-optimization-validation.md)
- [1.3.0 發版前獨立審查（2026-10-09）](archive/release-1.3.0-preflight.md)

</details>
