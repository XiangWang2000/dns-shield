# 1.3.0 候選優化與實機驗收（2026-10-12）

結論：兩項原先可延後的優化已納入本次候選，必要回歸與正式 APK 出包完成；API35 模擬器、Android 10 與 Android 15 實機的下述驗收通過。沒有具體證據支持新增發版阻擋。維持使用者「先不要發布」指示，沒有 push、tag、GitHub Release 或 APK 上傳。

本文件接續 [首次發版前獨立審查](release-1.3.0-preflight.md)，取代該報告的舊 APK、兩項可延後優化及「實機尚未完成」狀態。原始容量 SERVFAIL 的不確定性與 #73 延後範圍保持不變。

## 精確候選與修改

- APK source commit：`3207a6efa46491f46f7cb90d9acabae512534b7d`，本機分支 `codex/release-1.3.0-preflight`。基於 PR #99 merge `e23d3793e6cc7db9aef8fdc6382f2a261136bbb8` 與版本／診斷測試提交 `1deddcdb1dc8e6d03a074afd477114e50ae5a9f9`。後續提交僅更新文件。
- 維持未發布的 `versionName 1.3.0` / `versionCode 6`，沿用原簽章金鑰。
- 移除切網等待的 25 ms 定期檢查。只在網路 pending 時訂閱狀態通知，沿用 ingress 的 6 秒期限；網路世代切換、解析器變更、政策發布、debounce 完成及 callback 解除會喚醒等候者。普通查詢直接走 fast path，沒有新增 collector 或 timeout job。
- 政策通知在 `domainPolicy.install` 完成發布後發出，避免 pre-publish callback 喚醒的查詢仍讀到舊政策。世代／政策身分檢查、取消、response commit 與 socket I/O 的原邊界保留。
- 成功日誌先取得 `None / Detail / Summary` 決策，再於需要時格式化；安靜路徑回傳 singleton，不建立捕捉查詢資料的 formatter closure。首次背景明文通知、共用 60 秒 gate、前景完整細節均保留。
- 對照 `0022b34` 的阻塞 TUN 讀取、DoH 退避、單一恢復探測、背景失敗日誌限流與 UDP buffer 重用均未更動。沒有共享 UDP socket 重設計、容量／重送政策變更或無關重構。
- 獨立審查者已檢查主要 retained notification、stop 與 lock-order 路徑，指出 policy 通知時機；調整後由主審覆核並執行回歸。副審因工具額度中斷，未完成最後一版逐行覆核，不能宣稱第二位審查者完成最終核准。

## 建置與回歸

原始本機證據保存在 `captures/release-optimization-20261010/`；沒有為此本機 commit 另跑遠端 CI。

| 檢查 | 結果 |
| --- | --- |
| 焦點 JVM | 8 項 readiness + 6 項成功日誌政策，全部通過。涵蓋通知競態、24 個等候者、取消、舊狀態拒絕、原始期限，以及等待期間沒有定期狀態讀取。 |
| `release.ps1` → `verify.ps1` | 37 Python、330 JVM / 53 suites，0 failure / error / skip；assets、lint 與必要隔離 APK 建置通過。 |
| 警告 | 24 項既有 lint Warning、0 Error；D04 `ConnectivityManager.allNetworks` 的既有 deprecated 警告曾於重編譯時出現，沒有新增 source warning。 |
| API35 D09 | 2/2，46.777 s：三輪 Wi-Fi 恢復、飛航恢復、額外 Wi-Fi 中斷恢復均取得 DNS 回應。 |
| API35 D08 | 19/19，61.776 s：TLS、慢 DoH、backoff、ALLOW／STRICT、解析器、背景診斷、遷移與兩個容量受控案例。 |
| API35 D15 | 8/8，5.362 s：生命週期、意圖持久化、ViewModel 失敗處理。 |
| Release bytecode | 前版呼叫前存在捕捉五個值的 `Function0` factory；本版改成決策分支，`None` 直接跳過格式化。原始輸出為 `service-before.javap.txt`、`service-after.javap.txt`。 |
| API35 正式 APK | UDP/TCP 正常 DNS、UDP/TCP NXDOMAIN 封鎖、背景查詢；三輪啟停後 DNS 成功，running FD 各 111，停止後 active VPN type=-1 且服務列表為空。 |
| API35 原地升級 | 真正簽章 v1.2.2 → 本候選，schema 1→3；5 筆合成 resolver、自訂 active ID 77、1 筆 bypass、偏好逐欄保留；UID 10156、首次安裝時間不變。 |

D04 與 D08 實際安裝 APK SHA-256 和本輪建置相符。背景元件量測保存為 `d08-background-diagnostics-benchmark.jsonl`；其 baseline 是舊逐筆策略，不是本次兩個優化的整機 A/B，不用來宣稱本次省電百分比。

原始失敗也保留：

- 第一次完整建置在 Gradle 產生 `problems-report.html` 時遇到 `FileAlreadyExistsException`；舊檔無法搬移／讀 ACL。把精確的舊產生報告資料夾封存到 `gradle-problems-original/`，未更改 source 或 ACL，後續完整入口成功。`release-build.txt` 與 `release-build-after-report-cleanup.txt` 分別保留。不是測試 assertion 修復。
- 模擬器第一次正式 APK probe 緊接 UI 啟動、未等待 VPN 建立就送出，UDP 超時。原始 UI／VPN dump／logcat 與 `release-first-start-failure.json` 保存；沒有擷取精確送出與建立的相對時間，故不把它斷言為產品缺陷或確定根因。已確認 VPN 建立後的 smoke，以及三輪使用明確 readiness 的啟停成功，與該前提不完整的試跑分列。

## 原容量 SERVFAIL 結論維持

首次失敗的原始 raw log 確認走容量拒絕分支，但缺少 admission snapshot 與完整 callback 時序，仍不能唯一判定 waiter cap／unique cap 或當時 leader 變慢原因。新候選的受控測試再次驗證：500 ms 相同 socket 重送可達 leader + 8 waiters 並收到 SERVFAIL；釋放慢上游後 pending 歸零，下一個 QNAME 成功；單次傳送對照成功。沒有弱化原 assertion、增加自動重跑、提高容量或把歷史失敗改列通過。詳見首次報告的原始檔與界線。

## 正式 APK

- 路徑：`captures/release-optimization-20261010/release-1.3.0/app-release.apk`，同目錄附 `.sha256`。舊候選原檔保留供追查，應使用本路徑的新 APK。
- SHA-256：`ea1745ead74882d92fbe7eee9e7f20a80e0b5d1186db759f64be6258502d68fe`；16,439,071 bytes。
- 憑證 SHA-256：`9ff66cac6960bf10c2660df9f590ebf07ccd9784dae7756e4242007c9e867989`，與公開 v1.2.2 及兩支實機原安裝 APK 相同，`apksigner verify` 通過。
- 套件 ID 不變、非 debuggable；minSdk 24 / targetSdk 37。四個 ABI native libraries 存在、production assets 與 source bytes 相同、沒有 D08 TLS fixture。
- APK 內 VCS metadata 精確指向 `3207a6efa46491f46f7cb90d9acabae512534b7d`。

## 2026-10-10 Android 10 實機

ASUS Z01RD 真正 v1.2.2 → 1.3.0 原地升級；UID 10295、首次安裝時間不變。Google resolver、52 個可見 App 選項（0 個排除）與提示偏好保留。正式 APK UDP/TCP 正常解析與封鎖、切換 Cloudflare、僅加密 UDP/TCP 查詢通過，再恢復 Google／允許降級。

背景三輪 Wi-Fi 中斷時回 SERVFAIL，validated Wi-Fi 恢復後回 NOERROR，PID 26273 不變。短暫關屏 15 秒後 DNS 成功；不是長時間 Doze 或耗電測試。實機直接 shell 啟停非 exported service 被 Android 正確拒絕，當次未完成三輪啟停，不列通過；2026-10-12 改用正式 UI 於新實機完成。證據為前述 captures 目錄下 `physical-*`。

## 2026-10-12 Android 15 實機

ASUS AI2302 / API35，使用正式候選 APK；實際安裝 SHA-256 與上列 artifact 一致。證據位於 `captures/release-physical-20261012/`。

- 從實際使用中的 v1.2.2 / code 5 執行 `adb install -r`，升為 1.3.0 / code 6；未清資料或解除安裝。UID 10340、首次安裝時間 `2026-07-24 00:35:45` 不變。
- 原 AdGuard 選取、兩個排除項目、隱藏提示偏好保留。快速捲動共擷取舊版 115、新版 117 個可見項目，共同的 113 項完全相同，兩個已排除 App 相同；前後各有只出現在其中一側的未勾選項目，因此不宣稱完整 App 清單或私有 DB 逐欄驗證。模擬器合成資料的逐欄驗證另列，不能冒稱實機資料匯出。
- 升級前後畫面上的請求／封鎖計數是程序內統計；不把升級重啟後歸零冒稱持久化統計保留。
- UDP/TCP 正常查詢與 UDP/TCP NXDOMAIN 封鎖，4/4 通過。
- 背景連續三輪 Wi-Fi→行動數據→Wi-Fi，6/6 通過。每一步核對 selected default physical network 已 VALIDATED，且 VPN `UnderlyingNetworks` 指向同一 network ID，再執行 UDP NOERROR、TCP NOERROR、封鎖 NXDOMAIN，總計 18 次查詢成功。全程同一 PID 11966，並非重啟 VPN 取得成功。
- 三輪正常 UI STOP／START 全部成功；每次 STOP 確認 active VPN type=-1、DNS VPN／recovery 前景服務不存在，START 後 DNS 成功。使用 UI，沒有變更 service exported 或繞過 Android 權限。
- 初次啟動後一次 UIAutomator 回報 null root；該擷取不是有效新畫面，不列通過。後續新 XML、真實 DNS 及系統 VPN 狀態獨立確認。原擷取與錯誤保留。
- 測後維持原本 AdGuard、VPN 開啟、Wi-Fi 開啟、行動數據開啟；測試 probe 與手機暫存 XML 移除。原使用者資料與其他 App 保留。

## 剩餘限制

[#73](https://github.com/XiangWang2000/dns-shield/issues/73) 的 IPv6-only/NAT64、真正 captive portal、完整 API/OEM/真正 LMK、8–10 小時拔線耗電 A/B 仍延期，沒有視為通過。Android 10 電池豁免與 DNS-only lockdown 邊界維持既有約定。

本候選沒有重跑完整 API26 與所有 OEM；Android 15 的此次測試沒有長時間鎖屏／Doze、故障網路下所有 in-flight DNS 交錯、非 root 實機私有 DB／FD 全量量測。短時間網路功能、元件 benchmark、bytecode 與無輪詢測試都不能證明整機耗電改善。

出包與發布前代表性原地升級／資料保留／基本功能驗收已完成。上述延期與範圍限制不被改寫為通過；依使用者指示維持候選，不發布。
