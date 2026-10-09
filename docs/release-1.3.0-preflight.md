# 1.3.0 發版前獨立審查（2026-10-09）

狀態：獨立審查通過，可進入出包與實機驗收。正式簽章 APK 已完成，API35 模擬器原地升級與基本功能通過；實機驗收尚未完成，禁止發布。沒有遠端 push、tag 或 Release。

## 審查對象與結論

- 最新 main / PR #99 merge：`e23d3793e6cc7db9aef8fdc6382f2a261136bbb8`。與 PR head `24537ce8b293e101373eaf46ce831a80b280441f` tree 相同；產品 source 來自 `eba51bb048f7d033b7df89731084eab1ec81b9e4`。
- 本機發版候選：`1deddcdb1dc8e6d03a074afd477114e50ae5a9f9`，版本 `1.3.0` / `versionCode 6`。相對審查 main，產品程式邏輯、assets、依賴均未變；只提高版本並加入兩個測試及版本文件。
- 沒有找到具有具體證據與影響的產品發版阻擋。生命週期／併發／資源釋放與背景工作分由兩位獨立審查者檢查，主審核對原始紀錄、整合測試與出包流程。
- 本機候選沒有新的遠端 CI；不以 main 的 CI 冒稱此 commit 的 CI。PR exact-head [37906777788](https://github.com/XiangWang2000/dns-shield/actions/runs/37906777788) 與 exact-main [37908709301](https://github.com/XiangWang2000/dns-shield/actions/runs/37908709301) 均成功。

## PR #99 / issues #95–#98

- #95 / R17：背景明文成功首次記錄，其後以單調時鐘共用 60 秒 gate；跨 transport / resolver 交錯不恢復逐筆輸出，受抑制訊息不格式化，沒有新增 timer。
- #96 / R18：背景只保留 bounded deque 最新 100 筆，前景立即發布，之後以 300 ms 批次合併；鎖與 generation 避免 clear / 取消 flush 後資料復活。
- #97 / R19：單次順序 UDP 主備共用 4,097-byte 接收 buffer；並行查詢、回傳複本、溢出檢測、取消與 deadline 維持獨立。
- #98 / R20：結案的是評估；未導入 parser fast path。保留現有驗證正確性，不把 JVM 元件 benchmark 當作 Android 或整機收益。
- 四項 issue 已 Closed；PR #99 已 merged。原始歷史報告與本次新測試分開列示。

## 首次容量 SERVFAIL 的追查

原始證據位於 `C:/Users/User/.codex/worktrees/d05-bounded-admission/dns-shield/captures/`：

- `r17-r20-api35-safety-regression.txt`：第一個 backoff 案例 `expected 0 / actual 2`，對應原測試行 645 的第一筆查詢；其餘十項成功。
- `r17-r20-api35-backoff-logcat.txt` 行 635–647：08:38:25.974 TUN reader 啟動，08:38:32.570 對 `0x8400` 記錄容量已滿並立即回 SERVFAIL，隨後測試失敗。該區間沒有「網路連線正常」訊息。
- 同一檔行 900–912 的重跑：有 08:39:45.774 網路連線正常，接著成功。`r17-r20-api35-first-logcat.txt` 的保存窗口已錯過首次失敗，不能單獨用它還原原因。
- 原測試每 500 ms 在同一 socket 重送相同 query，最長 12 秒；產品的單 key 上限是 leader + 8 waiters，總 deadline 6 秒。因此未完成查詢的第十個 datagram 可於約 4.5 秒觸發容量拒絕，不需 24 個不同查詢，更不需存在資源洩漏。

本次保留原失敗測試與 assertion，不增加自動重跑。另新增真實 TUN / TLS 雙上游受控延遲案例（沒有新增產品 hooks 或政策變更）：

- 相同 500 ms 重送：`coalesced=8`、`overloaded=1`、`pending=9`；客戶端先收到 SERVFAIL。主、備各只有一個 DoH request，明文 UDP 0。
- 釋出上游後：9 筆完成，`pending=0`，`received=terminalCount`，下一個新 QNAME 得到 NOERROR。
- 相近慢上游只送一次：NOERROR、一個答案，`coalesced=0`、`overloaded=0`，完成後 pending 0；下一筆也成功。
- 初次兩案例 2/2（14.288 s）；加入 drain 與後續查詢斷言後 2/2（19.296 s）。見本機 `captures/release-review-20261009/capacity-controlled.txt`、`capacity-drain.txt`、`capacity-drain-logcat.txt`。

**可確定**：原失敗走容量拒絕分支；測試重送足以獨立造成相同 SERVFAIL，受控情境無名額未釋放。**仍不能確定**：原始當次是同 key waiter 上限或 unique-key 上限，以及 leader 變慢的唯一原因。原始 log 沒有 admission snapshot、每次接收時間與完整網路 callback 時序；缺少網路正常訊息只是線索，不是已證實的原因。故沒有把重跑成功當作缺陷修復，也沒有將原失敗改寫為通過。

必要的驗收方法修正已完成：保留失敗、明確證據界線、新增能重現失敗並驗證回收的案例。後續可將該 backoff 測試的 readiness 與重送責任分開，或增加 rejection reason 的有界診斷；本輪不改產品容量或重試政策。

## 正確性、生命週期與省電機制

- 對照 `0022b34772a73a17cdd69ba421dd7987db280967`：TUN 仍為阻塞讀取；失敗 DoH 仍有 threshold / cooldown / 單一恢復探測；背景失敗日誌仍有 5 秒 gate；UDP 單次主備接收 buffer 重用已恢復。
- resolver / network / policy generation fence、舊回應快取失效、STRICT 禁止明文、immutable response commit 後才在 state lock 外寫入的邊界均保留。
- STOP 取消 session、關閉 owned input 喚醒 reader、join 後關閉共享 descriptor；late TunnelEnded 依 generation / descriptor / state 排除。網路 callback 解除時清除 pending flag；query completion handler 釋放 lease。
- 可延後：網路變更期間每個待處理 leader 仍可能每 25 ms 檢查 pending flag（受 debounce 與 deadline 限制，不是閒置常駐輪詢）；受抑制成功日誌仍可能建立 capturing lambda。兩者均無本次可證實的整機耗電退化，沒有據此要求發版前重構。
- 新 API35 元件量測與歷史 JVM benchmark 只證明該工作負載的成本；沒有拔線長時間 paired power 測量，不宣稱整機省電百分比。

## 本次執行的驗證

| 檢查 | 結果與範圍 |
| --- | --- |
| `verify.ps1` on reviewed main | 37 Python、322 JVM / 52 suites，0 failure / error / skip；lint、assets 與必要 APK 建置通過。 |
| lint | 24 個既有 Warning，ID / message 與 PR99 本機報告相同；無新 lint 警告。本輪主機 log 無 Kotlin compiler warning，不等同所有 cached task 重新審核。 |
| 新建置 D08 API35 | 17/17，54.322 s：原 backoff、TLS／slow DoH／ALLOW／STRICT／resolver、背景診斷及 schema 1→3 / 2→3 遷移。安裝 hash 與本機 APK 相符。 |
| D15 API35 | 8/8，5.264 s：START/STOP/recovery、持久化與真實 ViewModel 失敗接線；撤銷授權另 1/1，3.091 s。 |
| 新容量受控案例 | 2/2；包括故意重現 SERVFAIL、單次傳送对照、pending 歸零與後續新查詢成功。 |
| `release.ps1` on 1deddcd | exit 0；完整 37 Python / 322 JVM、lint、必要 APK 建置重跑通過；正式簽章 APK 建置與 `apksigner verify` 通過。 |
| 正式 APK 基本功能 | UDP / TCP 正常查詢 2/2、UDP / TCP 封鎖 NXDOMAIN 2/2、背景解析 1/1；三輪 STOP/START 與重啟後 DNS 均通過，三輪 running FD 各 143，STOP 後 active VPN type=-1 且服務列表為空。 |

本次環境前提失敗也保留：初次 root checkout 的 `hev` 子模組未初始化，NDK 報 missing module；按釘選 SHA 初始化 recursive submodules 後完整通過。模擬器 quickboot 的舊 APK hash 不符，試跑缺少新測試 class；該結果不計入候選驗收，改安裝並核對本輪 APK。舊版正式 App 用 shell 直接 START 在未 prepare VPN 時回 null；從正常 UI 開關執行 prepare 後建立 TUN，`example.com` UDP 解析成功。這些前提失敗沒有被覆寫。

## 正式 APK 與原地升級

- APK：`captures/release-review-20261009/release-1.3.0/app-release.apk`；同目錄有 `.sha256`。檔案大小 16,439,071 bytes。
- APK SHA-256：`b168e6db1741d8255b7dbae98150a4fe85ef4233cd5ac991720ed7c8eb31877b`。
- 簽章憑證 SHA-256：`9ff66cac6960bf10c2660df9f590ebf07ccd9784dae7756e4242007c9e867989`，與下載之公開 v1.2.2 完全相同。保留既有發行金鑰，沒有重建金鑰。
- 套件 ID 不變，versionName 1.3.0 / code 6、minSdk 24 / targetSdk 37；非 debuggable。四個 ABI 的 native TCP library 均存在，封裝 active.bin / public_suffix.bin 與已驗證 source bytes 相同，無 D08 TLS fixture。
- APK 內 `META-INF/version-control-info.textproto` 記錄 source commit `1deddcdb1dc8e6d03a074afd477114e50ae5a9f9`。本報告的後續提交只修改文件。
- 真正安裝公開 v1.2.2（SHA-256 `e77cd89a859a95dc9dfbb9582cc6f0efa0b9b35636787595243863777b7af627`），由其 Room schema 1 建立合成驗收資料，再用 `adb install -r` 升級本次正式 APK，沒有解除安裝或清資料。
- 5 筆 DNS 設定逐欄一致，自訂 active resolver ID 77、1 筆 bypass 與 `info_card_visible=false` 保留；新增 policy 欄位預設正確，schema 1→3，UID 10158 與初次安裝時間不變。見 `upgrade-result.json`、`upgrade-expected.json`、`verify-upgrade.py` 與原始 DB；全部是本次模擬器合成資料，沒有匯出實機私有資料。
- 44.196 秒背景 VPN 區間，process CPU 增量 0.12 秒（100 ticks/s）。這是單一 API35 模擬器觀察，沒有 before/after 配對、功率或電量測量；只能支持該區間沒有重現 idle busy-spin，不能量化省電。
- 啟停檢查腳本最初錯用 `NetworkCapabilities` 中仍保留的 VPN transport 當成 active；當時實際 type=-1、服務列表已空。原始 dump 保留在 `stop-checker-original-*`；改查 `Active vpn type` 與真實服務紀錄後三輪通過，不是產品修正。最終腳本及結果為 `release-lifecycle.py/json`。

## 剩餘限制與發布前實機步驟

[#73](https://github.com/XiangWang2000/dns-shield/issues/73) 維持四項延期：IPv6-only/NAT64、真正 captive portal、完整 API/OEM/真正 LMK、8–10 小時拔線耗電 A/B。Android 10 電池豁免與 DNS-only lockdown 邊界不變。歷史實機 Wi-Fi↔LTE 已測，不冒稱本次候選又在實機重測。

本次沒有 USB 實機連線，也未在本候選重跑 API26 或 Android10 實機；歷史結果不冒稱本次通過。以下實機驗收尚未通過，不與模擬器結果混用：

1. 手機保留既有 v1.2.2，不解除安裝、不清除資料；記錄自訂 DNS、目前啟用 DNS、繞過 App 與偏好設定。
2. 連接 USB、開啟 USB 偵錯並同意此電腦；用 `adb devices -l` 確認實機 serial。
3. 執行 `adb -s <實機serial> install -r <本報告正式APK路徑>`。若簽章不符立即停止，不用解除安裝繞過。
4. 開 App 確認 1.3.0 / 6，以及步驟 1 的所有資料。舊版没有使用者網域規則；schema 2→3 規則保留另由 instrumentation 驗證。
5. 啟停三輪；正常網頁、封鎖、解析器切換、僅加密模式；回背景／鎖屏後再回前景，確認仍可用且日誌／計數更新。以暫時規則測試時，測完移除測試規則。
6. 在同一 VPN 做 Wi-Fi→行動數據→Wi-Fi，檢查 DNS、一般 IPv4/IPv6 連線；記錄機型、Android、每項結果與異常時間。

實機原地升級、資料保留與基本功能確認完成前，保持「候選 APK，禁止發布」。本次不建立 tag、不推送、不上傳 APK。
