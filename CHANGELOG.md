# Changelog

## Unreleased

### Added

- APK 內建固定 commit、SHA-256 驗證的 1Hosts Lite `active.bin`，提供 102,972 筆廣告、追蹤與惡意網域規則。
- 加入來源下載、deterministic compilation、production artifact 驗證及 Android 實機 benchmark 流程；App 執行期間不會下載規則。
- 使用者可新增允許／封鎖網域規則、選擇是否包含子網域，並即時套用；日誌中的精確允許操作可短時間復原。
- 每組解析器可選「加密優先，允許 UDP/53 降級」或「僅加密」，並設定主要／備援 DoH 與 bootstrap IPv4。
- 支援用戶端 IPv4 TCP/53；明文模式收到截短的上游 UDP 回應時，可在原請求期限內改用 TCP/53。
- 顯示規則來源、驗證狀態及 DNS 傳輸診斷。

### Changed

- 背景成功明文查詢改為首次即時記錄、後續限流摘要；封鎖事件在背景只保留最新 100 筆，回到前景再發布並批次更新。
- 單次 UDP 主備查詢恢復共用接收緩衝；並行查詢仍各自持有緩衝，保留取消、期限與回應驗證。

- 純 Markdown 文件變更改用文件與連結檢查；程式變更保留完整 CI，並加入 D08／D15 隔離 App 與測試 APK 編譯。
- production blocklist 與 Public Suffix resolver 在同一個 VPN Service lifecycle 內只載入一次；已驗證排序狀態會供後續 policy reload 重用。
- 網路、解析器與規則變更時失效舊 DNS 狀態，防止舊回應寫入新快取或跨狀態送出；DoH client 可重用，並在設定／底層網路變更時重建。
- 限制進行中的不同查詢與合併等候數，超額回覆 SERVFAIL；回應快取採估算容量預算。
- 一般 IPv6 流量允許直接走底層網路；IPv6 DNS 封包仍不攔截。
- 用戶端查詢上限為 4,096 bytes，上游 TCP／DoH 完整回應上限為 65,535 bytes；用戶端 UDP 回應仍受 EDNS／MTU 限制。

### Fixed

- 後續解析器選取會同步已儲存的明文降級政策，即使資料列相同也能恢復一致；較新「僅加密」不被舊設定覆蓋。
- 政策提交不再等待 UDP／TCP 寫入；傳送與 TCP 清理依版本判定，保留立即「僅加密」及進行中寫入的安全邊界。

- DoH 故障冷卻依端點設定與解析器／網路 generation 隔離，避免備援互相影響或舊請求污染新狀態。
- 單次 DoH 嘗試保留主備及允許的明文降級時間，避免慢速回應耗盡總期限。
- DNS 設定操作失敗會顯示可恢復的提示，區分尚未儲存與已儲存但尚未同步；僅加密防護維持關閉明文。
- 修正 API 26 反覆 START／STOP 時，關閉 TUN 後 reader 仍可能阻塞的問題。
- 啟用／停用意圖以序列化 IO 保存；已驗證 STOP／撤銷完成後立即終止程序仍維持停用，系統背景政策限制仍適用。

### Validation and known limits

- 完整驗證與 Android 10 實機、API 26／35 模擬器的代表性回歸已通過，詳見 [共同驗收](docs/r09-common-validation.md)、[傳輸上限](docs/r08-transport-size-validation.md) 及 [API 26 STOP](docs/api26-tun-stop-validation.md)。
- Android 15 實機完成三輪 Wi-Fi／LTE 雙向切換、舊回應防護、strict 切換前後防護與行動網路雙棧驗證，詳見 [R10 驗收](docs/r10-cellular-handoff-validation.md)。
- IPv6-only／NAT64、真正 captive portal、完整 API／廠牌矩陣及真正低記憶體回收、長時間耗電仍未完成，追蹤於 [#73](https://github.com/XiangWang2000/dns-shield/issues/73)。已測 ASUS Android 10 的背景恢復需電池豁免，DNS-only lockdown 不宣稱支援。
- 本節為尚未發行的原始碼異動；正式簽名 APK 與從 v1.2.2 升級的驗證須在下一版發行前完成。

## 1.2.2 - 2026-08-21

### Changed

- 將 VPN TUN 介面改為阻塞讀取，避免閒置時持續輪詢；實機約 60 秒測試的 App CPU time 由 70.86 秒降至 0.09 秒。
- DoH 連續失敗時加入短暫退避與單一恢復探測，降低斷網期間重複 HTTPS 嘗試。
- 背景模式減少逐筆封鎖與傳輸錯誤日誌，並限制最終失敗紀錄頻率；5 個並行斷網 hostname 的失敗紀錄由 20 筆降至 3 筆。
- UDP primary／secondary fallback 共用單一查詢的 4 KiB 接收緩衝，將雙伺服器失敗路徑的該項配置減半。

### Validation

- 於 Android 10 實機、Private DNS 關閉條件下量測閒置、正常並行 DNS、DoH 故障、UDP fallback 與網路恢復。
- 完整 repository verification、signed release APK 建置、簽名驗證與實機升級測試均通過。

## 1.2.1 - 2026-08-13

### Changed

- 快取 DNS query key 的 hash，避免同一查詢在快取與 in-flight 去重流程中重複掃描 payload。
- DNS 回應封包改在單次 payload 複製時寫入 client transaction ID，移除 cache hit 與共用上游回應的中間複本。
- 內建網域比對改用無 `split` 的 label 掃描，並避免 service 與 matcher 重複正規化。
- DoH client 的同主機並行上限與 service 的 24-query throttle 對齊，並使用固定 bootstrap 位址避免 DoH hostname 解析遞迴回 VPN。

### Validation

- 新增 JVM 與 Android 實機配對 benchmark、DNS response packet 等價測試、query key 穩定性測試及 DoH bootstrap wiring 測試。
- 256 筆實機 TUN burst 測試驗證直接阻塞 reader 的 64-slot 限制器會使完成時間增加約 11%，因此該原型未納入正式版本。

## 1.1.0 - 2026-07-24

### Changed

- VPN DNS 熱路徑改由可單元測試的 `BuiltInDomainMatcher` 處理阻擋判斷，保留原有的決策快取、DNS 快取、in-flight 去重與上游解析流程。

### Added

- 本機離線 blocklist 編譯器、版本化 64-bit FNV-1a 二進位格式文件、fixture 與 Python 單元測試。

### Notes

- 離線 blocklist 產物尚未載入 App，不會改變目前 APK 的攔截範圍。
