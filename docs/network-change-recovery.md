# 底層網路狀態與恢復

DNS Shield 被動觀察 Android 網路 callback，不使用 `requestNetwork` 要求或維持額外網路。候選網路可用，不等於系統已選它作為 VPN 底層路徑。

## 現行行為

- `UnderlyingNetworkStateReducer` 區分候選網路與選用路徑。已知選用路徑未變時，其他候選網路的變動不會觸發 DNS 狀態失效。
- 選用路徑或能力改變時，以 network generation 保護快取、等待中的查詢與 DoH 狀態；尚未提交的舊回應不得沿用新狀態。
- 無法唯一辨識底層路徑時回報 `UNKNOWN`，不把「尚未確認」當作已離線或已連線。實際候選網路改變仍保守處理 DNS 狀態失效。
- callback 註冊 token 與 generation 限制舊 callback／debounce 工作；延後工作讀取最新 snapshot。
- 網路變化保留使用者的解析器與加密模式設定。VPN 生命週期與底層網路狀態分開；網路恢復後繼續處理 DNS。

## 畫面狀態

服務透過唯讀 `underlyingNetworkConnectivityFlow` 發布 reducer 狀態，ViewModel 將它接入畫面。防護為 `RUNNING` 時使用下列標籤；啟動、停止或關閉狀態仍以 VPN 生命週期為準。

| 網路狀態 | 畫面標籤 |
| --- | --- |
| `UNKNOWN` | 確認網路中 |
| `OFFLINE` | 等待網路 |
| `CONNECTING` | 確認網路連線中 |
| `CAPTIVE_PORTAL` | 網路需要登入 |
| `ONLINE` | DNS 防護中 |

較舊 Android 的 VPN callback 可能只提供 transport，無法唯一關聯底層 `Network`；多個相同 transport 的候選網路也會造成歧義。因此關閉 Wi-Fi 不一定能由服務證明 `OFFLINE`，也可能是 `UNKNOWN`。

## 驗證方式與界線

日常建置／回歸使用根目錄的 `verify.ps1`，各 scope 見[開發指南](development.md)。它不會切換實機網路。

`D09WifiRecoveryDeviceTest` 的 Wi-Fi 測試先等待初始 callback，確認沒有其他非 VPN 底層網路，再驗證：

1. 已為 `ONLINE` 的防護在關閉 Wi-Fi 後產生新的 unavailable 紀錄，服務與 ViewModel 都離開 `ONLINE`，VPN 維持 `RUNNING`。
2. Wi-Fi 恢復後回到 `ONLINE`，並經實際 TUN 收到符合查詢的成功 DNS 回應。
3. 先離線啟動防護，再開 Wi-Fi 時，同樣能恢復 DNS。

這些案例不代表已完成所有 Android／廠牌、行動數據交接、真實 captive portal、IPv6-only／NAT64 或長時間耗電驗證。畫面注入狀態的測試，也不等同於實際特殊網路測試。

歷次環境、量測、失敗原因與當時待驗項目保存在[網路恢復歷史紀錄](archive/network-change-recovery.md)；整體驗收證據由[文件索引](README.md)連入。
