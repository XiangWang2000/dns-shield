# D15 Always-on／系統恢復驗證紀錄

## 2026-09-29 D09 主線整合

既有 `d15-always-on` 工作樹整合 D09 head `88f075c`（含 D06 診斷與 D11 鎖安全 TUN 回應）。保留 D15 的使用者顯式啟停意圖、`START_STICKY`／空 action 恢復條件、授權撤銷處理，並接上 D06 的 `ACTION_RELOAD_DOMAIN_POLICY` 與目前測試 build variant 設定。完整 `verify.ps1` 通過：29 Python、238 JVM／46 suites 零失敗／錯誤、assets、lint、Debug/AndroidTest/D04 APK。D15 app/test APK 另行建置成功。D04 裝置測試檔使用 `ConnectivityManager.allNetworks` 的 deprecated warning 來自本次合入的 D09 測試，非 D15 產品碼。

ASUS_Z01RD／Android 10 使用已同意 VPN 權限的隔離 `.d15test` 套件，`D15ServiceSmokeTest` 2/2（1.739 秒）：顯式開啟確實到達 RUNNING、顯式停止到達 STOPPED；停止後再送空 action 仍保持 STOPPED，持久化的 desiredEnabled 為 false。測試前後清除隔離偏好，不觸及正式套件資料。原始輸出位於本工作樹 ignored `captures/d15-d09-device-lifecycle-final.txt` 與 `captures/d15-d09-final-verify.log`。

系統 VPN 設定有多個同名 DNS Shield 項目，尚無法從該畫面確定哪一項對應 `.d15test`。本次沒有更改 Always-on／lockdown 系統設定，也沒有把嘗試 `stopService`（系統仍綁定 VPN）視為程序重建。重開機、系統程序回收、自動恢復、VPN 切換、授權撤銷及 lockdown 路徑仍需實機矩陣；Issue #48 與 PR #63 維持 In Progress／Draft。