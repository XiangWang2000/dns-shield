# Issue #73 入口登入與重開機驗收

2026-11-12 使用 DNS Shield v1.5.0（版本代碼 9）的正式簽署 APK。兩台隔離模擬器及 ASUS 都核對已安裝 APK 的 SHA-256 為 0730b8eddac56e5bd88345ccf259739b5f2a04fcd1db2a7a400b1d0dcf910216。驗收範圍見 [Issue #73](https://github.com/XiangWang2000/dns-shield/issues/73)。

## Android 15／API 35 模擬器的入口登入

在隔離模擬器使用系統 DNS，關閉模擬行動數據，由 Wi-Fi 連到主機上的受控 HTTP 入口。Android NetworkMonitor 的探測在一般狀態收到 204。切到入口登入測試後，Wi-Fi 出站除測試入口和必要網路控制封包外均被拒絕，探測收到 302 並指向登入頁。

- Android 將 Wi-Fi 標記為 CAPTIVE_PORTAL，尚未驗證。DNS Shield 顯示「網路需要登入」。
- 從 Android 的 Wi-Fi 設定點選該網路的登入入口，系統的 CaptivePortalLogin Activity 顯示測試頁。按下登入後，主機收到 POST，後續探測回覆 204，Android 將同一個 Wi-Fi 網路標為 VALIDATED。登入通知也有出現；本輪完成流程的入口是 Wi-Fi 設定。
- 連線前、登入前及登入後的 VPN PID、VPN 網路 ID 和 tun0 均相同。登入後 App 顯示「DNS 防護中」。直接送到本機 VPN DNS 的 UDP 查詢，example.com 回覆 NOERROR、兩筆答案，supportmetrics.apple.com 回覆 NXDOMAIN，交易 ID 均與查詢相符。

本輪驗證了受控入口的 Android 實際探測、登入及 DNS 恢復。Android 的 HTTP 探測設定見 [Android NetworkStack](https://android.googlesource.com/platform/packages/modules/NetworkStack/+/4e440c3e/src/com/android/networkstack/util/NetworkStackUtils.java)。

## Android 8／API 26 模擬器的重開機

用 Google DNS 啟用正式 App，在 Android 設定開啟「永久連線的 VPN」，關閉 lockdown。兩次實際重開的 boot ID 都有改變，桌面仍在前景時，VPN 服務和 tun0 已恢復。第一輪重開後，在未開啟 App 的情況下送出兩筆經 tun0 的 TCP DNS 查詢。example.com 回覆 NOERROR、兩筆答案，supportmetrics.apple.com 回覆 NXDOMAIN。兩個回應的交易 ID 和 DNS-over-TCP 長度都正確。

## ASUS Android 10 實機的熱點嘗試

建立單次工作階段的 Windows 熱點，讓 ASUS 實際連上 Wi-Fi。手機連到熱點上的本機 HTTP 測試服務，收到 200 回覆。這台 Android 10 在實驗中仍向預設 Google 驗證網域發出探測，並在熱點上遇到 DNS 失敗。手機當時顯示未驗證，但沒有進入 CAPTIVE_PORTAL，測試服務也沒有收到 Android 的入口探測。因此這輪記為實機到測試服務的連線通過，實機完整入口登入尚待測。

測試結束後還原探測設定，從手機設定清除測試 Wi-Fi，關閉熱點與 HTTP 服務。確認 ASUS 回到原本 Wi-Fi 且已驗證，系統 DNS 仍啟用，原 VPN 行程及通道仍在。回到原網路後，公開網域解析與本機封鎖均再驗證成功。

## 後續驗收

目前 [API 35 的 IPv6-only／NAT64 證據](../development.md)仍屬受控模擬器環境。ASUS 尚需能接入的 IPv6-only／DNS64／NAT64 測試網路及能實際攔截系統探測的入口網路。跨廠牌背景管理、系統低記憶體回收後的恢復，以及同機拔電 8–10 小時耗電 A/B 仍由 #73 追蹤。

本機原始結果在 build/issue-73-lab。入口登入含 api35-portal-acceptance.json、portal-http.jsonl 和系統登入畫面；重開機含 api26-after-reboot-1.json、api26-after-reboot-2.json 和 api26-probes.json；ASUS 含 asus-portal-acceptance.json 和 asus-portal-reachability.json。
