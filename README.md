# DNS Shield

<img src="app/src/main/res/drawable/dns_shield_icon_1780828904628.png" width="96" alt="DNS Shield 應用程式圖示">

DNS Shield 讓你決定要攔哪些網域、查詢交給誰解析。用 1Hosts Lite 與自訂規則封鎖常見廣告、追蹤和惡意網域，解析器也能自行選擇。Android 7.0（API 24）以上可用，不需 Root。

## 你可以決定

- **擋哪些網域：** 使用 APK 內附的 1Hosts Lite，也可新增允許或封鎖規則。名單隨 APK 更新，App 執行時不會另行下載。
- **交給誰解析：** 選擇 Google、Cloudflare、AdGuard、Quad9，或自訂 DNS／DoH。
- **加密失敗怎麼辦：** 預設加密優先，DoH 故障時可降級為明文 UDP/53；選「僅加密」則故障時回報解析錯誤，不送出明文 DNS。
- **App 例外與記錄：** 排除指定 App，查看查詢統計與即時診斷日誌。

## 安裝與啟動

1. 從 [GitHub Releases](https://github.com/XiangWang2000/dns-shield/releases) 下載並安裝 APK。
2. 開啟 DNS Shield，選擇解析器與加密模式。
3. 啟用防護，同意 Android VPN 權限，確認 App 顯示已啟用與系統 VPN 指示。

> 本頁依目前原始碼介紹功能；已發布 APK 可能尚未包含所有新功能，請以 [GitHub Releases](https://github.com/XiangWang2000/dns-shield/releases) 的版本說明為準。直接升級需使用相同簽名的 APK。

## 隱私

DNS Shield 沒有帳號、分析或廣告 SDK，也沒有開發者後端。DNS 設定、網域規則與 App 排除名單留在裝置；未被封鎖的查詢會送到你選擇的第三方解析器，資料保存方式依各解析器政策。

DoH 透過 HTTPS 傳輸；降級至 UDP/53 時，查詢未加密。DNS Shield 不在本機驗證 DNSSEC。查詢計數與即時日誌主要保存在 App 記憶體。詳見[隱私權說明](PRIVACY.md)。

## 防護範圍與限制

本機 VPN 只攔截 IPv4 UDP／TCP 53 的 DNS 查詢。一般 IPv4／IPv6 流量仍走原本網路；IPv6 DNS、App 自帶的 DoH／DoT 與直接 IP 連線不會被攔截。同一網域若同時提供廣告與正常內容，也無法只封鎖廣告。

部分手機的電池或背景管理會阻止 VPN 恢復；已測的 ASUS Android 10 裝置需要替 DNS Shield 設定電池豁免。Android 系統 Always-on 可用；目前不支援封鎖未經 VPN 的連線（lockdown）。

<details>
<summary>驗收報告與待補項目</summary>

- 共通驗收：[共同驗收](docs/r09-common-validation.md)。
- Wi-Fi／行動數據切換：[驗收報告](docs/r10-cellular-handoff-validation.md)。
- 尚待特殊網路、裝置與長時間測試環境：IPv6-only／NAT64、真實 captive portal、完整 Android API／廠牌矩陣與真正低記憶體終止（LMK）、8–10 小時離電耗電 A/B；追蹤於 [#73](https://github.com/XiangWang2000/dns-shield/issues/73)。

</details>

## 開發

開發環境、架構與建置方式請看[技術與開發指南](docs/development.md)；版本異動見[CHANGELOG.md](CHANGELOG.md)，第三方資料與授權見[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 授權

Copyright 2026 XiangWang2000

DNS Shield is licensed under the [Apache License 2.0](LICENSE).
