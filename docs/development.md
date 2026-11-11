# 技術與開發指南

本頁記錄目前可用的開發、驗證、資產維護與正式簽章流程。產品功能與使用者說明見 [README](../README.md)；完整資料處理方式見 [PRIVACY.md](../PRIVACY.md)。

所有命令都從 repository 根目錄執行。

## 開發環境與建置

使用 JDK 21；Windows 優先採用 Android Studio 內附 JBR。專案另需 Android SDK Platform 37、NDK 27.2.12479018、Python 3 與 Git。Gradle Wrapper 和 Android／Python 依賴版本由 repository 固定。

新 checkout 請初始化遞迴子模組：

~~~powershell
git submodule update --init --recursive
~~~

設定 Android SDK 路徑於環境變數或本機的 local.properties。此檔含機器路徑，不要提交。Windows PowerShell 可明確選用 JBR：

~~~powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
~~~

完整本機驗證使用唯一入口：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./verify.ps1
~~~

verify.ps1 會檢查 PowerShell 腳本語法、Python 工具、production blocklist 與 Public Suffix assets，執行 Android lint、JVM 測試及 Kotlin 編譯，並建置 Debug 與隔離 instrumentation variants。建置 androidTest APK 不等於執行裝置測試；此入口不會自動執行 adb instrumentation。

## 程式結構

| 路徑 | 責任 |
| --- | --- |
| [MainActivity.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/MainActivity.kt)、[ManagementTabs.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/ui/ManagementTabs.kt) 與 ui/theme | Compose 控制中心、設定與狀態呈現。 |
| [viewmodel/DnsVpnViewModel.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/viewmodel/DnsVpnViewModel.kt) | UI state、Room 資料、App 排除名單與 VPN 操作。 |
| [data/](../app/src/main/java/io/github/xiangwang2000/dnsshield/data) | DNS 設定、網域規則與排除 App 的 Room 資料。 |
| [blocking/](../app/src/main/java/io/github/xiangwang2000/dnsshield/blocking) | 規則比對、compiled blocklist、Public Suffix 載入及政策組裝。 |
| [service/DnsVpnService.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/DnsVpnService.kt) 與 [service/](../app/src/main/java/io/github/xiangwang2000/dnsshield/service) | VPN／TUN 生命週期、DNS 查詢、網路切換、快取、上游傳輸與診斷。 |
| [app/src/main/cpp/](../app/src/main/cpp) 與 NativeDnsTcpRuntime、SocksDnsServer | 用於轉送用戶端 TCP/53 DNS 的 JNI／Hev 與 SOCKS 橋接。 |
| [app/src/main/assets/](../app/src/main/assets) | 隨 APK 發布並由工具驗證的 production 資產。 |
| [tools/](../tools)、[app/src/test/](../app/src/test)、app/src/androidTest variants | 離線資產工具、CI、JVM 與隔離裝置測試。 |

DNS Shield 是 DNS 層工具：VPN 只攔截送往本機虛擬 IPv4／IPv6 DNS 位址的 UDP／TCP 53 查詢，其餘 IPv4／IPv6 流量仍轉送至底層網路。App 直接送往其他外部 DNS 位址的查詢、App 自行使用的 DoH／DoT 與直接 IP 連線不會被攔截。App 例外清單只用於使用者選擇略過 VPN 的 App；QUERY_ALL_PACKAGES 用途與資料邊界見 [隱私說明](../PRIVACY.md)。規則順序與 Public Suffix 邊界見 [blocking policy](blocking-policy.md)。

## 驗證範圍與 CI

verify.ps1 支援 Full、Core、Selected、Isolated。Selected 與 Isolated 必須指定 -Variants；可用 d03、d04、d08、d14、d15。

| Scope | 執行內容 |
| --- | --- |
| Full | 預設範圍；一般驗證加上全部隔離 variants 的 APK 建置。 |
| Core | 共用 preflight 與一般 Android build、lint、JVM 測試。 |
| Selected | Core 加上指定 variants 的 APK 建置。 |
| Isolated | 共用 preflight 加上指定 variants；略過一般 Android build 區塊。 |

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./verify.ps1 -Scope Core
powershell -NoProfile -ExecutionPolicy Bypass -File ./verify.ps1 -Scope Selected -Variants d04,d14
powershell -NoProfile -ExecutionPolicy Bypass -File ./verify.ps1 -Scope Isolated -Variants d15
~~~

CI 依變更分類分派同一個 verify.ps1，Full 由 Core 與 Isolated partitions 合作完成。Windows tooling job 另檢查工具與 dispatcher。CI 會執行文件檢查：

~~~powershell
python tools/ci.py verify-docs
~~~

文件變更可先跑文件檢查；程式、依賴、build 設定或 packaged data 變更則依 repository 要求執行完整 verify.ps1。遇到失敗時，先定位並修正第一個失敗步驟，再選足以驗證修正的範圍；只有完整入口仍是本次必需檢查，或仍有未解風險時，才重跑 Full。保留 Gradle、Python 與 JVM 原始錯誤；舊報告的測試數字不能代替本次結果。CI 會建置 instrumentation APK，但不代表裝置案例已執行。

### IPv6 DNS 範圍與驗證限制

VPN 只為本機虛擬 DNS 位址 10.0.0.1/32 與 fd29:1a5d:7c0d::1/128 加入路由；一般流量仍轉送至底層網路。若虛擬 IPv6 前綴與底層網路衝突，啟動會失敗；執行中偵測到衝突則停止 VPN。

封包解析器不重組 IPv6 分片，因此拒絕需要重組的非 atomic 分片；接受 atomic fragment 與數量、長度受限的延伸標頭。IPv6 MTU 1500 時，UDP DNS 回應負載上限為 1,452 bytes；超過上限會以 TC 標記，讓客戶端改用 DNS-over-TCP。DNS-over-TCP 支援完整 DNS 訊息，不受 UDP 負載上限限制。

同一個底層網路的位址、路由、DNS 伺服器或 NAT64 前綴變更，也會清除舊 DNS 快取與重建上游連線。API 30 起可監看 Android 回報的 NAT64 前綴；API 24–29 只能依公開的位址、路由與 DNS 變更判斷，無法直接偵測僅 NAT64 前綴改變的情況。

API 35 模擬器已在受控雙棧及 IPv6-only 網路（有、無 464XLAT）驗證 IPv6 DNS 主備、DNS64／NAT64、嚴格 DoH 備援與一般 IPv6 流量。公開 DoH 在這個環境經 NAT64 連線。API 26 已測虛擬 IPv4／IPv6 DNS，未以同一套受控底層網路驗收。App 不提供 DNS64 合成或 NAT64 閘道；這些結果不涵蓋所有 Android 版本、實機廠牌與電信商網路。

### System DNS 與 EDNS

「系統 DNS」是 Android 10 以上可選用的解析器，使用目前底層網路的 Android `DnsResolver`；DNS 加密沿用 Android「私人 DNS」設定。此選項預設不會啟用，也不會替使用者變更系統設定。其他解析器則依 DNS Shield 儲存的 DoH、UDP 或 TCP 設定傳送。

DNS Shield 保留客戶端 EDNS UDP payload size，並將上游值限制在 512 至 4,096 bytes；沒有 EDNS 的查詢以 512 bytes 為上限。送回客戶端的 UDP 回應還會受 TUN MTU 限制，超出上限時以截短回應和 TC 標記處理。系統 DNS 對符合條件的單一問題查詢遇到特定 Android resolver 系統錯誤或無效回應時，會以 4,096 bytes 的 EDNS payload 重試；若原始查詢沒有 EDNS，回傳前會移除重試用的合成 OPT 記錄。

## 資產維護

Active blocklist 的兩份固定來源、合併後來源及 production contract 分別記錄在 [active_blocklist_source.json](../tools/active_blocklist_source.json) 和 [active_blocklist_production.json](../tools/active_blocklist_production.json)。更新或重建時使用：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/prepare-active-blocklist-production.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/install-active-blocklist-asset.ps1
~~~

Installer 會在安裝前驗證候選資產；不要手動覆寫 app/src/main/assets/active.bin。App 執行時不下載 blocklist；更新只隨已驗證的 APK 發布。格式與 runtime fallback 見 [blocklist-format.md](blocklist-format.md)。

Public Suffix source、格式、production gate、APK staging gate 和目前 runtime 接線見 [public-suffix.md](public-suffix.md)。歷史驗收只作該次測試證據：[共同驗收](archive/r09-common-validation.md)、[行動網路切換](archive/r10-cellular-handoff-validation.md)、[R17–R19 背景工作](archive/r17-r19-background-work-validation.md)。這些報告不是當前驗收狀態。

## 正式簽章與發版

新版本需在 app/build.gradle.kts 更新 versionName 並遞增 versionCode，沿用原有 applicationId 與簽章金鑰。腳本不會自動調整版本或發布 GitHub Release；發版時需一併提供 APK、SHA-256 sidecar 與 `blocklist-source.zip`。來源壓縮檔需包含兩份固定的原始清單、合併後的網域文字、重建工具、manifest 及授權告知。

首次建立上傳金鑰時執行：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/setup-release-signing.ps1
~~~

腳本會產生 release/dns-shield-upload.p12 與根目錄 keystore.properties；repository 的 .gitignore 排除 *.p12 和 keystore.properties。兩者都是簽章機密：安全備份，不要提交、放入 captures、貼入日誌或傳送到公開位置。不要將密碼寫進文件或指令歷史。正式升級必須沿用相同簽章金鑰，遺失會使既有安裝無法由新 APK 直接升級。

完成本次程式與資產驗證後，從根目錄執行：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release.ps1 -BaselineApk "C:\release\dns-shield-v1.4.0.apk"
~~~

`BaselineApk` 必須指向可信任的既有正式 APK，建議使用目前最新公開版本。腳本會先驗證基準 APK 簽章與中繼資料，再執行 Full verify.ps1、建置 Release APK，並要求新版的 applicationId 相同、versionCode 較高且簽章憑證相同。相容性檢查前會清除上次產生的 SHA-256 sidecar，只有通過檢查才會寫入新版 sidecar。CI 另用短期測試金鑰建置並驗證 Release APK，該金鑰只用於建置檢查，不能用來發布或升級正式安裝。

根目錄的 `.codex-remote-attachments/` 是本機附件暫存目錄，已加入 `.gitignore`，其中檔案不應放入版本控制。
