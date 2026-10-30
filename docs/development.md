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

DNS Shield 是 DNS 層工具：VPN 路由涵蓋 IPv4 UDP/TCP 53，不攔截一般流量、IPv6 DNS、App 自行使用的 DoH／DoT 或直接 IP 連線。App 例外清單只用於使用者選擇略過 VPN 的 App；QUERY_ALL_PACKAGES 用途與資料邊界見 [隱私說明](../PRIVACY.md)。規則順序與 Public Suffix 邊界見 [blocking policy](blocking-policy.md)。

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

## 資產維護

Active blocklist 的 pinned source 與 production contract 分別在 [active_blocklist_source.json](../tools/active_blocklist_source.json) 和 [active_blocklist_production.json](../tools/active_blocklist_production.json)。更新或重建時使用：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/prepare-active-blocklist-production.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/install-active-blocklist-asset.ps1
~~~

Installer 會在安裝前驗證候選資產；不要手動覆寫 app/src/main/assets/active.bin。App 執行時不下載 blocklist；更新只隨已驗證的 APK 發布。格式與 runtime fallback 見 [blocklist-format.md](blocklist-format.md)。

Public Suffix source、格式、production gate、APK staging gate 和目前 runtime 接線見 [public-suffix.md](public-suffix.md)。歷史驗收只作該次測試證據：[共同驗收](archive/r09-common-validation.md)、[行動網路切換](archive/r10-cellular-handoff-validation.md)、[R17–R19 背景工作](archive/r17-r19-background-work-validation.md)。這些報告不是當前驗收狀態。

## 正式簽章與發版

新版本需在 app/build.gradle.kts 更新 versionName 並遞增 versionCode，沿用原有 applicationId 與簽章金鑰。腳本不會自動調整版本或發布 GitHub Release；發版時需一併提供 APK 與 SHA-256 sidecar。

首次建立上傳金鑰時執行：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/setup-release-signing.ps1
~~~

腳本會產生 release/dns-shield-upload.p12 與根目錄 keystore.properties；repository 的 .gitignore 排除 *.p12 和 keystore.properties。兩者都是簽章機密：安全備份，不要提交、放入 captures、貼入日誌或傳送到公開位置。不要將密碼寫進文件或指令歷史。正式升級必須沿用相同簽章金鑰，遺失會使既有安裝無法由新 APK 直接升級。

完成本次程式與資產驗證後，從根目錄執行：

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/release.ps1
~~~

Release script 會先執行 Full verify.ps1，再建置 Release APK、檢查 APK 簽章並產生 SHA-256 sidecar。發版前仍需人工確認版本、簽章憑證與此次驗收證據。
