# DNS Shield 技術與開發指南

基本功能與安裝方式見 [README](../README.md)。本文件保留 DNS 處理、規則、權限、架構、測試與維護的詳細說明。

## 功能

- 使用 Android `VpnService` 建立僅涵蓋指定 DNS 位址的本機介面。
- 內建 Google DNS、Cloudflare DNS、AdGuard DNS 與 Quad9 預設值。
- 可為每組解析器選擇「加密優先，允許 UDP/53 降級」或「僅加密」；舊設定升級後保留原本的明文降級行為。
- 支援自訂 HTTPS DoH 主要與備援端點；自訂主機名稱使用明確的 bootstrap IPv4 位址，並保留 HTTPS 憑證及 hostname 驗證。
- 依內建規則與 APK 內固定版本的 1Hosts Lite compiled blocklist，以 NXDOMAIN 回覆廣告、追蹤及惡意網域。
- 阻擋規則已由可單元測試的 `DomainMatcher` 元件處理，並保留既有的決策快取與 VPN DNS 熱路徑行為。
- APK 內的 `active.bin` 含 102,972 筆固定來源規則；若 App 私有 `blocklists/active.bin` 存在，則作為本機 override。parent-domain matching 受 APK 內已驗證的 Public Suffix List 邊界限制。
- 控制中心會顯示目前規則來源、revision、日期、筆數、驗證狀態，以及 Public Suffix List 是否降級為精確網域比對。
- 支援自訂 DNS、DNS 回應快取及同時重複查詢去重；最多容納 24 個不同的進行中查詢 key，每個 key 最多合併 8 個等候查詢，超額立即回覆 SERVFAIL；快取命中等快速路徑不受此 admission 配額限制。
- 底層網路或解析器設定變更時，會更新 generation、失效舊快取並重建相關 DoH client；規則更新會重載政策快照與清除快取。回應送出前再次檢查狀態，避免舊回應跨越變更。
- 明文降級模式遇到上游 UDP 截短回應時，會在原請求期限內以 TCP/53 重試；TUN MTU 設為 1500 bytes，送回用戶端的 DNS payload 上限為 min(EDNS/512 bytes, MTU−28 bytes = 1472 bytes)，超出時只保留完整資源記錄、設定 TC 並更新 section counts。
- DNS 用戶端查詢（UDP/TCP）上限為 4,096 bytes，較大的查詢不支援；上游 TCP/53 與 DoH 的完整 DNS 回應上限為 65,535 bytes。送回用戶端的 UDP 回應仍受 EDNS 與 TUN MTU 限制，超出時會在完整資源記錄邊界截斷並設定 TC。
- 支援選擇具有啟動入口的已安裝 App，使其略過 DNS Shield VPN。
- 在 App 開啟時顯示查詢數、阻擋數、估算節省流量與診斷日誌。

## 使用者網域規則

- 可新增允許或封鎖規則，並以網域名稱搜尋或刪除規則；資料保存在裝置的 Room 資料庫。
- 精確規則只適用於該網域；「包含子網域」會同時套用於該網域及其子網域，並拒絕公共後綴本身。
- 規則名稱會轉成小寫 ASCII IDNA 格式並移除一個結尾句點；子網域比對以 DNS 標籤邊界進行，因此 `example.com` 不會匹配 `lookalike-example.com`。
- 使用者規則優先於內建及編譯防護名單；多條規則同時匹配時，最精確的網域優先。相同網域與範圍的新規則會取代舊規則。
- 啟用 VPN 時，新增或刪除規則會即時重載不可變政策快照並清除舊決策與 DNS 回應快取；VPN 關閉時，規則會在下次啟動時載入。
- 偵測到封鎖時，運作日誌提供精確允許操作；短時間內可復原，復原會還原被取代的原規則。子網域範圍只有在已驗證的 PSL 可用時才能新增。

## 能力邊界

DNS Shield 是 DNS 層工具，不是完整流量 VPN、防毒軟體或防火牆：

- 目前原始碼支援送往虛擬 DNS 的 IPv4 UDP/53 與 TCP/53 查詢；TCP/53 已在 Android 10 實機與 Android 15 模擬器驗證真實 TUN 查詢、UDP TC 後重試、32 條連線容量、idle timeout 與停止清理。已安裝的舊版 APK 需更新後才包含此功能；詳見 [D11 驗證紀錄](d11-runtime-validation.md)。
- 啟用 VPN 時明確允許 IPv6 位址族；底層網路支援時，一般 IPv6 連線走底層網路，不進入 DNS Shield TUN，也不套用 DNS Shield 網域規則。IPv4 UDP/TCP 53 上的 AAAA 查詢仍由 DNS Shield 處理；IPv6 DNS 封包不會被攔截，此設定也不會新增 IPv6 DNS 上游。詳見 [D03 驗證紀錄](d03-dualstack-validation.md)。
- App 自行使用 DoH、DoT、非標準連接埠、直接 IP 連線或其他繞過系統 DNS 的方式，不會被此工具攔截。
- DNS 層規則無法阻擋與正常內容共用網域的廣告，也無法保證涵蓋所有廣告、追蹤或惡意網域。
- App 不會在執行期間下載遠端規則；production blocklist 只會隨經驗證的新 APK 更新。私有 override 缺失時使用 APK 內規則，格式或排序驗證失敗時也會改用 APK 內已驗證的清單；若該清單同樣無法使用，才退回內建規則。
- 「節省流量」是依被阻擋網域類型推算的參考值，不是實際網路流量量測。
- 實際解析延遲、耗電與攔截效果會因裝置、Android 版本、網路及 DNS 解析器而異。

## Always-on 與系統恢復

- 服務會持久化最後一次明確的使用者啟用或停用選擇。系統以 null intent
  恢復服務時，會在使用者最後選擇啟用，或 API 29 以上已設定 Always-on
  且 App 尚未記錄明確使用者選擇的情況下重新建立隧道。
- 使用者明確停用服務，或 Android 撤銷 VPN 授權時，服務會清除恢復意圖，避免
  `START_STICKY` 或系統恢復流程重新啟用 VPN。
- Manifest 明確宣告支援 Android Always-on；服務透過 IO 序列化寫入保存使用者意圖，並由獨立的 `VpnRecoveryService` 協助系統 sticky 恢復。
- Android 10 已驗證 Always-on 重開機、受控程序死亡恢復，以及 STOP／跨 VPN 撤銷後立即終止程序仍維持停用；另有 API 26／35 模擬器回歸。這些結果不涵蓋所有廠牌或真正低記憶體回收，詳見 [共同驗收](r09-common-validation.md) 與 [API 26 STOP 回歸](api26-tun-stop-validation.md)。
- 系統恢復沒有即時或必然成功的保證。在已測的 ASUS Android 10 上，預設背景限制曾阻止恢復；使用者自行設定 VPN App 的電池豁免後，受控程序死亡測試可恢復。這不代表其他廠牌、真正低記憶體回收或所有背景政策都已驗證。
- 若重開機或程序終止後未恢復，先開啟 App 查看防護狀態；「防護已關閉」表示目前沒有提供防護。需要防護時重新按下啟用，並確認 Android 的 VPN 指示和 App 狀態。可在系統的電池最佳化／背景執行設定中查找 DNS Shield 的 VPN App，依個人需求允許背景執行；各廠牌選單名稱不同。App 不會自行變更電池設定，同名測試 App 必須先核對套件，不要調整測試執行器。
- API 24–28 沒有公開的 `isAlwaysOn()` 查詢 API；這些版本只有在 App 曾明確
  記錄啟用意圖時才會自動恢復，需透過實機流程驗證系統行為。
- 目前 VPN 只建立 DNS 位址的路由，尚未驗證 Android lockdown 對一般流量的相容性。
  因此不宣稱支援 lockdown，啟用該模式前應先完成完整流量路徑與實機驗證。

## 隱私

DNS Shield 不包含帳號、分析 SDK、廣告 SDK 或開發者營運的後端服務。DNS 查詢會傳送至使用者選擇的第三方解析器；已安裝 App 清單、排除名單與設定不會由 DNS Shield 上傳。

DoH 將 DNS 查詢包在 HTTPS 傳輸中，但 DNS Shield 不會在本機驗證 DNSSEC。選擇「僅加密」時，DoH 端點故障、退避或自訂 bootstrap 不可用都會回覆 SERVFAIL，且不會降級為 UDP/53 或 TCP/53；「加密優先」會在加密端點失敗時使用未加密 UDP/53，若 UDP 回應設有 TC，則在原請求期限內改用 TCP/53 重試。自訂 DoH hostname 的 bootstrap 只使用設定的數字 IP，不會再透過系統 DNS 查詢該 hostname。

完整資料處理方式請參閱 [PRIVACY.md](../PRIVACY.md)。

## 權限用途

| 權限 | 用途 |
| --- | --- |
| `INTERNET` | 將允許的 DNS 查詢送往選定解析器。 |
| `ACCESS_NETWORK_STATE` | 觀察底層網路與連線狀態，處理切網與 DNS 恢復。 |
| `FOREGROUND_SERVICE` | 在 VPN 啟用期間維持可見的前景服務通知。 |
| `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` | Android 14 以上執行持續作用中的 VPN 前景服務。 |
| `POST_NOTIFICATIONS` | 顯示 VPN 運作中的前景服務通知。 |
| `QUERY_ALL_PACKAGES` | 查詢具有啟動入口的已安裝 App，讓使用者建立 VPN 排除名單。資料只在裝置上使用。 |
| `BIND_VPN_SERVICE` | 由 Android 系統綁定及管理 `VpnService`；此權限只套用於服務元件。 |

`QUERY_ALL_PACKAGES` 提供廣泛的套件可見性，只用於使用者主動開啟的 App 排除功能。

## 專案架構

Android App 使用 Kotlin、Jetpack Compose、ViewModel／Flow、Room、coroutines 與 OkHttp。Kotlin 原始碼位於 `app/src/main/java/io/github/xiangwang2000/dnsshield/`。

| 模組 | 責任 |
| --- | --- |
| [MainActivity.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/MainActivity.kt)、[ui/theme/](../app/src/main/java/io/github/xiangwang2000/dnsshield/ui/theme/) | Compose 控制中心、規則與解析器設定、診斷畫面。 |
| [viewmodel/DnsVpnViewModel.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/viewmodel/DnsVpnViewModel.kt) | UI 狀態、Room 資料、App 排除名單及 VPN 命令。 |
| [data/](../app/src/main/java/io/github/xiangwang2000/dnsshield/data/) | 解析器、使用者網域規則與排除 App 的 Room 資料。 |
| [blocking/](../app/src/main/java/io/github/xiangwang2000/dnsshield/blocking/) | 規則驗證、compiled blocklist／PSL 載入與不可變政策快照。 |
| [service/DnsVpnService.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/DnsVpnService.kt) 及 [service/](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/) | TUN／生命週期、網路觀察、查詢容量與快取、DoH／UDP／上游 TCP、回應防護及診斷。 |
| [NativeDnsTcpRuntime.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/NativeDnsTcpRuntime.kt)、[SocksDnsServer.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/SocksDnsServer.kt)、[app/src/main/cpp/](../app/src/main/cpp/) | JNI／Hev TCP 協定堆疊與本機 SOCKS5 DNS 橋接，讓用戶端 TCP/53 使用同一套 DNS 政策。 |
| [VpnUserIntent.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/VpnUserIntent.kt)、[VpnRecoveryService.kt](../app/src/main/java/io/github/xiangwang2000/dnsshield/service/VpnRecoveryService.kt) | 啟用／停用意圖的持久化順序及系統恢復。 |
| [app/src/main/assets/](../app/src/main/assets/)、[tools/](../tools/) | APK 內固定的 blocklist／PSL、離線編譯與驗證工具、實機測試 runner。 |
| [app/src/test/](../app/src/test/)、`app/src/androidTest*/`、[docs/](./) | JVM 測試、隔離 instrumentation variants、驗收與格式紀錄。 |

一般流量不走 Hev；原生堆疊只處理送往 VPN DNS 路由的 TCP 封包。上游 DoH 使用 OkHttp，明文 UDP／TCP 使用受保護的 socket。Hev 及遞迴子模組由 Git 固定版本，授權資訊隨 APK 包含於 [native-tcp-NOTICES.txt](../app/src/main/assets/native-tcp-NOTICES.txt)。

## 開發建置

需求：Python 3、JDK 21（Windows 優先使用 Android Studio 內附 JBR 21）、Android SDK Platform 37、NDK `27.2.12479018`，以及 Git／Gradle Wrapper。Gradle 與依賴版本分別固定於 [Wrapper 設定](../gradle/wrapper/gradle-wrapper.properties)及 [版本目錄](../gradle/libs.versions.toml)。

新 checkout 需取得遞迴子模組：

```powershell
git clone --recurse-submodules https://github.com/XiangWang2000/dns-shield.git
cd dns-shield
```

既有 checkout 可在專案根目錄執行 `git submodule update --init --recursive`。設定 Android SDK 路徑（`local.properties` 或環境變數）；使用 PowerShell 直接呼叫 Gradle 時，可先設定 JBR：

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
```

Gradle daemon 的既定條件為 JDK 21；CI 先安裝符合條件的 JDK，避免依賴額外的 Foojay 下載。從專案根目錄執行完整驗證：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

驗證入口會執行 PowerShell 語法檢查、離線 Python 工具測試、production Public Suffix 與 active blocklist asset 驗證、Android lint、JVM 單元測試及 Kotlin 編譯，並建置 Debug 與 D03／D04／D14 隔離 App／androidTest APK。D07／D08／D12／D15 variants 需另行建置；CI 不會自動執行裝置測試。GitHub Actions 固定使用 Windows 2025、Python 3.13.15 與 Temurin 21.0.12.1+1 執行同一個 `verify.ps1`，並保存 JVM 測試與 lint 報告。

目前 `main` 已將 GitHub Actions 的 `Windows verification` 設為 required status check，並套用於 repository 管理員；分支不必先與 `main` 同步。CI 執行建置、資產驗證、lint 與 JVM／Python 測試；實機 instrumentation 與耗電量測須另外執行，不能由 CI 建置結果推定通過。

`assembleDebugAndroidTest` 只建置 instrumentation APK，不代表已執行 instrumentation tests。連接 emulator 或 Android 裝置後，可用以下命令執行；公開 DNS 測試與實機效能、耗電量測仍須明確啟動：

```powershell
.\gradlew.bat --no-daemon --console=plain :app:connectedDebugAndroidTest
```

D15 的實機 smoke test 使用獨立的 `d15test` build type，套件為
`io.github.xiangwang2000.dnsshield.d15test`，不會使用正式 Debug 套件的資料。可在
已連線的裝置上只執行 D15 測試：

```powershell
.\gradlew.bat :app:assembleD15test :app:assembleD15testAndroidTest
adb install -r .\app\build\outputs\apk\d15test\app-d15test.apk
adb install -r .\app\build\outputs\apk\androidTest\d15test\app-d15test-androidTest.apk
adb shell am instrument -w -r `
  -e class io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest `
  io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
adb uninstall io.github.xiangwang2000.dnsshield.d15test.test
adb uninstall io.github.xiangwang2000.dnsshield.d15test
```

此 smoke test 驗證隔離套件的實際 VPN 啟動／停止、使用者開關意圖，以及顯式停止後不因空 action 自動恢復；測試前須先同意該隔離套件的 Android VPN 權限。完整 Always-on／撤銷流程需額外的系統設定與程序死亡操作；較早紀錄見 [D15 驗證紀錄](d15-device-acceptance.md)，最新整合結果見 [共同驗收](r09-common-validation.md)。

### 當前驗收範圍（2026-10-07）

| 範圍 | 已完成的代表性驗證 |
| --- | --- |
| DNS／規則／strict／用戶端及上游 TCP | Android 10 實機整合回歸；大回應／快取與生命週期另在 API 26／35 模擬器驗證。見 [共同驗收](r09-common-validation.md)、[R08 傳輸上限](r08-transport-size-validation.md)、[API 26 STOP](api26-tun-stop-validation.md)。 |
| Wi-Fi ↔ LTE、IPv6 pass-through | Android 15 實機同一 VPN 三輪雙向切換，DNS 與實際連線、延遲舊回應防護、strict 切換前後防護，以及行動網路雙棧／IPv4 Wi-Fi 的 VPN off/on/off 通過。見 [R10 驗收](r10-cellular-handoff-validation.md)。strict 案例不宣稱 TLS 請求在整個切網期間持續 pending。 |
| 主機端完整驗證 | 最新本地完整驗證為 29 Python、283 JVM 測試通過；這些數字描述該次紀錄，不取代目前 `verify.ps1` 的實際結果。 |

[環境追蹤 #73](https://github.com/XiangWang2000/dns-shield/issues/73) 仍保留四項未完成驗收：IPv6-only／NAT64、真正 captive portal、完整 API／OEM 矩陣與真正低記憶體回收，以及 8–10 小時拔除充電線的耗電 A/B。Android 10 未設定電池豁免時的背景恢復限制仍存在，DNS-only lockdown 不宣稱支援。

離線 blocklist 編譯器及其測試可獨立執行：

```powershell
python -m unittest discover tools/tests
python tools/build_blocklist.py --input tools/tests/fixtures/blocklist.txt --output build/test-blocklist.bin
```

production `active.bin` 使用固定 commit 與 SHA-256 的 1Hosts Lite 來源；準備腳本是明確、opt-in 的維護操作，日常 App 執行不會下載規則：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\prepare-active-blocklist-production.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-active-blocklist-asset.ps1
```

二進位格式、來源合約與更新方式請參閱 [docs/blocklist-format.md](blocklist-format.md)。第三方資料歸屬請參閱 [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)。

連接 adb 實機後，可比較內建規則與 production blocklist 的組裝及 lookup 成本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-production-blocklist-android.ps1
```

測試方法與 ASUS_Z01RD 實測結果請參閱 [docs/production-blocklist-android-benchmark.md](production-blocklist-android-benchmark.md)。

VPN 底層網路切換的觀察方式、API 24–27 限制及實機驗收狀態，請參閱 [docs/network-change-recovery.md](network-change-recovery.md)。

Public Suffix 來源更新是獨立且明確的維護操作。先安裝鎖定且帶雜湊的 IDNA 依賴，再取得並正規化 manifest 指定的來源：

```powershell
python -m pip install --require-hashes -r tools/requirements-public-suffix.txt
python tools/prepare_public_suffix_source.py `
  --manifest tools/public_suffix_source.json `
  --output build/public-suffix.normalized.dat `
  --metadata-output build/public-suffix.source.json
python tools/build_public_suffix.py `
  --input build/public-suffix.normalized.dat `
  --output build/public-suffix.bin
```

準備器只接受 `publicsuffix.org` 的 pinned 來源，會驗證並移除官方 URL 加入的 `VERSION`/`COMMIT` 前導註解，再以指定 upstream Git blob 驗證其餘完整位元組；日常 `verify.ps1` 不會下載來源或安裝套件。格式與供應鏈邊界請參閱 [docs/public-suffix-format.md](public-suffix-format.md)。

產生完整 normalized source 與 artifact 後，可用固定的 production manifest 驗證輸出並執行 opt-in JVM characterization：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-public-suffix.ps1
```

腳本會先確認來源 revision、IDNA 版本、SHA-256、檔案大小、規則數與 deterministic regeneration，再輸出 `build/public-suffix.validation.json` 與 `build/public-suffix.benchmark.json`。benchmark 記錄載入時間、估算常駐 heap 與 lookup latency，但不設定跨裝置的效能通過門檻，也不會由日常 `verify.ps1` 自動執行。

連接 adb 實機後，可使用同一份已驗證 artifact 執行測試 APK 專用的 instrumented characterization：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\benchmark-public-suffix-android.ps1
```

腳本只把 benchmark artifact 複製到 `app/build/generated` 的 androidTest asset；結果會拉回 `build/public-suffix.android-benchmark.json`。Production APK 另包含已釘選且驗證的 PSL asset，只有有效 `active.bin` 需要 parent-domain matching 時才由 service lifecycle lazy 載入；載入失敗時 compiled blocklist 退回 exact-only。測試流程與指標解讀請參閱 [docs/public-suffix-android-benchmark.md](public-suffix-android-benchmark.md)。

## 正式發行

正式套件識別為 `io.github.xiangwang2000.dnsshield`。目前程式版本為 `1.2.2`、`versionCode 5`；不要變更 `applicationId`，每次發布新版都必須增加 `versionCode`。

第一次建立本機發行金鑰：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup-release-signing.ps1
```

請將產生的 `release/dns-shield-upload.p12` 與 `keystore.properties` 安全備份；兩者都由 `.gitignore` 排除，不得提交至 GitHub。

建立並驗證正式簽名 APK：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\release.ps1
```

腳本會產生 `app/build/outputs/apk/release/app-release.apk`、驗證 APK 簽名，並輸出 SHA-256 檔案供 GitHub Release 使用。CI 也可以改用 `KEYSTORE_PATH`、`STORE_PASSWORD`、`KEY_ALIAS`、`KEY_PASSWORD` 環境變數提供簽名資料。
