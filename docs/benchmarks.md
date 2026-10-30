# Benchmarks

本頁提供目前可重跑的 host/JVM 與 Android benchmark 步驟。所有命令都從 repository 根目錄執行。歷史數字留在 [archive 合併紀錄](archive/android-benchmarks.md)；每次結果應和當次輸入、裝置及環境一起閱讀。

## 共通準備

所有 runner 都會把 machine-readable JSON 寫到 build/，不會把數值當成跨裝置 pass/fail 門檻。

Windows 請使用 Android Studio JBR。Android runner 另需 Android SDK build tools 與 adb。

未指定 -Serial 時，Android runner 預期恰好一台已連線裝置。多台裝置時請明確指定 adb serial。

Android runner 會安裝 Debug 與 androidTest APK，只執行指定 benchmark test class，並將裝置 JSON 拉回 build/。這些 runner 使用一般 Debug applicationId（不是 D04／D07 隔離套件）；請在專用測試裝置執行，避免覆蓋同簽章的既有安裝。

## Host JVM：Public Suffix resolver

工具：tools/benchmark-public-suffix.ps1。

適用於比較 JVM 上 resolver 載入、快取、查詢與近似 retained heap 的變化。

執行前需有通過 production contract 的 build/public-suffix.normalized.dat 與 build/public-suffix.bin；可依 [Public Suffix rebuild 步驟](public-suffix.md)產生。

此 runner 先驗證 production manifest，再執行 opt-in 的 ProductionPublicSuffixBenchmarkTest。它不使用 adb，也不代表 Android 執行結果。

結果檔為 build/public-suffix.validation.json 和 build/public-suffix.benchmark.json。

## Android：Public Suffix resolver

工具：tools/benchmark-public-suffix-android.ps1。

適用於裝置上的 resolver first load、warm load、同一 loader cached load、lookup 及近似 heap 比較。

執行前需有通過 production contract 的 normalized source 與 artifact、JBR、adb 和一台裝置。

Runner 會把已驗證 artifact 複製到產生的 androidTest-only asset，再安裝並執行 ProductionPublicSuffixInstrumentedBenchmarkTest。

這是 resolver 的 Android characterization；該 generated asset 不在 main APK source set，不能單獨證明正式 APK asset 封裝或 runtime policy 接線。

結果檔為 build/public-suffix.android-validation.json 和 build/public-suffix.android-benchmark.json。

## Android：production blocklist

工具：tools/benchmark-production-blocklist-android.ps1。

適用於同一 instrumentation process 中，比較 builtin-only domain policy 與使用 APK 內 active.bin 的 policy。

執行前需有通過驗證的 app/src/main/assets/active.bin、JBR、adb 和一台裝置。

測試會暫時移除 app-private blocklists/active.bin；若先前有一般檔案，會在 finally 中還原。裝置不會下載或更新 blocklist。

結果檔為 build/production-blocklist.android-benchmark.json。

## Android：runtime domain policy

工具：tools/benchmark-runtime-domain-policy-android.ps1。

適用於測量 RuntimeDomainPolicy 接上 APK 正式 Public Suffix asset 的實際組裝與查詢路徑。

執行前需有已封裝並通過 gate 的 app/src/main/assets/public_suffix.bin、JBR、adb 和一台裝置。

Instrumentation 使用四筆 active.bin fixture；它會建立 app-private 測試檔，並在 finally 中清除 fixture。

結果區分缺少 active.bin、首次有效組裝、cached 組裝、exact/parent lookups 與近似 heap。四筆 fixture 不是 production blocklist，不能用來估算正式清單的掃描時間或記憶體。

結果檔為 build/runtime-domain-policy.android-benchmark.json。

## 執行命令

Host runner 先完成，或獨立產生 Public Suffix production build outputs。三個 Android runner 依上列條件使用現有 packaged assets 或測試輸入。

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/benchmark-public-suffix.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tools/benchmark-public-suffix-android.ps1 -Serial <adb-serial>
powershell -NoProfile -ExecutionPolicy Bypass -File tools/benchmark-production-blocklist-android.ps1 -Serial <adb-serial>
powershell -NoProfile -ExecutionPolicy Bypass -File tools/benchmark-runtime-domain-policy-android.ps1 -Serial <adb-serial>
~~~

若只有一台裝置，Android 命令可省略 -Serial。PSL runners 另支援指定 Normalized、Artifact 與 report paths；其他 runner 可用 BenchmarkReport 改變輸出檔路徑。

## 結果解讀與證據界線

先看 JSON 的輸入識別、裝置/API/ABI 或 JBR 資訊，再比較相同 runner 的同環境重跑結果。更換 artifact、runtime、OS、電源或熱狀態時，建立新的比較基準。

JVM host benchmark 只描述 host JVM；Android instrumentation 只描述其已執行的測量步驟。Instrumentation 已在測試程序中執行，不包括完整 App 冷啟動、VPN 權限、TUN 建立、Room 初始化或上游 DNS 交易。

first load、warm load、cached load 與 policy assembly 是不同路徑，不要合併成一個啟動時間。Runtime policy 的缺少 active.bin 結果也不同於有效 production blocklist 首次載入。

GC-assisted heap 是近似值，會受 GC 時機、ART/JVM 版本與測試配置影響。它不是完整 object graph 大小；單次零差異或一次大值都不足以證明沒有記憶體成本或已發生 regression。

Public Suffix Android runner 測量 androidTest-only generated asset。要確認 main APK 內的資產，使用 repo verification 或 runtime policy runner；建置 APK 本身不表示 instrumentation 已執行。

Microbenchmark 不代表 8–10 小時耗電 A/B，不能據此宣稱電池影響。長時間耗電驗收需另做同裝置 A/B。

舊版同裝置數字與當時條件見 archive 的 [production blocklist](archive/android-benchmarks.md#production-blocklist)、[Public Suffix](archive/android-benchmarks.md#public-suffix) 與 [runtime domain policy](archive/android-benchmarks.md#runtime-domain-policy)。這些報告保留歷史上下文，不是目前 runner 的通用門檻。
