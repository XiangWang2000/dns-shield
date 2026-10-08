# R15／R16：解析器政策收斂與非阻塞提交驗證

日期：2026-10-08。範圍：[#91](https://github.com/XiangWang2000/dns-shield/issues/91)、[#92](https://github.com/XiangWang2000/dns-shield/issues/92)，共同修正與驗收。

- Red 基準：`aae6fa828f5b4cc0b484021b2baa89db4ea43956`；當時 main 的產品程式未修改。
- 最終程式與測試 source：`91b23b46dc4c4dd3d90c14bf30003546f2903572`；產品修正提交為 `7aa492345d47b530c2eaeb8fb7290cd29ab03c2d`，前者另補相同 row 的 Android 測試。
- 本文與開發指南為後續文件提交；PR 的 exact-head／合併後 exact-main CI 由 PR checks 與 issue 收尾紀錄對應，不能以先前 main CI 代替。

## 根因與修正邊界

ALLOW 成功寫入 Room 後，如果被較新的 resolver 選取 revision 超越，會回報「已儲存但未同步」。原 Service 重新套用資料列時只更新解析器，沒有同步 fallback fence；row 相等時更會直接略過更新。

原 coordinator 在 submissionLock 內套用政策；政策 monitor 又涵蓋 socket write／flush／UDP send。網路寫入阻塞時，worker 等待 monitor 並持有全域提交鎖，主執行緒的新選取、刪除及 STRICT 請求也可能等待。

修正採每個 resolver 的原子政策狀態，保存 requested revision、是否成功持久化及 applied revision：

- STRICT 在提交當下立即關閉新明文傳送；ALLOW 必須等目前版本成功持久化，並由有效命令套用。
- Service 套用有效 active row 時，先同步 fence 再判斷 row 是否相等。延遲 DB read、舊 ALLOW 或舊 intent 不能覆蓋較新 STRICT；未儲存 STRICT 也不能被舊 DB 的 ALLOW 打開。
- current check 與非阻塞政策發布仍在同一提交臨界區，沒有把 effect 直接移出鎖而留下 check-then-act 競態。
- socket I/O 不持有政策 monitor 或全域提交鎖。傳送先以 CAS 取得 admission；STRICT 拒絕之後的新 admission，已取得 admission 的寫入視為 in-flight，不宣稱可撤回已送出的位元組。
- STRICT 的 TCP 清理在提交鎖外執行，依 admission revision 關閉舊 socket；新 ALLOW 及較新 socket 註冊不被過期清理誤關。UDP 已進行中的寫入由既有 deadline／取消與 socket close 收尾。
- 啟動先等待既有 FIFO 命令，不建立額外 revision；重新讀取持久資料後，用 current revision 套用整組狀態。讀取被新命令超越就重讀；Service 停止仍遵守 lifecycle 與 coroutine cancellation。
- 同 process STOP／START 保留 requested policy 防護；process 重建沒有未儲存的記憶體政策，依持久化 active row 初始化。失敗 STRICT 的立即保護不承諾跨 process 保存。

## Red／green 證據

| 情境 | Red 或驗證方式 | 最終結果 |
| --- | --- | --- |
| ALLOW → 選取同 A | 原產品＋真實 coordinator／persistFallbackPolicy／fence barrier 測試；JVM baseline 12 項中 2 項失敗之一 | 已儲存 ALLOW 由後續有效 row 套用收斂 |
| 阻塞 send → 舊 ALLOW effect → 新 STRICT | 同一 JVM baseline 第二個 assertion failure；受控 send callback 未釋放時提交超時 | callback 未釋放前選取／刪除／STRICT 可提交，後續明文 admission 被拒絕 |
| 實際 ViewModel／Room／Service／TUN 同 A | API35 baseline 1 項／1 failure，2.974 秒；DoH 失敗後 unique QNAME 的 UDP 嘗試仍為零 | final ALLOW 的本機 UDP 備援回覆有效 NOERROR／1 answer |
| row 完全相同 | Room 原已 ALLOW，以 D08 測試 hook 注入 runtime STRICT；先確認 SERVFAIL／UDP 0，再透過實際 ViewModel ALLOW＋選取，assert 前後整列相等 | fence 仍恢復，實際 TUN 查詢可 UDP 備援；此為受控不一致狀態，不宣稱真實 DAO 故障 |
| ALLOW → B → A、舊 intent、同 process STOP／START | API35 實際接線＋受控 TLS／UDP／TCP fixture | final ALLOW 可備援；final STRICT 的 unique QNAME UDP／TCP 嘗試均為零，重啟仍維持 STRICT |
| 延遲 read、failed STRICT／ALLOW、dispatch false／例外、無 active resolver、不同 resolver | coordinator／fence／結果處理 JVM 回歸；D15 ViewModel failure 接線 | 保留 NOT_SAVED／SAVED_UNSYNCED 語義；舊資料不重新放行，後續有效操作／重試可恢復 |
| 主執行緒實際 API 呼叫 | API35 在受控 service send callback 佔住期間，以 Handler／barrier 驗證 ViewModel STRICT／select／delete 返回 | 有界等待通過；不是裝置真實阻塞 socket／ANR 重現 |
| TCP 清理、取消、例外與 worker 後續命令 | fence／TCP client／coordinator JVM 回歸，保留既有 backoff／budget 測試 | in-flight release 與清理完成後沒有阻住後續 worker；舊 cleanup 不傷新 ALLOW |

API35 最終共同 source 執行：

- D08：11／11，31.182 秒，0 failures、0 skips。包含政策／backoff class 6 項、invalid TLS／slow handshake 的 strict／allow 4 項及 resolver selection 1 項。
- D15：8／8，5 秒，0 failures、0 skips。包含 ViewModel failure 4 項、Service smoke 2 項及 user intent 2 項。錯誤操作由注入 fixture 控制，不等同真實 Room 磁碟故障或 Toast 視覺驗收。
- `verify.ps1`：exit 0，83.710 秒；37 Python、305 JVM（49 suites），0 failures／errors／skips，六組 Gradle build、lint、assets 與 PowerShell 檢查通過。此為已有快取的本機執行時間，不作效能比較。
- 先前冷些的同產品完整驗證為 205.222 秒；只出現既有 `D09WifiRecoveryDeviceTest.allNetworks` deprecation warning，沒有本修正新增的 compiler warning。
- 限定差異獨立審查未發現需修正項目。測試 scaffold 編譯錯誤及 baseline 缺少 native submodule 的環境準備錯誤已修正，不列為產品 red。

## 可重跑命令

使用 Android Studio JBR、既有 API35 AVD 與隔離套件；先同意測試套件的 VPN 權限。D08 測試 hook 僅允許 `.d08test`，TLS fixture 使用固定本機信任，不更動正式版 TLS 驗證。

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
$env:ANDROID_HOME = 'C:\Users\User\AppData\Local\Android\Sdk'
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
adb -s emulator-5556 install -r app\build\outputs\apk\d08test\app-d08test.apk
adb -s emulator-5556 install -r app\build\outputs\apk\androidTest\d08test\app-d08test-androidTest.apk
$prefix = 'io.github.xiangwang2000.dnsshield.service.'
$d08 = @(
  'DohFailureBackoffTunInstrumentedTest',
  'DohTlsFallbackInstrumentedTest#strictModeReturnsServFailWithoutUdpAfterInvalidTlsCertificate',
  'DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterTheSameInvalidTlsCertificate',
  'DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterSlowDohHandshake',
  'DohTlsFallbackInstrumentedTest#strictModeDoesNotUseUdpAfterSlowDohHandshake',
  'ResolverSelectionTunInstrumentedTest'
) | ForEach-Object { $prefix + $_ }
adb -s emulator-5556 shell am instrument -w -r -e class ($d08 -join ',') io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
adb -s emulator-5556 install -r app\build\outputs\apk\d15test\app-d15test.apk
adb -s emulator-5556 install -r app\build\outputs\apk\androidTest\d15test\app-d15test-androidTest.apk
$d15 = 'io.github.xiangwang2000.dnsshield.viewmodel.ResolverCommandViewModelFailureInstrumentedTest,io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest,io.github.xiangwang2000.dnsshield.service.VpnUserIntentInstrumentedTest'
adb -s emulator-5556 shell am instrument -w -r -e class $d15 io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
```

`adb am instrument` 的 shell exit code 不足以判斷通過；本次另外確認各 test 的 status code 0、沒有負值的 failure／skip status，以及 `OK (11 tests)`／`OK (8 tests)`。

## APK 與本機證據

以下 SHA-256 已與 API35 實際安裝的 `base.apk` 一致性核對：

| 套件 | SHA-256 |
| --- | --- |
| d08test | `aeb49704dcab3df86b76616cb7c013dff0b9fc4e8410046c5961537188b0a3fc` |
| d08test.test | `1b98a2b2eb20d76ad6e75f39eb18608e5480e406a03e4898b3a0b3eabd7a3aa0` |
| d15test | `720d90f30ef884bddbcf4e6738150f6468bf26a03a6a25a9af3e0f3aa7f8fdea` |
| d15test.test | `fad1358418d77921c5301fbe5719e1a19ecf2e7a149d2034ecfe4b4a152026c7` |

原始輸出保留於既有 `d05-bounded-admission` worktree 的 ignored `captures/`：`r15-r16-baseline-jvm-red.txt`、`r15-r16-baseline-ResolverCommandOrderingTest.xml`、`r15-r16-android-baseline-red.txt`、`r15-r16-final-full-verify.txt`、`r15-r16-final-api35-d08-green.txt`、`r15-r16-final-api35-d15-green.txt`、`r15-r16-final-installed-apk-hashes.json`。API35 baseline 另留在 `d01-dns-validation` worktree；raw log／APK／機器設定不加入 repository。

本次只使用 API35 AVD，不操作實機，也不新增 Always-on 重開機、OEM、真正 LMK 或特殊網路驗收宣稱。[#73](https://github.com/XiangWang2000/dns-shield/issues/73) 四項環境延期保持不變；版本、正式簽名 APK 與 release 均未調整。
