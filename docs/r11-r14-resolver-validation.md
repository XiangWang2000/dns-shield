# R11–R14 解析器修正驗證

日期：2026-10-07。對應 [#84](https://github.com/XiangWang2000/dns-shield/issues/84)、[#85](https://github.com/XiangWang2000/dns-shield/issues/85)、[#86](https://github.com/XiangWang2000/dns-shield/issues/86)、[#87](https://github.com/XiangWang2000/dns-shield/issues/87)。

最終產品與測試 source：`caf6465f1f18f276dd8ad69dbb33f799f658af2f`。包含目前 main 的 README／文件 CI 調整；後續提交本報告不變更 App source。沿用既有工作樹，保留既有修改與 ignored 證據。

## 根因與修正

| 項目 | 已確認的問題 | 修正 |
| --- | --- | --- |
| R11 | backoff 只用 URL 與 network generation，同 URL 的不同 bootstrap 互相影響；舊 resolver 完成事件可污染新狀態。 | 使用 URL、hostname、bootstrap、custom 標記的不可變識別，並以 resolver／network generation fence 拒絕舊完成事件；設定及底層網路變更同步重設。 |
| R12 | 單次 DoH 可用完整個總期限，慢速 body 讓健康備援沒有機會。 | 在原本總期限內分配 attempt budget，保留剩餘端點與允許的明文降級時間；同 URL／bootstrap 的重複端點去重，不同 bootstrap 保留。 |
| R13 | FIFO worker 回傳例外後，ViewModel 三入口直接 await，例外會逸出；儲存成功但沒有 dispatch 也可能顯示已套用。 | 處理一般例外、保留取消；區分未儲存／已儲存未同步／已 dispatch，保留已提交資料並提供恢復提示。STRICT 立即關閉明文，ALLOW 在儲存、dispatch 及 current fence 成功後才放行；fence 的 check／effect 同鎖。 |
| R14 | 完整 CI 入口未編譯 D08／D15 AndroidTest，測試 source 壞掉仍可能綠燈。 | 分開建置 D08、D15 App 與 AndroidTest，明確指定 testBuildType，任何失敗均終止 verify.ps1；CI 不執行 adb 或裝置測試。 |

## 重現與回歸

- **R11 baseline red**：在原 backoff 實作套用新測試的相容接線，同 URL／不同 bootstrap 的冷卻隔離 assertion 失敗。最終完整 JVM 的 backoff 8/8 通過，涵蓋 cooldown、單一 recovery probe、成功恢復、取消及舊 generation 完成事件。
- **R12 baseline red**：實際本機 TLS 主端點送出部分 body 後阻塞，備援正常；舊版約 6.289 秒後回 UNAVAILABLE。修正版同案例約 3.055 秒使用健康 HTTPS 備援成功。這是單一受控測試的時間，不是實機效能統計。受控時鐘另驗證 6 秒在主／備／UDP 各保留 2 秒；strict 的 UDP／TCP callback 嘗試均為零，parent cancellation 不啟動備援或降級。
- **R13 red**：實際 ViewModel 的 DAO／dispatch 失敗缺少 recovery 提示。後續複核新增的 dispatch=false、runtime-fence=false JVM 案例 2 fail；API35 no-active／找不到 DNS 提示案例 2 fail。這輪後續 red 的 XML／stdout／logcat 已另存，未被 green 覆寫。
- **R13 green**：Result 9/9、Ordering 10/10；API35 實際 ViewModel 4/4，涵蓋三入口 DAO 失敗、已提交後 dispatch 失敗、沒有 active resolver 的未同步結果與找不到 DNS 提示。取消與已接受命令的 process FIFO 保留；後續命令可繼續與重新同步。
- **R14 baseline replay**：原 verify.ps1 的受控 runner 只有 4 組 Gradle invocation，新增 gate regression 期望 6 組而失敗；修正版 3/3 入口回歸通過，並注入 D08／D15 exit code 驗證失敗傳播。這是控制流程測試；APK 真正編譯另由下列完整驗證與 PR CI 證明。

最初的測試 scaffold 有 timeout Int／Long 型別與 assertFalse import 編譯錯誤，修正後才完成下列驗收；這些錯誤沒有算成產品問題的 red。初次完整入口確實在 D08 編譯錯誤時停止，沒有繼續以 D15 成功取代失敗。

## 最終完整驗證

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
$env:ANDROID_HOME = 'C:\Users\User\AppData\Local\Android\Sdk'
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
```

Exit 0，約 278 秒。37 Python、298 JVM／49 suites，0 failure／error／skip；PowerShell syntax、固定 blocklist／PSL assets、lint、Debug Kotlin 及 APK 通過。D03／D04／D08／D14／D15 App 與各自 AndroidTest 全部編譯成功。初次編譯的 D09WifiRecoveryDeviceTest.allNetworks deprecation 為原有 warning；未新增 warning。

本地 build 使用既有快取；全新 CI checkout 的同一入口結果需另核對 PR exact head，不能由本地 build 推定。CI／合併證據在對應 PR 及 issue 更新中追蹤。

## API35 實際 Android 回歸

只使用本輪啟動的 `dns_shield_api35` 模擬器（emulator-5556）；正式手機未改 App、VPN、資料或網路設定。

### D08：7/7，約 31.158 秒，0 skip

- 新 backoff TUN 兩案例：同 URL 的 primary 失敗 3 次後 cooldown，健康 alternate 仍成功，primary count 維持 3、alternate count 到 4；舊 resolver HTTP response 以 barrier 保持 pending 跨越設定 fence，釋放後不使新 generation 提早 cooldown。兩者 strict 明文 UDP 計數均為零。
- 原有 TLS 失效／慢 handshake 各跑 strict 與允許降級，4/4；確認拒絕錯誤憑證、strict 不送 UDP、允許模式可改用健康 UDP。
- 原有 resolver 選擇 Room／service／TUN 接線 1/1；較新 ViewModel 選擇及舊 service 命令防護正常。

新增 fixture 僅在 `.d08test` 以 gated hook 使用固定測試 certificate／hostname；client 從原 service client 建立，production trust 未放寬，finally 清除 hook。它們使用實際 VPN TUN，不只呼叫獨立 backoff map。

重跑命令（以下 `$cases` 為新 backoff class、原 TLS 四個 method 與 resolver selection class 的逗號清單；排除需真實切網的 external handoff method）：

```powershell
adb -s emulator-5556 install -r app\build\outputs\apk\d08test\app-d08test.apk
adb -s emulator-5556 install -r app\build\outputs\apk\androidTest\d08test\app-d08test-androidTest.apk
$cases = @(
'io.github.xiangwang2000.dnsshield.service.DohFailureBackoffTunInstrumentedTest',
'io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#strictModeReturnsServFailWithoutUdpAfterInvalidTlsCertificate',
'io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterTheSameInvalidTlsCertificate',
'io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#allowedFallbackUsesUdpAfterSlowDohHandshake',
'io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#strictModeDoesNotUseUdpAfterSlowDohHandshake',
'io.github.xiangwang2000.dnsshield.service.ResolverSelectionTunInstrumentedTest'
) -join ','
adb -s emulator-5556 shell am instrument -w -r -e class $cases io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

測試前核對該隔離套件 VPN consent；本次已核准。原始 instrumentation status 明確為 7 tests、OK，沒有 ignored／assumption status。

### D15：4/4，約 3.583 秒，0 skip

以實際 `DnsVpnViewModel` 公開入口注入 DAO／dispatch 操作，檢查可見診斷 Flow 的完整繁中提示、已保存狀態、後續同步與 uncaught handler 為空。這不是實際 Room 失敗或 Android startService 拒絕的重現；Toast 的 Main-thread 接線有程式複核，沒有 Toast 截圖或完整畫面手勢驗收。正常 Room／service 接線由上面的 D08 案例補驗證。

```powershell
$env:ANDROID_SERIAL = 'emulator-5556'
.\gradlew.bat --no-daemon --console=plain -PandroidTestBuildType=d15test -Pandroid.testInstrumentationRunnerArguments.class=io.github.xiangwang2000.dnsshield.viewmodel.ResolverCommandViewModelFailureInstrumentedTest :app:connectedD15testAndroidTest
```

## APK 身分（本地測試用途，未發布）

| APK | SHA-256 |
| --- | --- |
| D08 App | `10776e61a0d06d160a1878bf451ca84274d0e64fe5e6ecab1bc8c5d09db94acb` |
| D08 AndroidTest | `bd3dab3d8482e9a96029b3d73e283ec0a3af5fdcfc2ce861db2eb2a418b4aafc` |
| D15 App | `a70d9097df1edcbbbecc487f196f2b14b62d974804ce918bba3330becbde50cc` |
| D15 AndroidTest | `fad1358418d77921c5301fbe5719e1a19ecf2e7a149d2034ecfe4b4a152026c7` |

## 證據與範圍

ignored 原始證據保留於既有工作樹的 `captures/r11-r14-*`、`app/build/issue86-evidence/{red,green}` 與 Gradle XML；它們未上傳 repo。最新完整 source 與測試、此報告、CI gate 都是可審查的 tracked 內容。

本次沒有重跑真實 Wi-Fi／LTE 切換、Always-on 或 Android 10／API26 全部流程；既有紀錄保留。也沒有完成 IPv6-only／NAT64、真 captive portal、完整 API／OEM／真正 LMK 或 8–10 小時 unplugged power A/B；[#73](https://github.com/XiangWang2000/dns-shield/issues/73) 維持環境追蹤。App version／簽名／release 未變，未發布 APK。
