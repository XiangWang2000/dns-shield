# R10 Wi-Fi／行動數據實機驗收（2026-10-06–07）

關聯：D03 #36、D09 #42、環境追蹤 #73；本輪只新增驗收工具及紀錄。

## 版本與環境

- 產品 source 與 main `1a9180083e0706b43a7c564356e8dbff7dd7af5c` 相同。重用的工作樹原 head `3287d09e4d2d839d58d08f2281cacf11b7dcb5c6` 與該 main 的 Git tree 相同；新增改動只在 AndroidTest、D14 runner 與文件，沒有產品 source／依賴／assets 改動。
- ASUS_AI2302，Android 15／API 35，USB 接線及充電。Wi-Fi 為 IPv4／IPv6 link-local；LTE 為 IPv4＋global IPv6 雙棧。有 Wi-Fi 密碼不等於 captive portal，這次沒有入口登入網路，也沒有 IPv6-only／NAT64 環境。
- main exact CI [37471613389](https://github.com/XiangWang2000/dns-shield/actions/runs/37471613389) SUCCESS。本輪新增測試工具另以本地建置、完整 `verify.ps1` 及以下實機案例驗證，沒有把舊 CI 當成新測試 commit 的 CI。

## 通過的範圍

| 驗收 | 結果 | 可證明的行為 |
| --- | --- | --- |
| D14 真實 Wi-Fi→LTE／LTE→Wi-Fi | 各 1/1；5.156／5.092 秒 | selected physical transport 1→2／2→1，TUN DNS 成功，換網後重查上游而非沿用舊 cache |
| 同一 VPN 的三輪雙向實網切換 | 六次切換、七個穩態階段全部通過 | PID 12290、VPN netId 128 維持不變；恢復 generation 24／26／29／31／34／36；每次切換後各有 fresh DoH A、AAAA 回應，transaction／rcode／answer count 正確 |
| 真實外網連線 | 七階段 DNS＋ping及 IPv4 TCP 全通過；三個 LTE 階段 IPv6 TCP 全通過 | 實際連線能力，而非只有 fake upstream 成功；短樣本不代表所有網路與零中斷 |
| gated 有效舊回應，兩方向 | 各 1/1；8.985／8.237 秒 | 舊查詢先抵達 fixture；只有確認 selected route 改變且穩定後才釋出有效答案；客戶端在釋出後繼續監聽三秒，只有非成功回應，沒有遲到 NOERROR；同 domain 必須再到上游，舊答案未進新 cache |
| strict-mode 切網前後，兩方向 | 各 1/1；9.418／8.702 秒 | 同一次 VPN／同一 strict resolver 設定下換網；實際目標 VPN transport、service fence log、OkHttp client identity 更新；fresh AAAA 回答為無答案 SERVFAIL，測試 domain 明文 UDP=0 |
| D03 LTE dual-stack VPN off/on/off | 1/1；2.380 秒 | VPN 前／中／後 IPv4、IPv6 TCP及外部 IPv4／IPv6 DNS AAAA；VPN 中 virtual IPv4 DNS AAAA |
| D03 IPv4 Wi-Fi VPN off/on/off | 1/1；1.928 秒 | 同機當前 IPv4-only Wi-Fi 的代表情境 |
| 受影響的既有 D08 TLS／fallback | 4/4；22.675 秒 | 無效憑證及慢 handshake 的 strict 零明文、允許 fallback 的原行為仍成立；明確選四個原方法，沒有把 manual skip 算成 pass |

Strict fixture使用不受信任的憑證；它證明 strict 前後不降級與 client 重建，不證明「有效的舊 TLS 成功答案」被 fencing。此輪兩次 strict 記錄均 `oldQueryPendingAtFence=false`，不宣稱 TLS 查詢在整個換網期間仍 pending。有效舊成功回應的實際 handoff 防護由獨立 gated UDP/TUN 案例證明。受控 TLS 的背景請求失敗是預期負面情境，不報成實網零失敗或零封包遺失。

## 重現命令

使用 Android Studio JBR 作為 JAVA_HOME，ANDROID_HOME 指向本機 SDK。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1
.\gradlew.bat --no-daemon --console=plain :app:assembleD08test :app:assembleD08testAndroidTest
powershell -NoProfile -ExecutionPolicy Bypass -File tools\d14-device-test.ps1 -Action Run -Serial SERIAL -ManualNetworkHandoff -CheckDelayedResponseFence -BenchmarkLabel r10-delayed-fence
adb -s SERIAL shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.DohTlsFallbackInstrumentedTest#strictModeSurvivesExternalNetworkHandoff -e handoff_direction wifi-to-cellular io.github.xiangwang2000.dnsshield.d08test.test/androidx.test.runner.AndroidJUnitRunner
```

反向 strict 使用 `handoff_direction cellular-to-wifi`。執行前需安裝對應隔離 APK及 AndroidTest APK、確認來源網路與 VPN 授權。D14於 fresh `D14_NETWORK_SWITCH_REQUIRED`、D08於 fresh `D08_HANDOFF_SWITCH_REQUIRED` 後才切換；D08 Log tag為 `D08_HANDOFF`。不帶方向時 manual strict case會 skip，不能將該 skip 視為實機驗收。持續實網切換的裝置端二進位 DNS 回應先 base64再通過 adb，避免 shell 的 LF→CRLF 轉換污染 packet。

## 本地證據及 APK SHA256

Raw evidence保留在重用工作樹的 ignored `captures/`，沒有上傳手機原始 dumpsys／logcat。

- D14基礎 reports：`d14/d14-e2e-muwsrb1f.json`、`d14/d14-e2e-muwsrudh.json`。
- 最終 gated reports：`d14/d14-e2e-muwtmfqd.json`、`d14/d14-e2e-muwtljuq.json`，均 `failure=null`、cleanup true、沒有 fallback stop。
- 真實持續 VPN：`r10-real-continuous-handoff-summary.json`／`-logcat.txt`、七個 `r10-real-handoff-phase*-connectivity.txt` 與 raw DNS `.bin`；控制器 `.py` 保留供重現。
- strict：`r10-strict-{wifi-to-cellular,cellular-to-wifi}.txt`、`-logcat.txt`、`-controller.json`。
- D03：`r10-d03-mobile-dualstack.txt`、`r10-d03-wifi-ipv4.txt`；原 D08：`r10-d08-original-four-regressions.txt`。
- 最終完整驗證：`r10-cellular-completed-verify.log`，29 Python、283 JVM／48 suites，0 failure／error／skip；assets、lint、Debug及 D14／D04／D03 APK均通過。D08 app／AndroidTest另行建置成功，沒有新的編譯 warning；既有 allNetworks deprecation 不因增量建置未列出就宣稱已移除。

| APK | SHA256 |
| --- | --- |
| D03 app | `651419937aedef9662e4743732f1c965be9580b7328d6629e224d683a053ee22` |
| D03 test | `c77725f3f4be85b44210fcd52d66bba61828d5086302bf82a5f19388ddf6c0de` |
| D14 app | `73eb5e89fc1941f20c33efdbfbbd1aa7fea92a550b5ca96e723111f4c9dd5c50` |
| D14 final test | `7214f102f03f950fd1c270f9a547e2f65c72da594004e6f0ba67f75cbcd8150e` |
| D08 app | `6f1a24bbc249c024de43911ad8cd5c777120515e3a3d5bddee01f059d126b08d` |
| D08 final test | `31197bccb4f10610a7862c8833a9f4cc2107cbedb644745dbc962e282c7ab9d5` |

## 負面前提與清理

保留未捕捉 fresh marker 的第一輪、raw adb binary換行污染、初始 baseline 已有cache、固定延遲 fixture 尚未發出答案、正式VPN擋住physical-default前提、consent／Log tag／舊查詢重疊前提等負面紀錄；不把它們抹成 pass或冒稱產品切網缺陷。對應證據位於 `r10-real-handoff-probe-negative/`、`r10-strict-{precondition,marker,overlap}-negative/`、初期 D14 failure reports及 build logs。gate及observer的前提失敗清理已修正，fixture初始權限與編譯失敗均已處理。

六個本輪新增 D03／D08／D14 app/test 套件已移除。只剩原正式版；正式資料／resolver選擇保留，正式VPN已恢復運作，example.net DNS／ping 1/1。Wi-Fi=1、mobile_data=1、airplane=0、Always-on與lockdown原值均null；沒有升級正式APK、設定APN、發版或合併main。所有既有工作樹、ignored evidence及root原 untracked進度文件保留。

## 缺口核對

核對最新 #33／#36／#42／#47／#48／#73、Project2及相關報告；未找到另一個漏列的獨立驗收類別。原 D03／D09只按限定核心範圍 Done，本輪補充實網證據。#73的 Wi-Fi／行動數據項可勾完成，但其餘四項保持未完成：IPv6-only／NAT64、真正 captive portal、完整 API／OEM／真正 LMK、8–10小時 unplugged paired power。Android10未豁免背景限制的負面結果仍保留；本輪沒有修復或重新宣稱該限制已解決，DNS-only lockdown仍不宣稱支援。
