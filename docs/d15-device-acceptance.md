# D15 Always-on／系統恢復驗證紀錄

## 2026-09-29 D09 主線整合

既有 `d15-always-on` 工作樹整合 D09 head `88f075c`（含 D06 診斷與 D11 鎖安全 TUN 回應）。保留 D15 的使用者顯式啟停意圖、`START_STICKY`／空 action 恢復條件、授權撤銷處理，並接上 D06 的 `ACTION_RELOAD_DOMAIN_POLICY` 與目前測試 build variant 設定。完整 `verify.ps1` 通過：29 Python、238 JVM／46 suites 零失敗／錯誤、assets、lint、Debug/AndroidTest/D04 APK。D15 app/test APK 另行建置成功。D04 裝置測試檔使用 `ConnectivityManager.allNetworks` 的 deprecated warning 來自本次合入的 D09 測試，非 D15 產品碼。

ASUS_Z01RD／Android 10 使用已同意 VPN 權限的隔離 `.d15test` 套件，`D15ServiceSmokeTest` 2/2（1.739 秒）：顯式開啟確實到達 RUNNING、顯式停止到達 STOPPED；停止後再送空 action 仍保持 STOPPED，持久化的 desiredEnabled 為 false。測試前後清除隔離偏好，不觸及正式套件資料。原始輸出位於本工作樹 ignored `captures/d15-d09-device-lifecycle-final.txt` 與 `captures/d15-d09-final-verify.log`。

系統 VPN 設定有多個同名 DNS Shield 項目，尚無法從該畫面確定哪一項對應 `.d15test`。本次沒有更改 Always-on／lockdown 系統設定，也沒有把嘗試 `stopService`（系統仍綁定 VPN）視為程序重建。重開機、系統程序回收、自動恢復、VPN 切換、授權撤銷及 lockdown 路徑仍需實機矩陣；Issue #48 與 PR #63 維持 In Progress／Draft。

## 2026-09-30 系統 Always-on 啟動與授權撤銷

ASUS_Z01RD／Android 10 的 VPN 詳細頁 `AppManagementFragment.mArguments` 實際回報 `package=io.github.xiangwang2000.dnsshield.d15test`，因此安全開啟該隔離套件的系統 Always-on；lockdown 始終為 `0`。測試前正式版與 `.d15test` 的 ASUS `AUTO_RUN` 都是 `ignore`。第一次用 `am crash` 測程序死亡時，ActivityManager 明確記錄 `App Op not allow to restart app`；只對 `.d15test` 暫設 `AUTO_RUN allow` 後重測，該拒絕訊息消失，但 `am crash` 後仍未自動建立新程序／TUN。這是強制崩潰測試，不能等同系統低記憶體回收，程序重建仍未驗收。

修正前，在 `.d15test` 已保存 `desired_enabled=true`、系統 Always-on 指向該套件的條件下重開機（boot ID `3493f6b6-162b-4032-99c9-93936cd6af43` → `fbd3f1ab-5618-476e-a319-71adaa89cf60`）：Android 以 `android.net.VpnService` action 啟動服務，但沒有 `tun0`。根因是 `onStartCommand` 只讓 null action 進入系統恢復分支。修正讓 `VpnService.SERVICE_INTERFACE` 與 null action 共用原有 `VpnUserIntentState.shouldRecoverFromSystemStart` 防護，保留明確停止／revoke 不恢復的規則。

修正後完整 `verify.ps1` 通過：29 Python、238 JVM／46 suites（零失敗／錯誤）、production assets、lint、Debug/AndroidTest/D04 APK；隔離 App 與 AndroidTest APK 另行建置成功。Android 10 `D15ServiceSmokeTest` 3/3 通過，新增系統 `VpnService` action 恢復案例，並在明確停止案例追加相同 action 不得重啟的斷言。原始本機 ignored 記錄：`captures/d15-system-action-verify.log`、`captures/d15-system-action-apk-build.log`、`captures/d15-system-action-device-instrument.txt`。隔離 APK SHA256：App `80A8039025CBAADA44DD425C11F583544EE0AD43BF22D37F740E4CF432DCB25F`，AndroidTest `13558535E09C6D2F05F7A253A729045C401CFD9DAB1578807B7538FD9E06AC59`。

修正後重新明確啟用 `.d15test`，再重開機（boot ID `fbd3f1ab-5618-476e-a319-71adaa89cf60` → `3ef3b4b3-edff-4946-b362-4d188313bcf4`）：Android 仍送 `android.net.VpnService` action，服務以前景模式啟動，`tun0` 重建；Connectivity 顯示 VPN `CONNECTED`、DNS `10.0.0.1`，手機成功解析並 ping `example.org`（104.20.26.136，1/1）。App UI 顯示「防護中」。其後從 App 明確停止，等待後 `tun0` 仍不存在且 `desired_enabled=false`，沒有被系統 Always-on 立即重啟。

再次啟用後，在已讀取詳細頁 `package=.d15test` 的系統設定中執行「清除 VPN 設定檔」。結果 `always_on_vpn_app=null`、lockdown `0`、`ACTIVATE_VPN=ignore`、`desired_enabled=false`、`tun0` 消失；正式版與 `.d15test` App 都仍安裝，手機網路仍可用。最後將隔離套件 `AUTO_RUN` 還原為原本的 `ignore`。這證明授權撤銷路徑會清除恢復意圖，但沒有測試切換至其他 VPN、真正系統低記憶體回收、其他 Android 版本的前景服務限制，亦未宣稱 DNS-only 與 lockdown 相容。D09 依賴仍未 Done；D15 保持 Draft／In Progress。

## 2026-09-30 Android 15／API 35 模擬器系統恢復

既有 `dns_shield_api35` AVD（Android 15／API 35）安裝 `.d15test` 隔離 App／AndroidTest APK。初跑 `D15ServiceSmokeTest` 為 2/3：`@Before` 送出的 STOP 仍在佇列時，新案例已寫入 `desired_enabled=true`，稍後到達的 STOP 把它清回 false。這是測試前置狀態競態；在新案例寫入恢復意圖前，先經 START→RUNNING→STOP→STOPPED，同步清空前次停止命令。產品恢復邏輯未改。重跑與另三次重複測試皆 3/3；修正測試後完整 `verify.ps1` 通過（29 Python、238 JVM／46 suites、assets、lint、APK）。原始 ignored 記錄：`captures/d15-system-action-api35-instrument.txt`、`captures/d15-api35-test-sync-rerun.txt`、`captures/d15-api35-test-sync-repeat-1.txt` 至 `-3.txt`、`captures/d15-api35-test-sync-verify.log`。

啟用 `.d15test` 後，以 VPN Settings 唯一顯示 Connected 的項目進入齒輪，並從 `AppManagementFragment.mArguments` 回讀完整套件 ID，才對該項開啟 Always-on；lockdown 保持 0。重開機 boot ID `d786938d-04ae-4ab0-b2a5-9b0cfdfeac80` → `920be004-e84c-427f-89f1-68658d288ff3` 後，系統以 `android.net.VpnService` action 建立新程序，服務為 foreground（type `0x400`），VPN CONNECTED、`tun0` 與 DNS `10.0.0.1` 存在；模擬器解析並 ping `example.org`（104.20.26.136，1/1）。

App 顯式停止後 `tun0` 消失、`desired_enabled=false`，Always-on 仍指向 `.d15test` 且沒有立即重啟。再次啟用後，在已核對套件 ID 的詳細頁執行 Forget VPN：`always_on_vpn_app=null`、lockdown 0、`ACTIVATE_VPN=ignore`、`desired_enabled=false`、`tun0` 不存在。此次新裝的 D15 app/test 套件已從 AVD 移除，模擬器已關閉；原有其他測試套件未動。這補足 Android 15 模擬器的系統啟動、重開機、顯式停止與授權撤銷證據，但不等同 Android 15 實機、低記憶體程序回收、切換其他 VPN、lockdown 或 API 24–27 驗收。D09 依賴仍未 Done，D15 維持 Draft／In Progress。

## 2026-09-30 Android 15 模擬器切換其他 VPN

重新使用同一 API 35 AVD（既有 D04/D07/D08 隔離套件未移除），只安裝 D15 隔離 App。D15 經 App 與系統 VPN consent 啟用後，`desired_enabled=true`、`tun0` 存在。先在已核對 `AppManagementFragment.mArguments` 為 `.d15test` 的詳細頁開啟 Always-on、lockdown 0；此時嘗試啟用既有 `.d04test`，它仍顯示「防護已關閉」，不能列為成功切換。關閉 D15 Always-on 後，系統設定為 null、D15 TUN 消失、`desired_enabled=false`；這一步與後續真正切換分開記錄。

再次由 D15 App 明確啟用，確認 `desired_enabled=true`、UI「防護中」及新 `tun0`。再由已安裝的 `.d04test` App 啟用其 VPN：D15 `desired_enabled` 轉為 false，D04 UI「防護中」、其 `DnsVpnService` 為 foreground（type `0x400`），`tun0` 由介面 19 變為新介面 20；Always-on 保持 null。稍後回讀 D15 仍為 false、D04 仍為前景服務，未觀察到 D15 搶回 VPN。ADB shell 嘗試直接送 `android.net.VpnService` action 到 D15 時被 Android 以 `Requires permission not exported from uid` 拒絕，因此該嘗試不算系統恢復測試；既有同 UID instrumentation 已覆蓋停止後 action 防護。

測後由 D04 App 明確停止，確認 `tun0` 消失；本次安裝的 `.d15test` 已卸載，Always-on=null、lockdown 0，原有 D04/D07/D08 套件保留，AVD 已關閉。這補足 API 35 模擬器「一般 VPN 切換至另一 App」的狀態清理；不聲稱 Always-on 開啟時可切換、Android 10 實機切換、低記憶體程序回收、lockdown 或 API 24–27 已驗收。D09 依賴仍在 In Progress，D15 保持 Draft／In Progress。

## 2026-09-30 API 35 強制程序死亡觀察

同一 AVD 再次暫裝 `.d15test`，由 App 取得 VPN consent，並在 `AppManagementFragment.mArguments` 核對完整 ID 後開啟 Always-on、lockdown 0。測前 boot ID `96701cee-f2cf-4ba2-8d19-f6223fb771d4`、PID 1855、`desired_enabled=true`、`tun0` 存在。`am crash` 後程序和 TUN 消失；多次回讀期間 Always-on 與 desired 意圖仍保留，但沒有觀察到新程序或 TUN。ActivityManager 記錄該程序死亡與 `crashCount=1`，service 紀錄有 `startRequested=true`、`stopIfKilled=false`、`startCommandResult=1`（`START_STICKY`），未顯示排定重啟。這不等同系統低記憶體回收。

手動啟動 App 並再次點選防護後 PID 2155、`tun0` 恢復；接著由同 UID 的 `run-as` 執行 `kill -9`，觀察期間也沒有新程序或 TUN。但此操作發生在前述 crash 之後，既有 `crashCount=1`，不能當成獨立乾淨條件下的程序回收結論。Android [Service `START_STICKY` 文件](https://developer.android.com/reference/android/app/Service#START_STICKY) 說系統稍後嘗試重建服務，並未給出即時恢復期限；目前只記錄觀察結果，不以此推導產品恢復分支的新修正。

在 Always-on 與 `desired_enabled=true` 仍保留、TUN 尚未恢復的狀態重開 AVD，boot ID 變為 `c8eab05f-950e-41c0-9f2b-70d409db0560`：系統 `android.net.VpnService` action 建立 PID 1368 與前景服務（type `0x400`），`tun0` 恢復，`example.org` 解析至 172.66.157.237 並 ping 1/1。這是再次證實重開機恢復，不是程序回收成功。其後從已核對 ID 的 Settings 詳細頁 Forget VPN，回讀 Always-on=null、lockdown 0、`ACTIVATE_VPN=ignore`、`desired_enabled=false`、TUN 消失；本次暫裝 D15 已卸載，AVD 已關閉。D15 的真正系統回收與其他未驗收矩陣仍待完成。

為排除前次 `crashCount=1` 干擾，再將 `.d15test` 完全卸載後重新安裝，於新 AVD boot ID `27d822b4-eb79-4fa9-a99a-f2197e3a0afc` 明確啟動 VPN、核對 ID 後開啟 Always-on。測前 PID 1856、`tun0`、`desired_enabled=true`，service `startRequested=true`／`stopIfKilled=false`／`startCommandResult=1`，沒有先跑 `am crash`。同 UID `kill -9 1856` 後，前 35 秒每 5 秒觀察，加上後續 45 秒，均無新程序或 TUN；Always-on 仍指向 D15，service 紀錄 `app=null`、`startRequested=true`。這獨立確認「強制終止後約 80 秒未觀察到自動恢復」，仍不是低記憶體回收測試，也不推論 Android 永不重啟。再重開機 boot ID `05de511d-4d1c-45f4-9808-642bc27b5e83`，新 PID 1362 與 `tun0` 重建。最後在核對 ID 的 Settings 頁 Forget VPN，Always-on=null、lockdown 0、`desired_enabled=false`、TUN 消失；D15 測試 App 已卸載、AVD 關閉。此負面觀察保留在 D15 未驗收清單，不標 Done。

## 2026-09-30 程序死亡根因與獨立恢復服務（仍未 Done）

本輪先核對既有工作樹 `codex/d15-always-on`／PR #63，baseline `612a9f7` 的 Windows CI 36679922359 成功。ASUS_Z01RD／Android 10 原設定為 Always-on=null、lockdown=0、AUTO_RUN=ignore；正式版資料保留。手機只有目前 IPv4 Wi-Fi。先補一般跨 App VPN 切換：D15 運作中由暫裝 `.d04test` 接手，D15 的 desired 變 false，D04 前景服務與新 TUN 接手，稍後沒有被 D15 搶回。這項切換發生在新增恢復服務前，不能當作新服務版本的切換驗收；D04 測後停止並移除。證據：ignored `captures/d15-physical-20260930-vpn-switch.txt`。

### 根因與修正界線

Android 10 的 `run-as ... kill -9` 被 SELinux 拒絕，PID／TUN 未消失，不能當作程序死亡。新增僅在 `.d15test` 的 `D15ProcessDeathActivity`：由具 `android.permission.DUMP` 的 shell/system 啟動，延遲五秒以同程序 `Process.killProcess` 終止；期間回 HOME，沒有 instrumentation 留在程序內。正式 APK 不包含此 Activity。這是真實 SIGKILL，仍不是低記憶體 LMK。

修正前實機 PID 30655 在 21:49:29.493 自行 SIGKILL。系統先在 29.591 處理 TUN 移除／VPN unbind 時收到 DeadObjectException，29.670 才處理程序死亡；VPN sticky record 留下 app=null，但未排定重啟，約 88 秒後仍無 TUN。AOSP Android 10 的 `removeConnectionLocked` 例外路徑會經 `serviceProcessGoneLocked` 把服務從 process.services 移除，而 `killServicesLocked` 只遍歷 process.services 排定 sticky 重啟；這是與時間順序及 stack 相符的根因推論，未直接修改系統驗證。官方來源：[ActiveServices.java](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android10-release/services/core/java/com/android/server/am/ActiveServices.java)。原始證據：`captures/d15-physical-20260930-unbind-exception.txt`、`d15-physical-20260930-selfkill-checked.txt`。`selfkill-observation.txt` 曾有空 PID Trim 錯誤，不採信其中 PID 欄。

新增同程序、非匯出的 `VpnRecoveryService`，保留與系統 VPN binding 無關的 START_STICKY 記錄；不加輪詢、工作執行緒或另一個程序。它沿用既有通知 ID，正常啟動保留目前通知；null 重建才要求原 VPN service 以系統 action 恢復，原 user-intent 防護仍會再檢查。STOP、revoke、啟動／重新啟動失敗及 tunnel 停止皆清理恢復服務。DNS 傳輸、D11 回應提交與 strict-mode fence 未改。

Android 15 negative 回歸曾確認：授權撤銷後強制以 SYSTEM_EXEMPTED 提升 helper 會 SecurityException；直接拒絕 `startForegroundService` 又會在 API 29/35 觸發 FGS timeout。最終 helper 由「已完成前景提升」的 VPN 以 `startService` 啟動，再於授權有效時自行提升；STOP／無授權時直接結束。授權在 prepare 與提升之間消失的 SecurityException 僅在再次確認未授權時結束，其他權限錯誤仍拋出。原 VPN 若被 foreground system start 呼叫卻不允許恢復，先履行前景契約再依閒置狀態停止。失敗證據與修正後輸出均保留，沒有將中途成功當成最終驗收。

### 最終候選版驗證

| 案例 | Android 10 實機 | Android 15／API 35 AVD |
| --- | --- | --- |
| START→RUNNING→STOP、明確停止後 null／system action／helper 不恢復 | 3/3，3.832 秒 | 3/3，5.015 秒 |
| 未授權 START／RESTART 到 FAILED、late helper 不留前景服務 | 1/1，3.613 秒 | 1/1，3.212 秒 |
| 無 instrumentation 的 SIGKILL→sticky null→新 PID／TUN／DNS | 電池豁免下成功：7488→7730，TUN 69→70 | 預設電池設定成功：3051→3160，TUN 34→35 |
| 運作中 Settings Forget VPN | desired=false、TUN 消失、兩服務消失 | 同左，ACTIVATE_VPN=ignore |

兩個最終 SIGKILL 案例的 Always-on 都為 null，測的是顯式啟用意圖的 sticky 重建；不要與前面 baseline 的真正 Always-on／重開機驗收混為一項。約 10.8 秒採樣已觀察到新 PID／TUN，後續至約 32 秒仍存在；兩機 `example.org` 解析／ping 1/1。

實機在 Always-on 指向 D15、AUTO_RUN=allow、安裝後等 81 秒排除系統 VPN 60 秒暫時白名單的候選版試驗，PID 3660→3959，但 helper 與 VPN 在重建命令前被 AMS 以 app-idle 停止，TUN 未恢復。不同 helper 啟動方式的早期試驗也有同一限制，不能宣稱預設實機已修好。AOSP `stopInBackgroundLocked`／`getAppStartModeLocked` 與此紀錄相符，UID idle 不等於 standby bucket。只對隔離套件暫加 user battery whitelist，再移除 tempwhitelist，PID 5210→5512、TUN 58→59、DNS 1/1；最終 ordinary-start 版本亦如上表成功。這支持電池／背景服務限制是另一個阻斷點，不是產品已能繞過系統政策。[ActivityManagerService.java](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android10-release/services/core/java/com/android/server/am/ActivityManagerService.java)

原始 ignored 記錄：`captures/d15-recovery-ordinary-{smoke,negative}-<serial>.txt`、`d15-recovery-final-death-<serial>-{before,observation,logcat,after}.txt`、`d15-recovery-final-revoke-<serial>.txt`；serial 為 `JCAZB7604377HFP`／`emulator-5554`。背景限制對照為 `d15-recovery-expired-whitelist-*`、`d15-recovery-battery-exempt-isolated-*`。執行 negative class 前必須在核對套件 ID 的 Settings 頁 revoke，smoke class 則需先給隔離套件 VPN consent：

```powershell
adb -s <serial> shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.D15ServiceSmokeTest io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
adb -s <serial> shell am instrument -w -r -e class io.github.xiangwang2000.dnsshield.service.D15UnapprovedStartTest io.github.xiangwang2000.dnsshield.d15test.test/androidx.test.runner.AndroidJUnitRunner
# 啟用 VPN、回 HOME，且沒有正在執行的 instrumentation 後才做死亡觀察。
adb -s <serial> shell am start -n io.github.xiangwang2000.dnsshield.d15test/io.github.xiangwang2000.dnsshield.D15ProcessDeathActivity
adb -s <serial> shell input keyevent HOME
```

本輪測後：實機 Always-on=null、lockdown=0、ACTIVATE_VPN=ignore、desired=false、無 TUN／service；user battery whitelist 已移除，AUTO_RUN 還原 ignore，正式版與既有 D15 app/test 保留，網路 ping 1/1。AVD 本輪新增 D15 app/test 已移除，原有 D04/D07/D08 保留；本任務模擬器及 screen-awake helper 已關閉。

仍缺：Android 10 預設背景限制下可靠重建、真實 LMK、最終版本跨 VPN 切換／重開機矩陣、API 24–27 與 Android 15 實機、即時死亡下 STOP／revoke 的磁碟意圖持久化（目前 SharedPreferences.apply）、D09 #42 依賴。DNS-only lockdown 不宣稱支援。此切片留在 Draft／In Progress，不合併 main、不標 Done。

最終 ordinary-start 版完整 verify.ps1 在不更動程式碼下重跑成功：29 Python、238 JVM／46 suites 零 failure/error、assets、lint、Debug/AndroidTest/D04 APK。第一輪既有 DnsUdpUpstreamClientTest.truncatedUdpResponseRetriesTheSameUpstreamOverTcpWithinTheDeadline 於暫時 UDP/TCP 共用埠發生 BindException，保留 captures/d15-recovery-ordinary-final-verify.log；通過紀錄為 captures/d15-recovery-ordinary-final-verify-rerun.log。沒有新增 warning；D09 測試既有 deprecation 不另當本切片警告。隔離 APK SHA256：App 098BD093DAC054D6F39B1B9E5343BF47023901A5BCA8025E4A7F40BB36CAF506，AndroidTest 361B3F4440C2826A5552581B1B498305230B99B2A4408DF6EC8A231393BECD24。獨立 reviewer 未見確定 bug，保留上述剩餘驗收風險。
