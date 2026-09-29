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
