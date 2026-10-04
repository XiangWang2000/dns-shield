# 網路變更復原的能力邊界

DNS Shield 以兩種被動 callback 監看網路：`INTERNET + NOT_VPN` 候選網路，以及 App 的預設網路。API 31 以上另用 `registerBestMatchingNetworkCallback` 取得最佳非 VPN 網路的 identity。這些 callback 不會要求系統喚醒或維持額外網路。

## API 24–27

`registerDefaultNetworkCallback` 追蹤 App 的預設網路；官方文件指出它可能是 VPN 這類虛擬網路。[Android 7.1.2 AOSP 的 `Vpn.updateCapabilities`](https://android.googlesource.com/platform/frameworks/base/+/adbf1d0/services/core/java/com/android/server/connectivity/Vpn.java) 會從明確設定的 `underlyingNetworks` 複製 transport。未指定底層網路時，VPN capabilities 只標示 `TRANSPORT_VPN`。DNS Shield 沒有呼叫 `setUnderlyingNetworks`，因此不能依賴該 callback 得知實際 Wi-Fi 或行動網路。

`getNetworkInfo(TYPE_VPN)` 也不是替代訊號：Android 7.1.2 的 [ConnectivityService](https://android.googlesource.com/platform/frameworks/base/+/android-7.1.2_r36/services/core/java/com/android/server/ConnectivityService.java) 只有在 VPN 明確提供 underlying network 時，才嘗試回傳其中一個網路的 `NetworkInfo`；未指定時回傳的是 VPN 網路狀態。這個舊 API 也不提供可供 callback 關聯的 `Network` identity。

因此，API 24–27 可以觀察各候選網路的連線狀態，但當 Wi-Fi 與行動網路都持續在線時，沒有找到受支援的被動公開 API 可判斷系統把 VPN socket 的預設路徑切到哪一個。兩個候選 transport 相同時，較新版本以 transport 對應 identity 也同樣有歧義。`requestNetwork` 不是合適的替代方式，因為它會要求網路滿足條件，可能喚醒或維持該網路。

## 驗收狀態

Issue #42 維持 **In Progress**，直到實機驗收記錄 Wi-Fi／行動網路切換、飛航模式與 captive portal 的結果，並確認 API 24–27 的已知限制可接受。`verify.ps1` 不會執行這些實機測試。

## 2026-09-29 D06／D11 整合與 Android 10 Wi-Fi 實測

既有 D09 工作樹已整合 D06 主線。保留 network generation 對快取、DoH 退避、舊查詢和明文 fallback 的防護；UDP／TCP 回應沿用 D11 的鎖內狀態檢查及不可變提交、鎖外 TUN 寫入。本地封鎖 NXDOMAIN 也走同一狀態提交器，避免政策或網路變更後傳出尚未提交的舊封鎖回應。完整 `verify.ps1` 通過：29 Python、234 JVM／45 suites（0 failures／errors）、assets、lint 與 APK 建置。

ASUS_Z01RD（Android 10，USB）在僅有 IPv4 Wi-Fi 的環境執行 `D09WifiRecoveryDeviceTest` 1/1：關閉 Wi-Fi 後服務記錄「目前沒有可用網路」，重新啟用後記錄 validated 非 VPN 網路已就緒；觀測恢復耗時 2374 ms、期間失敗 DNS 查詢 0 筆，隨後 `example.com` 經真實 TUN 查詢成功。測試結束確認 Wi-Fi 已恢復啟用、VPN 已停止。原始輸出位於本工作樹 ignored `captures/d09-wifi-recovery-device.txt` 與 `captures/d09-wifi-recovery-logcat.txt`。

整合版另有 `.d04test` 診斷 UI／TCP/TUN 5/5、`.d08test` TLS strict／fallback 與 UDP→TCP 5/5；初次執行時查詢落在 VPN 啟動後約 500 ms 的初始網路 callback debounce 視窗，可能合法回 SERVFAIL，測試已待初始網路狀態穩定再驗證穩態行為。這不代表 Wi-Fi↔行動網路、captive portal、飛航模式或 API 24–27 實機矩陣已完成；裝置目前沒有行動數據或其他測試網路，Issue #42 與 PR #59 保持 In Progress／Draft。

## Android 10 repeated Wi-Fi and airplane recovery (2026-10-02)

Candidate `88f075c` plus the new isolated harness passed `D09WifiRecoveryDeviceTest#repeatedWifiAndAirplaneRecoveryRestoreDns` 1/1 in 18.742 seconds on ASUS_Z01RD / API 29. Three real Wi-Fi off/on cycles and one airplane-plus-Wi-Fi-off → airplane-off-plus-Wi-Fi-on cycle each observed a new recovery log/generation and a valid TUN DNS response with its own transaction ID. The final recovery used generation 22 and took 2473 ms, with zero failed DNS queries during that recovery. This checks actual Wi-Fi recovery, not cellular handoff or per-response proof of generation fencing.

The first harness version passed all three Wi-Fi cycles but timed out after enabling airplane mode because this handset legitimately kept Wi-Fi connected. The final version explicitly disables Wi-Fi while in airplane mode and enables it after leaving airplane mode. Preserve the initial output and logcat as a test-precondition failure, not a product failure or passing airplane test. Both versions restore original airplane/Wi-Fi settings in finally; device readback was airplane=0, Wi-Fi=1.

Raw ignored evidence: `captures/d09-android10-20261001-repeat-flight{,-final}.txt` and corresponding `-logcat.txt`; final `verify.ps1`: `captures/d09-repeat-flight-final-verify.log`. The existing single-outage test remains available. Integrated TLS strict/fallback and UDP→upstream TCP device regression also passed 5/5 in 107.605 seconds (`captures/d09-android10-20261001-strict-tcp.txt`). No production package was replaced.

The 2026-10-04 issue policy supersedes historical full-matrix completion gates: special networks/platform matrices are deferred in #73. D09 still needs #68 candidate-versus-effective-underlay correction, callback regressions, and common-version integration #72. Neither these short radio tests nor the deferred policy closes those code requirements.
