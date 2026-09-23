# 網路變更復原的能力邊界

DNS Shield 以兩種被動 callback 監看網路：`INTERNET + NOT_VPN` 候選網路，以及 App 的預設網路。API 31 以上另用 `registerBestMatchingNetworkCallback` 取得最佳非 VPN 網路的 identity。這些 callback 不會要求系統喚醒或維持額外網路。

## API 24–27

`registerDefaultNetworkCallback` 追蹤 App 的預設網路；官方文件指出它可能是 VPN 這類虛擬網路。[Android 7.1.2 AOSP 的 `Vpn.updateCapabilities`](https://android.googlesource.com/platform/frameworks/base/+/adbf1d0/services/core/java/com/android/server/connectivity/Vpn.java) 會從明確設定的 `underlyingNetworks` 複製 transport。未指定底層網路時，VPN capabilities 只標示 `TRANSPORT_VPN`。DNS Shield 沒有呼叫 `setUnderlyingNetworks`，因此不能依賴該 callback 得知實際 Wi-Fi 或行動網路。

`getNetworkInfo(TYPE_VPN)` 也不是替代訊號：Android 7.1.2 的 [ConnectivityService](https://android.googlesource.com/platform/frameworks/base/+/android-7.1.2_r36/services/core/java/com/android/server/ConnectivityService.java) 只有在 VPN 明確提供 underlying network 時，才嘗試回傳其中一個網路的 `NetworkInfo`；未指定時回傳的是 VPN 網路狀態。這個舊 API 也不提供可供 callback 關聯的 `Network` identity。

因此，API 24–27 可以觀察各候選網路的連線狀態，但當 Wi-Fi 與行動網路都持續在線時，沒有找到受支援的被動公開 API 可判斷系統把 VPN socket 的預設路徑切到哪一個。兩個候選 transport 相同時，較新版本以 transport 對應 identity 也同樣有歧義。`requestNetwork` 不是合適的替代方式，因為它會要求網路滿足條件，可能喚醒或維持該網路。

## 驗收狀態

Issue #42 維持 **In Progress**，直到實機驗收記錄 Wi-Fi／行動網路切換、飛航模式與 captive portal 的結果，並確認 API 24–27 的已知限制可接受。`verify.ps1` 不會執行這些實機測試。
