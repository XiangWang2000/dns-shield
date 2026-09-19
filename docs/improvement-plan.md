# DNS Shield 改善工作清單

狀態：規劃待實作。所有未勾選項目都不代表已修復。
審查基準：`ba4da78078cfdaefd91a762131a5c46b6c9d406a`（main）。
本清單源自原始碼與既有測試／benchmark 文件審查，未重新執行實機測試。
實作前先比對最新 main；若已有等效修復，附證據後標記完成，避免重做。

## 分工與交付方式

- 本 PR 僅保存規劃，作為後續 Codex 工作入口。
- 後續每次處理一個任務或密切相關的一組任務，各開 branch／PR，引用本文件的任務 ID。
- 修復項目優先；可選功能列為 backlog，不要求一次全部導入。
- 每個實作 PR 說明問題、行為改變、驗證結果與尚未驗證的平台；不可把未執行的實機測試寫成通過。
- 合併後在本表附上 PR、驗證證據及殘留限制；合併與發布遵循當次使用者授權及 repository 規則。
- 保留 DNS-only 定位、applicationId、既有可驗證規則來源；不要順帶擴成全流量 VPN。
- 若需重構，先抽出能支援該任務測試的最小元件，避免先進行大型架構重寫。

## 建議順序與進度

| 完成 | ID | 優先度 | 任務 | 依賴 | PR／證據 |
| --- | --- | --- | --- | --- | --- |
| [ ] | D01 | 高 | DNS 封包解析與上游回應驗證 | 無 | 待補 |
| [ ] | D02 | 高 | 快取 TTL 與負向快取正確性 | D01 | 待補 |
| [ ] | D03 | 高 | IPv6 流量行為明確化 | 無 | 待補 |
| [ ] | D04 | 高 | VPN 生命週期串行化與退出清理 | 無 | 待補 |
| [ ] | D05 | 中高 | 有界等待、總 deadline、取消及 SERVFAIL | D01、D04 | 待補 |
| [ ] | D06 | 中 | 診斷指標與完整查詢計數 | D05 | 待補 |
| [ ] | D07 | 中 | 使用者允許／封鎖規則與誤擋解除 | D01、D02 | 待補 |
| [ ] | D08 | 中 | 加密模式與自訂 DoH | D01、D05 | 待補 |
| [ ] | D09 | 中 | 網路切換與故障恢復 | D04、D05 | 待補 |
| [ ] | D10 | 中 | 上游 TCP fallback 與大型回應 | D01、D05 | 待補 |
| [ ] | D11 | 擴充 | 本機 TCP DNS 支援 | D04、D05、D10 | 待補 |
| [ ] | D12 | 中／擴充 | 規則健康狀態與獨立更新 | D07 | 待補 |
| [ ] | D13 | 高 | PR CI 與回歸驗證入口 | 無，可先做 | 待補 |
| [ ] | D14 | 中 | VPN 端到端效能與耗電量測 | D05、D06、D09 | 待補 |
| [ ] | D15 | 擴充 | Always-on／系統重啟恢復 | D04、D09 | 待補 |

## D01 — DNS 封包解析與上游回應驗證

證據：`DnsVpnService.kt` 的 `handlePacket`、`parseDomainName`、`resolveQuery`、`performDohLookup`、`buildNxDomainResponse`。
目前 UDP 接受第一個收到的 datagram，未核對來源、ID 與 question；DoH 主要檢查 HTTP 成功；NXDOMAIN 複製原查詢但將 additional count 歸零，可能留下 EDNS 尾端資料。

實作：
- 抽出具明確失敗結果的封包解析器；檢查實際讀取長度、IPv4 total length／IHL、UDP length、fragment flags／offset，以及 DNS header／question 邊界。
- 明確處理不支援的 opcode／question count／分片；不可把解析失敗的部分網域當成有效名稱送入 matcher。
- 壓縮名稱解析須限制跳轉次數、偵測循環及越界、驗證 label 長度；明確定義不支援輸入的回覆或丟棄策略。
- UDP 綁定指定上游（connected socket 或等效來源驗證），核對來源 port、交易 ID、QR、opcode 與 question；不符合的回應忽略至原 deadline。
- DoH 驗證 DNS 格式、與原查詢的一致性、Content-Type 及串流讀取大小上限；不能只信 Content-Length，也不能無界讀取 body。
- 由已驗證的 header／question 重建 NXDOMAIN、SERVFAIL、必要的 FORMERR；EDNS 若保留，必須重建並使 count 與資料一致。
- 驗證通過前不得 cache；保留每位合併查詢用戶端自己的 ID。

驗收：
- 正常 A／AAAA／EDNS、短封包、非法 length、壓縮循環、分片、錯誤 ID／來源／question、HTTP 200 非 DNS body、超大 body。
- 錯誤回應不入快取；錯誤回應後到達的有效回應仍可接受。
- NXDOMAIN／SERVFAIL 可由獨立 DNS parser 解析，無未宣告的尾端資料。
- 以可控本機 fake upstream 驗證，不依賴公開 DNS 的偶發行為。

## D02 — 快取 TTL 與負向快取

證據：`parseDnsResponseTtl` 忽略 TTL=0、使用 `coerceIn(5, 300)`，無答案通常回到 30 秒；`getCache` 回傳未遞減 TTL 的 bytes，過期依 wall clock 判斷。

實作：
- TTL=0 不跨查詢重用；移除任意提高低 TTL 的下限，可保留有文件的最高保存時間。
- 使用 monotonic clock，注入 clock 供測試；記錄插入時間、各可快取 RR 的 TTL 與 offset。
- 命中時在輸出副本遞減 TTL，不修改共享 cache bytes；OPT 的 TTL 欄位不是一般 TTL，不可遞減。
- 正確解析 Answer／Authority／Additional；完整封包快取不得讓仍會回傳的資料超過其有效期限。
- NXDOMAIN／NODATA 依 SOA TTL 與 MINIMUM 決定負向保存時間；缺 SOA 不任意套用 30 秒。
- SERVFAIL／REFUSED／TC／格式錯誤與一般正向快取分流；若實作短暫失敗快取，明定時間、作用範圍及重新嘗試行為。
- 延續 resolver generation 與 policy identity 隔離。

驗收：
- TTL 0／1／4／300、多 RR 混合 TTL、CNAME 鏈、NXDOMAIN、NODATA、無 SOA、OPT、不完整 RDATA。
- fake clock 前進後 TTL 遞減，過期不命中；wall clock 改變不影響保存期限。
- 多個 concurrent hit 互不污染原始 response 或 transaction ID；切換 resolver／policy 不重用舊回應。

## D03 — IPv6 流量行為

證據：VPN Builder 僅設定 IPv4 address／route／DNS，未呼叫 `allowFamily(AF_INET6)`。依 Android API 契約，未允許的位址家族預設封鎖；實際裝置影響需實測。

實作：
- 維持 DNS-only 設計時，明確允許一般 IPv6 流量走 underlying network。
- 分開描述「一般 IPv6 通行」、「以 IPv4 DNS 查詢 AAAA」、「攔截 IPv6 DNS」、「IPv6 上游」四件事。
- 不宣稱因此已攔截 IPv6 DNS 或 App 自有 DoH。

驗收：
- VPN 開／關下比較 IPv4-only、雙棧、IPv6-only／NAT64 環境的 DNS 與實際連線。
- 驗證一般 IPv6 連線不因 VPN 啟用意外失效；列出可用與未測的環境。

## D04 — VPN 生命週期

證據：`startVpn` 的 running guard 在非同步啟動完成前仍為 false；`runTunnel` 在 IOException／EOF 後只關閉 stream，未統一處理 running 狀態。

實作：
- 使用單一命令處理器／mutex 與 Stopped、Starting、Running、Stopping、Failed 狀態，串行化 start／stop／restart。
- 每個 tunnel 持有自己的 descriptor、job 及 generation；舊 tunnel 的 finally 不得清掉新 tunnel。
- EOF、read failure、establish null、取消、revoke、destroy 均走一致且冪等清理。
- 取消例外須原樣傳遞；避免 tunnel 自己 cancelAndJoin 自己。
- 通知與 UI 由同一生命週期狀態推導，移除 ViewModel 過早宣告成功／停止的競態。
- 檢視 restart 固定 400 ms delay，改為以實際完成狀態決定；有平台需要才保留並說明。

驗收：
- 連續 start、啟動中 stop、快速多次 restart、establish 失敗、EOF、revoke、停止時存在上游查詢。
- 無重複活躍 tunnel、孤兒 job／FD；UI／通知與實際狀態一致。

## D05 — 有界請求、總 deadline 與失敗回覆

證據：每包 `launch` 後才等待 semaphore；in-flight map 沒有容量限制。DoH 與兩次 UDP 串行可能累加延遲；最終 null 僅寫 log。UDP receive 為阻塞式。

實作：
- 為排隊請求、不同 in-flight key、同 key 等待者建立可量測上限；初值由壓測決定，不僅提高 24 的限制。
- 有界 admission 不得讓 read loop 長時間卡住，或使快取／阻擋命中都被慢上游拖住。
- deadline 從收到查詢開始計時，包含排隊與所有 transport 嘗試；coalesced waiter 有自己的等待期限。
- 總失敗／超載對合法查詢回 SERVFAIL；無效輸入遵循 D01 策略。
- 取消時關閉 UDP socket；僅包 `withTimeout` 無法保證阻塞 receive 立刻中止。
- 明確設定 OkHttp call timeout；剩餘預算不足時不再啟動新的完整 timeout。
- 檢查 `protect(socket)` 結果；資源關閉與 permit 釋放涵蓋所有路徑。
- 避免任一 waiter 取消導致所有同查詢用戶端失敗；定義 leader 的所有權及退出行為。

驗收：
- 全部上游無回應、DoH 慢／失敗、UDP 主失敗次成功。
- 大量唯一查詢與大量重複查詢下 pending／heap 有界，快取與阻擋路徑仍可服務。
- 截止後可預期返回 SERVFAIL；stop 不需要等待完整 UDP timeout；無 permit／socket 洩漏。

## D06 — 診斷與計數

證據：`queryCounter` 在 resolved／blocked 時才增加，failed 未計入；現有字串日誌難以分析 transport 與延遲。

實作：
- 定義 received、resolved、blocked、failed、rejected、cache hit、coalesced、DoH／UDP／TCP 與 fallback 計數。
- 分開「用戶端查詢數」與「真正上游呼叫數」；明定 malformed、超載與重試如何計入。
- 提供 bounded 延遲 histogram／摘要及 queue 深度，不逐筆永久保存網域。
- 繼續批次 flush／背景抑制；若需要歷史資料，提供明確 opt-in 與保留期限。
- 保留「節省流量是估算」標示，不將其當成真實效能證據。

驗收：
- 成功、阻擋、timeout、cache hit、coalesced、超載的計數守恆且無重複累計。
- 背景運作不新增高頻 timer／無界歷史儲存；UI 恢復前景可看到最新摘要。

## D07 — 誤擋解除與使用者規則

證據：`DomainAllowlist`／`ExactDomainAllowlist` 已存在，但 service 的 `RuntimeDomainPolicy.assemble` 未傳入使用者名單；目前 UI 無網域規則管理。

實作：
- 新增 Room entity／migration 與設定 UI，支援允許、封鎖、刪除、搜尋。
- 日誌使用結構化 domain／decision／reason，提供一鍵允許與復原，不以解析顯示文字取得網域。
- 精確網域與含子網域為明確選項；採 label 邊界比對，子網域規則不得誤中相似尾字串。
- 定義 allow 優先權、重疊／衝突行為、IDNA／大小寫／尾點正規化與 PSL 邊界。
- 使用 immutable policy snapshot 原子替換並使舊 DNS／decision cache 失效，不需重啟整個 VPN。
- 保留舊資料的 Room migration，別以 destructive migration 取代。

驗收：
- 誤擋可解除且立即作用，重開仍保存；刪除允許後恢復阻擋。
- exact 不自動放行子網域；含子網域不匹配 lookalike-example.com；覆蓋 IDN、衝突與 migration。

## D08 — 加密策略與自訂 DoH

證據：DoH URL 由固定 IP mapping 決定；失敗或退避時自動 UDP fallback，次要 resolver 沒有獨立加密策略。

實作：
- 提供「加密優先、允許明文降級」與「僅加密」；升級既有設定時保留原行為並清楚標示。
- strict 模式下任何失敗／退避／bootstrap 情況不得暗中送 UDP；無可用加密上游則 SERVFAIL。
- 支援自訂 HTTPS DoH endpoint、bootstrap 設定與加密備援，驗證 URL／certificate／hostname。
- 自訂 bootstrap 避免經由自身 VPN DNS 造成迴圈，並定義 strict 模式的 bootstrap 隱私行為。
- UI 呈現實際使用 transport／降級狀態；更新隱私文件。
- 不將標準 UDP 或 DoH 的成功等同本機 DNSSEC 驗證。

驗收：
- 用 fake DoH／UDP server 驗證 strict 模式 UDP 呼叫數為零。
- 覆蓋 invalid certificate、HTTP error、錯誤 DNS body、bootstrap 失敗、主次加密端點與資料 migration。

## D09 — 網路切換與恢復

實作：
- 訂閱合適的 ConnectivityManager network callback，區分 underlying network 與 VPN，避免自行觸發恢復迴圈。
- 將連線／上游健康狀態與 underlying network generation 關聯；切換網路後適當重設退避、處理舊連線及 in-flight。
- 訂明網路切换是否清 DNS cache，避免 split-horizon／舊網路答案污染；保留使用者所選 resolver。
- 對暫時離線及 captive portal 顯示可理解狀態；不自動切換到未授權第三方 resolver。
- 回調去抖並在停止時解除註冊。

驗收：
- Wi-Fi ↔ 行動網路、飛航模式、斷網恢復、captive portal。
- 恢復時間與失敗數有量測；無高頻重啟、重複 callback 或需手動重開才恢復的情況。

## D10 — 上游 TCP fallback／大型回應

證據：目前只走 DoH 或 UDP，UDP response buffer 為 4096，無 TC 分支；回應輸出未建立完整的大小協商策略。

實作：
- 上游 UDP TC=1 時，在剩餘 deadline 中走可用 TCP／DoH，不能把不完整答案當成完整 cache entry。
- 支援 TCP DNS 兩位元組長度 framing、partial read、大小界線、protect 與取消。
- 依用戶端 EDNS advertised size／無 EDNS 情況及 TUN MTU 設計合法回應；需截斷時以 RR 邊界重建並設 TC。
- 考慮接收 buffer 被截斷但原 DNS TC 未置位的情況；不能回傳破損 payload。
- 尊重 D08 strict encryption：TCP/53 本身不是加密，不可作為 strict 的明文 fallback。

驗收：
- 模擬 TC、超過 4096 的答案、TCP partial read／timeout、EDNS 與無 EDNS client。
- 無截斷壞包入 cache；文檔明確揭露 D11 未完成前本機 TCP retry 仍不支援。

## D11 — 本機 TCP DNS（可選，較大工作）

實作：
- 為送到虛擬 DNS 的 TCP/53 增加正確的 TCP 處理與 DNS framing，先評估維護中的實作／函式庫與授權、Android 相容性。
- 不能以在一般 localhost 綁定 ServerSocket 就宣稱處理了 TUN 內 TCP 封包。
- 處理連線容量、重傳／順序、半關閉、idle timeout、多訊息、取消與 resource cleanup。
- 使用同一 policy／cache／resolver pipeline，仍僅路由 DNS 位址。

驗收：
- 真實 DNS client 的 TCP query／UDP TC 後 retry、多訊息、連線中 stop、連線耗盡與異常封包。
- 未通過端到端測試前，README 保留只支援 UDP 的限制。

## D12 — 規則狀態與獨立更新

現況：隨 APK 更新規則是既有刻意設計，不是缺陷；獨立下載屬新增能力。

第一階段：
- UI 顯示來源 revision、來源日期、規則數、APK／private override 來源、驗證狀態與降級原因。
- 明確區分 bundled blocklist、private override、PSL failure 的 fallback；評估壞 override 是否應退回已驗證 bundled，而非僅少量 built-in，變更前補回歸測試。

可選第二階段：
- 明確 opt-in 的更新入口，先做手動，再考慮低頻排程。
- 使用受信任簽章與內建信任根；僅從同一未受信任來源取得 payload 和 SHA-256 不足以建立真實性。
- 驗證格式、大小、規則數、版本相容性；temporary file → 驗證 → atomic replace，保留上一份有效版本可回滾。
- 設計 blocklist／PSL 組合一致性、更新中斷及版本回退策略。
- 更新隱私／來源授權文件；避免每次啟動下載或高頻背景輪詢。

驗收：
- 壞檔、壞簽章、超大檔、網路中斷、低儲存空間、程序於更新中死亡、rollback。
- 任何失敗不覆寫最後有效版本，UI 顯示真實目前生效來源。

## D13 — CI 與回歸入口

證據：基準 tree 沒有 `.github/workflows`；`verify.ps1` 執行 Python／asset checks／JVM tests／APK build，但不執行 instrumentation。

實作：
- PR CI 跑 Python tests、兩種 production assets 驗證、JVM tests、Android lint、debug 與 androidTest APK build。
- 讓 Linux CI 可用，或明確使用 Windows runner；不要直接在 Linux 呼叫目前假設 java.exe／gradlew.bat 的脚本。
- 既有 PR 測試不下載新規則；來源更新走獨立明確 workflow。
- fake upstream 的整合測試可用 emulator job；公開 DNS 與實機耗電 benchmark 保持 opt-in。
- 固定工具鏈／action 版本，快取依賴，保存失敗報告；一般 PR 無需 release signing secrets。
- 為 D01–D12 增加對應回歸測試，不只鏡像 implementation。

驗收：
- 新 workflow 在實際 PR 完成，測試失敗使 job 失敗；上傳報告可讀。
- 區分 build androidTest APK 與真正執行 instrumentation；文件列出本機與 CI 的可重現命令。
- 若 repository 權限不足以設定 required checks，記錄待管理員設定，不宣稱已生效。

## D14 — 端到端效能與耗電

證據：既有規則 benchmark 為微秒級；DoH burst benchmark 主要比較 OkHttp per-host 併發，不涵蓋完整 VPN 路徑。

實作：
- 在同裝置上從 client → TUN → policy／cache → fake upstream → TUN → client 量測。
- 覆蓋 cache hit、blocked、unique miss、coalesced miss、故障 fallback、全部上游故障、burst、網路切換。
- 記錄 p50／p95／p99、timeout／error rate、上游 request 數、queue wait、heap／PSS、GC、CPU。
- 分開整個 App／VPN 冷啟動與 policy assembly；使用足夠樣本、重複 paired run。
- 耗電採同裝置、同網路、同 workload 的 8–10 小時 A/B，另外區分待機與使用中；不由微秒 benchmark 推論省電。
- 改 cache 容量、pool、buffer reuse 或併發數前先用上述數據辨認瓶頸；避免降低協定正確性來換速度。

驗收：
- 保存環境、版本、樣本数、原始摘要與重現步驟；同裝置 baseline 可比較。
- 對修改前後給出實測結果；沒有量測設備時明確留下待測，不能用推估充當改善百分比。
- 一般 CI 不設定跨裝置固定微秒門檻。

## D15 — Always-on／系統恢復（可選）

證據：`onStartCommand` 僅处理自訂 action，回傳 START_NOT_STICKY；目前不能僅依有 VpnService 就認定 Always-on 已支援。

實作：
- 依 Android 官方生命週期處理 system start／null intent／process recreation，持久化期望啟用狀態。
- 區分使用者明確停止、系統回收、授權撤銷；不得在使用者停止／revoke 後自行重新啟用。
- 定義與 DNS-only 路由不一定相容的 lockdown 模式；未驗證前不宣稱支援。
- 必要時調整 manifest 中 Always-on 支援宣告，讓設定 UI 與實際能力一致。

驗收：
- 系統 Always-on 啟動、重新開機、程序重建、使用者停用、切換其他 VPN、revoke。
- 於支援 Android 版本實測前景服務限制；不以 START_STICKY 一行取代完整恢復設計。

## 實作起點

主要程式路徑前綴：`app/src/main/java/io/github/xiangwang2000/dnsshield/`。

- `service/DnsVpnService.kt`：封包、快取、transport、統計及生命週期。
- `service/DnsResponsePacketBuilder.kt`：TUN 回應封包。
- `service/DohFailureBackoff.kt`、`DohBootstrapDns.kt`：加密上游。
- `blocking/DomainPolicy.kt`、`RuntimeDomainPolicy.kt`、`ReloadableDomainPolicy.kt`：規則組裝與 snapshot。
- `data/AppDatabase.kt`、`DnsDao.kt`：設定持久化與 migration。
- `viewmodel/DnsVpnViewModel.kt`、`MainActivity.kt`：狀態與設定 UI。
- `app/src/test/`、`app/src/androidTest/`、`tools/tests/`、`verify.ps1`：既有驗證。

## 規格與既有量測參考

- [RFC 5452 §9.1 — Query matching](https://www.rfc-editor.org/rfc/rfc5452.html#section-9.1)
- [RFC 2308 — Negative caching](https://www.rfc-editor.org/rfc/rfc2308.html)
- [Android VpnService.Builder allowFamily](https://developer.android.com/reference/android/net/VpnService.Builder#allowFamily(int))
- [Production blocklist benchmark](production-blocklist-android-benchmark.md)
- [Runtime domain policy benchmark](runtime-domain-policy-android-benchmark.md)

## 給 Codex 的任務範本

> 讀取 docs/improvement-plan.md，從最新 main 處理 Dxx。先確認現況與尚未完成的驗收條件，完成最小必要實作及有意義的回歸測試，開一個獨立 PR。PR 引用規劃 PR 與任務 ID，列明實際執行的測試、未測平台及剩餘限制；依授權進行後續合併或發布。勿把其他未完成任務標成完成。
