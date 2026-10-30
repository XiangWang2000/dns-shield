# Public Suffix production asset

本頁合併格式、來源準備、APK 安裝與現行 runtime 行為。所有命令都從 repository 根目錄執行。數量、大小與 artifact／normalized SHA-256 以 [production manifest](../tools/public_suffix_production.json) 為準；source identity 以 [source manifest](../tools/public_suffix_source.json) 為準，文件不另複製一份數值表。

## 固定來源與正規化

來源是 publicsuffix/list 的固定 revision e1b8015c3b2f0f4f8c18659c2480fc1a22c07b20，Git blob 為 52b981034da22eb87ee6cc719cba4d5561a7d351。official mirror 可能在內容前加入 // VERSION 與 // COMMIT；preparer 只接受符合 manifest 的 metadata，移除這兩項後，以 Git blob 標準 header `blob <length> NUL` 加上來源 bytes 計算 blob identity。

tools/prepare_public_suffix_source.py 會驗證 pinned source、MPL-2.0 notice，以及完整的 ICANN 和 PRIVATE 區段，再產出正規化 source。Unicode 網域以鎖定的 idna==3.18 處理，設定為 UTS #46、STD3 與 non-transitional；wheel 和 source distribution 都由 tools/requirements-public-suffix.txt 的 hashes 鎖定。原始碼不能直接帶入 binary：format version 1 只接受 ASCII 與 punycode。

tools/verify_public_suffix_production.py、verify_public_suffix_asset.py 和一般 verify.ps1 都以本機檔案驗證，不下載 PSL，也不安裝 IDNA 套件。只有明確的 source preparation 會取得固定 revision；提供本機來源時仍執行相同身份驗證。

## DNSHPS01 格式 version 1

所有整數都是 little-endian。Header 固定 60 bytes，之後依序為 exact、wildcard、exception 三個表格。

| Offset | Size | 欄位 |
| ---: | ---: | --- |
| 0 | 8 | ASCII magic DNSHPS01。 |
| 8 | 4 | format version，必須為 1。 |
| 12 | 4 | flags；bit 0 表示包含 PRIVATE rules。 |
| 16 | 4 | exact rule count。 |
| 20 | 4 | wildcard suffix count。 |
| 24 | 4 | exception rule count。 |
| 28 | 32 | 正規化 source bytes 的 SHA-256。 |
| 60 | variable | exact、wildcard、exception UTF-8 tables。 |

每筆表格項目是 little-endian uint16 UTF-8 byte length，接著是該長度的 UTF-8 rule。每張表必須依 unsigned UTF-8 bytes 嚴格排序。wildcard 的 `*.` 前綴及 exception 的 `!` 前綴不存入表格；例如 `*.ck` 存為 `ck`，`!www.ck` 存為 `www.ck`。

Reader 拒絕缺少 PRIVATE coverage、未知 flags、錯誤 UTF-8、非 ASCII rule、無效網域、重複或未排序項目、截斷資料及尾隨 bytes。所有表格都必須完整且符合 manifest 數量。

## 規則解析

精確規則與 wildcard 規則依適用的最長匹配生效；符合的 exception 優先於 exact 或 wildcard。若沒有規則符合，使用預設 fallback `*`，將最右側 label 視為 public suffix。網域本身若是 public suffix，就沒有 registrable domain。

ICANN 與 PRIVATE 規則都參與解析，因此 private suffix 也會限制可比對的 parent boundary。

## 重建、驗證與安裝

唯一的 fresh rebuild／verify／install 流程如下。Source preparation 預設從 pinned URL 取得固定版本；若要離線重建，將第二行補上 -Source ./path/to/public_suffix_list.dat，並提供符合 pinned Git blob 的來源。後續 verifier 不會下載。

~~~powershell
python -m pip install --require-hashes -r tools/requirements-public-suffix.txt
powershell -NoProfile -ExecutionPolicy Bypass -File tools/prepare-public-suffix-production.ps1
python tools/verify_public_suffix_production.py --manifest tools/public_suffix_production.json --source-manifest tools/public_suffix_source.json --normalized build/public-suffix.normalized.dat --artifact build/public-suffix.bin
powershell -NoProfile -ExecutionPolicy Bypass -File tools/install-public-suffix-asset.ps1
python tools/verify_public_suffix_asset.py --manifest tools/public_suffix_production.json --asset app/src/main/assets/public_suffix.bin
~~~

Production verifier 比對 pinned source identity、normalized bytes、artifact SHA-256／size／counts，並從 normalized source 確定性重建 artifact，要求逐 byte 相同。Installer 會先驗證 production outputs，再將候選 binary stage 在目的檔旁，獨立套用 APK asset gate；只有通過才移至 app/src/main/assets/public_suffix.bin。任何失敗都不覆寫目的檔；既有資產若不符合 contract，installer 拒絕替換。

Build outputs 通過驗證不代表 APK asset 已安裝。Installer 成功後可由末行 verifier 或完整 verify.ps1 確認 main asset；這也不代表 Android 實機 benchmark 已執行。

## Runtime 使用與 fallback

目前 app/src/main/assets/public_suffix.bin 已隨 APK 封裝。DnsVpnService 將 PublicSuffixResolverOwner.resolverOrNull 傳入 RuntimeDomainPolicy.assemble；只有 compiled blocklist 成功驗證後，DomainPolicyAssembler 才取得 resolver，並將 ParentDomainMatcher 套在該 compiled matcher 上。

Resolver owner 每個 service lifecycle 只嘗試載入一次，並將狀態記為 Loaded 或 Rejected。成功載入的 resolver 會重用；若載入失敗、resolver 不可用或 provider 拋出 recoverable exception，已驗證的 compiled blocklist 仍以 exact matching 運作。ParentDomainMatcher 依 PSL 計算 registrable boundary，不會跨越 public suffix。

這是目前 runtime policy 的接線與 fallback 行為。裝入 APK、啟動 resolver 或本頁的 offline verification 各自只證明對應步驟；device characterization 方法見 [benchmarks.md](benchmarks.md)。
