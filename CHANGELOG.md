# Changelog

## 1.2.1 - 2026-08-13

### Changed

- 快取 DNS query key 的 hash，避免同一查詢在快取與 in-flight 去重流程中重複掃描 payload。
- DNS 回應封包改在單次 payload 複製時寫入 client transaction ID，移除 cache hit 與共用上游回應的中間複本。
- 內建網域比對改用無 `split` 的 label 掃描，並避免 service 與 matcher 重複正規化。
- DoH client 的同主機並行上限與 service 的 24-query throttle 對齊，並使用固定 bootstrap 位址避免 DoH hostname 解析遞迴回 VPN。

### Validation

- 新增 JVM 與 Android 實機配對 benchmark、DNS response packet 等價測試、query key 穩定性測試及 DoH bootstrap wiring 測試。
- 256 筆實機 TUN burst 測試驗證直接阻塞 reader 的 64-slot 限制器會使完成時間增加約 11%，因此該原型未納入正式版本。

## 1.1.0 - 2026-07-24

### Changed

- VPN DNS 熱路徑改由可單元測試的 `BuiltInDomainMatcher` 處理阻擋判斷，保留原有的決策快取、DNS 快取、in-flight 去重與上游解析流程。

### Added

- 本機離線 blocklist 編譯器、版本化 64-bit FNV-1a 二進位格式文件、fixture 與 Python 單元測試。

### Notes

- 離線 blocklist 產物尚未載入 App，不會改變目前 APK 的攔截範圍。
