# Changelog

## 1.1.0 - 2026-07-24

### Changed

- VPN DNS 熱路徑改由可單元測試的 `BuiltInDomainMatcher` 處理阻擋判斷，保留原有的決策快取、DNS 快取、in-flight 去重與上游解析流程。

### Added

- 本機離線 blocklist 編譯器、版本化 64-bit FNV-1a 二進位格式文件、fixture 與 Python 單元測試。

### Notes

- 離線 blocklist 產物尚未載入 App，不會改變目前 APK 的攔截範圍。
