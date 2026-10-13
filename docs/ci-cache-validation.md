# CI 快取與 JVM 重用驗證（2026-10-14）

## 問題與修改

v1.3.0 合併後的完整 CI 花費 20 分 47 秒。原始紀錄顯示 `setup-java` 未找到新的 Gradle 快取鍵；原設定將建置檔雜湊放進精確匹配鍵，並無上一鍵的還原路徑。六次 Gradle 呼叫亦各自建立 single-use daemon。

這次只調整 CI 與驗證腳本的程序選項：

- 使用固定 commit 的 GitHub `actions/cache` 保存 Gradle dependencies、wrapper 及 build cache。每個 commit 保存新輸出，還原時可退回相同 OS、架構與 wrapper 設定的最近快取，由 Gradle 檢查輸入並重建受影響工作。
- CI 傳入 `verify.ps1 -ReuseGradleDaemon`，六次 Gradle 呼叫重用 JVM；無論驗證成功或失敗，JDK 設定成功後都會執行 daemon 清理。本機預設不變。
- 保留 Python、資產、lint、JVM 驗證，以及 Debug、D14、D04、D03、D08、D15 的 App／androidTest 建置。保留文件分流及必要檢查名稱 Windows verification。

沒有更動產品程式、APK 版本、簽章或已發布的 v1.3.0。

## 基準

| 設定 | 快取狀態 | 整個 job 耗時 | 證據 |
| --- | --- | --- | --- |
| 原設定，release merge | Gradle 快取未命中 | 20 分 47 秒 | [run 38428582377 attempt 1](https://github.com/XiangWang2000/dns-shield/actions/runs/38428582377/attempts/1) |
| 原設定，同一 commit 重跑 | 精確命中原有快取 | 5 分 21 秒 | [run 38428582377 attempt 2](https://github.com/XiangWang2000/dns-shield/actions/runs/38428582377/attempts/2) |
| 新設定首輪 | 新快取未命中 | 15 分 16 秒 | [run 38432808326](https://github.com/XiangWang2000/dns-shield/actions/runs/38432808326) |

原設定暖快取六次 Gradle 分別為 1m53s、26s、26s、25s、29s、26s。`testDebugUnitTest FROM-CACHE` 表示重用原測試結果，不代表再次執行測試。

新設定首輪只啟動一個 Gradle daemon；六組 Gradle 建置分別為 9m46s、1m9s、53s、46s、48s、56s，結束時紀錄為 `1 Daemon stopped`。整個 job 的冷快取觀察值減少 5 分 31 秒（約 26.5%）。成功後保存約 941 MB 的新快取；後續不同 commit 的還原效果須另行測量。

## 驗證範圍與限制

- 本機原始入口 `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify.ps1` 通過：37 Python 測試；330 JVM 測試報告零失敗／錯誤／略過，本輪 JVM 工作為 UP-TO-DATE；lint 保留原有 24 warnings、零 errors。六組 APK 建置皆通過。
- 文件檢查與 5 項 CI 分流回歸通過。獨立檢查未發現驗證範圍、失敗傳遞或清理的阻擋問題。
- GitHub hosted runner 每次可能不同；單次差距為觀察值，不是多次受控實驗，也不保證所有未來變更有相同比例。比較整個 job，包括快取還原、壓縮與上傳。
- 所有快取可被淘汰；沒有快取仍須完整建置。每個成功 commit 的快取會增加儲存量，需觀察後續還原／保存耗時和淘汰情況。
- 本輪只驗證 CI 效能，不取代裝置測試，不涉及整機耗電或 #73 延期驗證。

本機原始紀錄保留於 [captures/ci-optimization-20261014](../captures/ci-optimization-20261014)。快取還原語意參見 [GitHub 官方文件](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)。
