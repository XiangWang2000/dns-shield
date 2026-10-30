"""Exercise the actual PowerShell dispatcher with stub external build commands."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("powershell.exe" if os.name == "nt" else "pwsh")


@unittest.skipUnless(POWERSHELL, "PowerShell executable is not installed")
class VerifyScopeTest(unittest.TestCase):
    def run_verifier(self, options="", fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "verify.ps1", root / "verify.ps1")
            # Syntax-only inputs and assets; python is stubbed to prevent recursion.
            for path in ("tools/prepare-active-blocklist-production.ps1", "tools/install-active-blocklist-asset.ps1",
                         "tools/benchmark-production-blocklist-android.ps1", "tools/benchmark-public-suffix-android.ps1",
                         "tools/benchmark-public-suffix.ps1", "tools/prepare-public-suffix-production.ps1",
                         "tools/install-public-suffix-asset.ps1", "tools/benchmark-runtime-domain-policy-android.ps1",
                         "tools/d14-device-test.ps1", "tools/d04-device-test.ps1", "tools/release.ps1", "tools/setup-release-signing.ps1",
                         "app/src/main/assets/public_suffix.bin", "app/src/main/assets/active.bin",
                         "jdk/bin/java.exe" if os.name == "nt" else "jdk/bin/java"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()
            if os.name == "nt":
                (root / "gradlew.bat").write_bytes(
                    b'@echo off\r\necho %*>> "%~dp0calls.txt"\r\n'
                    b'if "%FAIL_GRADLE%"=="1" exit /b 17\r\nexit /b 0\r\n')
            else:
                wrapper = root / "gradlew"
                wrapper.write_text(
                    '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$(dirname "$0")/calls.txt"\n'
                    'if [ "${FAIL_GRADLE:-0}" = "1" ]; then exit 17; fi\n'
                    'exit 0\n', encoding="utf-8")
                wrapper.chmod(0o755)
            environment = dict(os.environ, JAVA_HOME=str(root / "jdk"),
                               FAIL_GRADLE="1" if fail else "0")
            script = str(root / "verify.ps1").replace("'", "''")
            command = ("function global:python { $global:LASTEXITCODE = 0 }; & '" +
                       script + "' " + options)
            result = subprocess.run([POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
                                     "-Command", command], cwd=root, env=environment,
                                    capture_output=True, text=True, errors="replace", timeout=30)
            calls = (root / "calls.txt").read_text() if (root / "calls.txt").exists() else []
            return result, calls.splitlines() if isinstance(calls, str) else calls

    def test_default_preserves_full_gate(self):
        result, calls = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 6)
        self.assertTrue(all("--no-daemon" in call for call in calls))
        for task in ("lintDebug", "testDebugUnitTest", "assembleDebugAndroidTest"):
            self.assertIn(task, calls[0])

    def test_core_keeps_main_build_tests_and_lint(self):
        result, calls = self.run_verifier("-Scope Core -ReuseGradleDaemon")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertIn("--daemon", calls[0])
        self.assertIn(":app:testDebugUnitTest", calls[0])
        self.assertIn(":app:lintDebug", calls[0])
        self.assertIn(":app:assembleDebugAndroidTest", calls[0])

    def test_selected_runs_core_and_only_selected_builds(self):
        result, calls = self.run_verifier("-Scope Selected -Variants d08,d15")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertIn("-PandroidTestBuildType=d08test", calls[1])
        self.assertIn(":app:assembleD08testAndroidTest", calls[1])
        self.assertIn("-PandroidTestBuildType=d15test", calls[2])
        self.assertIn(":app:assembleD15testAndroidTest", calls[2])

    def test_core_and_isolated_partition_preserve_exact_full_builds(self):
        full, full_calls = self.run_verifier()
        core, core_calls = self.run_verifier("-Scope Core")
        isolated, isolated_calls = self.run_verifier(
            "-Scope Isolated -Variants d03,d04,d08,d14,d15")
        for result in (full, core, isolated):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(isolated_calls), 5)
        self.assertEqual(full_calls, core_calls + isolated_calls)

    def test_failure_stops_before_remaining_builds(self):
        result, calls = self.run_verifier(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_invalid_scope_selection_does_not_run_builds(self):
        for options in ("-Scope Isolated", "-Scope Selected", "-Scope Core -Variants d08", "-Scope Unknown",
                        "-Scope Selected -Variants unknown"):
            with self.subTest(options=options):
                result, calls = self.run_verifier(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()