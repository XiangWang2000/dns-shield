"""Exercise the actual PowerShell dispatcher with stub external build commands."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.name == "nt", "PowerShell verification entrypoint is Windows-only")
class VerifyScopeTest(unittest.TestCase):
    def run_verifier(self, options="", fail=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "verify.ps1", root / "verify.ps1")
            # Syntax-only inputs and assets; python is stubbed to prevent recursion.
            for path in ("prepare-active-blocklist-production.ps1", "install-active-blocklist-asset.ps1",
                         "benchmark-production-blocklist-android.ps1", "prepare-public-suffix-production.ps1",
                         "install-public-suffix-asset.ps1", "benchmark-runtime-domain-policy-android.ps1",
                         "tools/d14-device-test.ps1", "tools/d04-device-test.ps1", "release.ps1",
                         "app/src/main/assets/public_suffix.bin", "app/src/main/assets/active.bin",
                         "jdk/bin/java.exe"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.touch()
            (root / "gradlew.bat").write_bytes(
                b'@echo off\r\necho %*>> "%~dp0calls.txt"\r\n'
                b'if "%FAIL_GRADLE%"=="1" exit /b 17\r\nexit /b 0\r\n')
            environment = dict(os.environ, JAVA_HOME=str(root / "jdk"),
                               FAIL_GRADLE="1" if fail else "0")
            command = ('function global:python { $global:LASTEXITCODE = 0 }; '
                       '& ./verify.ps1 ' + options)
            result = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                                     "-Command", command], cwd=root, env=environment,
                                    capture_output=True, timeout=30)
            calls = (root / "calls.txt").read_text().splitlines() if (root / "calls.txt").exists() else []
            return result, calls

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

    def test_failure_stops_before_remaining_builds(self):
        result, calls = self.run_verifier(fail=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)

    def test_invalid_scope_selection_does_not_run_builds(self):
        for options in ("-Scope Selected", "-Scope Core -Variants d08", "-Scope Unknown",
                        "-Scope Selected -Variants unknown"):
            with self.subTest(options=options):
                result, calls = self.run_verifier(options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
