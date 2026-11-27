"""Exercise the actual PowerShell dispatcher with stub external build commands."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which("powershell.exe" if os.name == "nt" else "pwsh")


@contextmanager
def temporary_directory_with_cleanup_retry():
    directory = tempfile.TemporaryDirectory()
    try:
        yield directory.name
    finally:
        # Windows can briefly refuse cleanup while a file handle is still open.
        for delay in (0.05, 0.1, 0.2, 0.4, None):
            try:
                directory.cleanup()
            except OSError as error:
                if getattr(error, "winerror", None) != 32 or delay is None:
                    raise
                time.sleep(delay)
            else:
                break


@unittest.skipUnless(POWERSHELL, "PowerShell executable is not installed")
class VerifyScopeTest(unittest.TestCase):
    def run_verifier(self, options="", fail=False):
        with temporary_directory_with_cleanup_retry() as directory:
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

    def test_temp_directory_cleanup_retries_a_windows_sharing_violation(self):
        original_rmtree = shutil.rmtree
        calls = 0

        def fail_once_with_sharing_violation(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                error = PermissionError(13, "sharing violation", os.fspath(path))
                error.winerror = 32
                raise error
            return original_rmtree(path, *args, **kwargs)

        with patch("shutil.rmtree", side_effect=fail_once_with_sharing_violation):
            with temporary_directory_with_cleanup_retry() as directory:
                Path(directory, "held-until-cleanup").touch()

        self.assertEqual(calls, 2)
        self.assertFalse(Path(directory).exists())

    @unittest.skipUnless(os.name == "nt", "Windows file sharing semantics are required")
    def test_temp_directory_cleanup_retries_after_a_file_handle_is_released(self):
        held_file = None

        def release_handle(_delay):
            held_file.close()

        try:
            with patch("time.sleep", side_effect=release_handle) as retry_delay:
                with temporary_directory_with_cleanup_retry() as directory:
                    marker = Path(directory, "held-open")
                    marker.touch()
                    held_file = marker.open("rb")
            retry_delay.assert_called_once_with(0.05)
            self.assertFalse(Path(directory).exists())
        finally:
            if held_file is not None:
                held_file.close()

    def test_temp_directory_cleanup_preserves_errors_and_caps_retries(self):
        for winerror, expected_attempts in ((32, 5), (5, 1)):
            with self.subTest(winerror=winerror):
                directory = None
                error = PermissionError(13, "cleanup failed")
                error.winerror = winerror
                try:
                    with patch("shutil.rmtree", side_effect=error) as remove, patch("time.sleep"):
                        with self.assertRaises(PermissionError) as raised:
                            with temporary_directory_with_cleanup_retry() as directory:
                                Path(directory, "held-until-cleanup").touch()
                    self.assertIs(raised.exception, error)
                    self.assertEqual(remove.call_count, expected_attempts)
                    self.assertTrue(Path(directory).exists())
                finally:
                    if directory is not None:
                        shutil.rmtree(directory)

    def test_temp_directory_cleanup_does_not_suppress_body_errors(self):
        original_rmtree = shutil.rmtree
        calls = 0

        def fail_once_with_sharing_violation(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                error = PermissionError(13, "sharing violation", os.fspath(path))
                error.winerror = 32
                raise error
            return original_rmtree(path, *args, **kwargs)

        with patch("shutil.rmtree", side_effect=fail_once_with_sharing_violation), patch("time.sleep"):
            with self.assertRaisesRegex(RuntimeError, "preserve body error"):
                with temporary_directory_with_cleanup_retry() as directory:
                    raise RuntimeError("preserve body error")

        self.assertEqual(calls, 2)
        self.assertFalse(Path(directory).exists())

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
