"""Exercise verify.ps1 with fake executables: variant routing and failure propagation."""
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY_TEXT = (ROOT / "verify.ps1").read_text(encoding="utf-8")


@unittest.skipUnless(os.name == "nt", "verify.ps1 requires Windows")
class VerifyApkGatesTest(unittest.TestCase):
    def run_gate(self, failure=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "verify.ps1").write_text(VERIFY_TEXT, encoding="utf-8")
            for name in re.findall(r'"([^"]+\.ps1)"', VERIFY_TEXT):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("", encoding="utf-8")
            assets = root / "app/src/main/assets"
            assets.mkdir(parents=True)
            for name in ("active.bin", "public_suffix.bin"):
                (assets / name).write_bytes(b"fixture")
            (root / "gradlew.bat").write_text(
                '@echo off\n'
                'echo %*>>"%~dp0calls.txt"\n'
                'if defined DNS_SHIELD_GATE_FAILURE (\n'
                '  echo %* | findstr /L /C:"%DNS_SHIELD_GATE_FAILURE%" >nul\n'
                '  if not errorlevel 1 exit /b 7\n'
                ')\nexit /b 0\n', encoding="ascii")
            environment = os.environ.copy()
            if failure:
                environment["DNS_SHIELD_GATE_FAILURE"] = failure
            else:
                environment.pop("DNS_SHIELD_GATE_FAILURE", None)
            bundled_jbr = Path(r"C:\Program Files\Android\Android Studio\jbr")
            if bundled_jbr.exists():
                environment["JAVA_HOME"] = str(bundled_jbr)
            quoted = str(root / "verify.ps1").replace("'", "''")
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "function global:python { $global:LASTEXITCODE = 0 }; "
                 f"& '{quoted}'"],
                capture_output=True, text=True, env=environment, timeout=30)
            calls = (root / "calls.txt").read_text() if (root / "calls.txt").exists() else ""
            return result, calls

    def test_all_required_variants_use_separate_correct_invocations(self):
        result, calls = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = calls.splitlines()
        self.assertEqual(len(lines), 6, calls)
        for variant in ("D03test", "D04DeviceTest", "D14DeviceTest", "D08test", "D15test"):
            matching = [line for line in lines if f":app:assemble{variant}AndroidTest" in line]
            self.assertEqual(len(matching), 1, calls)
            self.assertIn(f"-PandroidTestBuildType={variant[0].lower() + variant[1:]}", matching[0])
            self.assertIn(f":app:assemble{variant} ", matching[0])

    def test_d08_build_failure_fails_gate_and_stops_before_d15(self):
        result, calls = self.run_gate("assembleD08test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("D08 APK build failed: 7", result.stderr)
        self.assertNotIn("assembleD15test", calls)

    def test_d15_build_failure_fails_gate(self):
        result, _ = self.run_gate("assembleD15test")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("D15 APK build failed: 7", result.stderr)


if __name__ == "__main__":
    unittest.main()
