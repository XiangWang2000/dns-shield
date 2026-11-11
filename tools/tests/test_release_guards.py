"""Exercise compatibility checks used before publishing a Release APK."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUARD_SCRIPT = ROOT / "tools" / "release-guards.ps1"
POWERSHELL = shutil.which("powershell.exe" if os.name == "nt" else "pwsh")


@unittest.skipUnless(POWERSHELL, "PowerShell executable is not installed")
class ReleaseGuardsTest(unittest.TestCase):
    def test_signer_digest_parser_accepts_legacy_and_scheme_specific_output(self):
        script_path = str(GUARD_SCRIPT).replace("'", "''")
        legacy_digest = "c" * 64
        v2_digest = "d" * 64
        command = (
            f". '{script_path}'; "
            f"$output = \"Signer #1 certificate SHA-256 digest: {legacy_digest}`n"
            f"V2 Signer: certificate SHA-256 digest: {v2_digest}`n"
            f"Source Stamp Signer: certificate SHA-256 digest: {'b' * 64}\"; "
            "$digests = Get-CertificateSha256Digests -VerificationOutput $output; "
            f"if (($digests -join ',') -ne '{legacy_digest},{v2_digest}') {{ throw 'Digest parsing failed.' }}"
        )
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=ROOT, capture_output=True, text=True, errors="replace", timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    @unittest.skipUnless(os.name == "nt", "Native .cmd mock requires Windows")
    def test_apksigner_stderr_warning_is_captured_and_exit_code_is_checked(self):
        script_path = str(GUARD_SCRIPT).replace("'", "''")
        digest = "e" * 64
        with tempfile.TemporaryDirectory() as temp_dir:
            mock_apksigner = Path(temp_dir) / "mock-apksigner.cmd"
            mock_apksigner.write_bytes(
                (
                    "@echo off\r\n"
                    "echo WARNING: apksigner requires native access 1>&2\r\n"
                    f"echo Signer #1 certificate SHA-256 digest: {digest}\r\n"
                    "exit /b %MOCK_APKSIGNER_EXIT_CODE%\r\n"
                ).encode("ascii")
            )
            signer_path = str(mock_apksigner).replace("'", "''")
            command = (
                "$ErrorActionPreference = 'Stop'; "
                f". '{script_path}'; "
                "$env:MOCK_APKSIGNER_EXIT_CODE = '0'; "
                f"$digests = Get-ApkSignerDigests -ApkSignerPath '{signer_path}' -ApkPath 'candidate.apk'; "
                f"if (($digests -join ',') -ne '{digest}') {{ throw 'Successful signer output was not parsed.' }}; "
                "if ($ErrorActionPreference -ne 'Stop') { throw 'Preference was not restored after success.' }; "
                "$env:MOCK_APKSIGNER_EXIT_CODE = '23'; "
                "$failed = $false; "
                f"try {{ $null = Get-ApkSignerDigests -ApkSignerPath '{signer_path}' -ApkPath 'candidate.apk' }} "
                "catch { $failed = $_.Exception.Message -like 'APK signature verification failed*' }; "
                "if (-not $failed) { throw 'Nonzero apksigner exit code was not rejected.' }; "
                "if ($ErrorActionPreference -ne 'Stop') { throw 'Preference was not restored after failure.' }"
            )
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                cwd=ROOT, capture_output=True, text=True, errors="replace", timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_guard(self, candidate_application_id="io.github.xiangwang2000.dnsshield",
                  candidate_version_code=8, candidate_signers=("a" * 64,)):
        script_path = str(GUARD_SCRIPT).replace("'", "''")
        command = (
            f". '{script_path}'; "
            "$baseline = [pscustomobject]@{ApplicationId='io.github.xiangwang2000.dnsshield'; VersionCode=7}; "
            f"$candidate = [pscustomobject]@{{ApplicationId='{candidate_application_id}'; VersionCode={candidate_version_code}}}; "
            "$baselineSigners = @('" + "a" * 64 + "'); "
            "$candidateSigners = @('" + "','".join(candidate_signers) + "'); "
            "Assert-ReleaseCompatibility -BaselineMetadata $baseline -CandidateMetadata $candidate "
            "-BaselineSignerDigests $baselineSigners -CandidateSignerDigests $candidateSigners"
        )
        return subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            cwd=ROOT, capture_output=True, text=True, errors="replace", timeout=20)

    def test_matching_identity_and_higher_version_pass(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_equal_or_lower_version_is_rejected(self):
        for version_code in (7, 6):
            with self.subTest(version_code=version_code):
                result = self.run_guard(candidate_version_code=version_code)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be greater", result.stderr)

    def test_different_application_id_is_rejected(self):
        result = self.run_guard(candidate_application_id="io.github.example.other")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match baseline", result.stderr)

    def test_application_id_case_difference_is_rejected(self):
        result = self.run_guard(candidate_application_id="io.github.xiangwang2000.DnsShield")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match baseline", result.stderr)

    def test_different_signer_is_rejected(self):
        result = self.run_guard(candidate_signers=("b" * 64,))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signer certificate does not match", result.stderr)


if __name__ == "__main__":
    unittest.main()
