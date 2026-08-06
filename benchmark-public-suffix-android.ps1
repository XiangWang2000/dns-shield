[CmdletBinding()]
param(
  [string]$Artifact = "build/public-suffix.bin",
  [string]$Report = "build/public-suffix.android-benchmark.json"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Package = "io.github.xiangwang2000.dnsshield"
$Runner = "$Package.test/androidx.test.runner.AndroidJUnitRunner"
$Class = "$Package.blocking.PublicSuffixArtifactInstrumentedBenchmarkTest"
$RemoteTmp = "/data/local/tmp/dns-shield-public-suffix.bin"
$PrivateName = "public-suffix.bin"

Set-Location $Root
$ArtifactPath = (Resolve-Path $Artifact).Path
$ReportPath = [System.IO.Path]::GetFullPath((Join-Path $Root $Report))
New-Item -ItemType Directory -Force -Path (Split-Path $ReportPath) | Out-Null

& python tools/verify_public_suffix_production.py `
  --manifest tools/public_suffix_production.json `
  --source-manifest tools/public_suffix_source.json `
  --normalized build/public-suffix.normalized.dat `
  --artifact $ArtifactPath
if ($LASTEXITCODE -ne 0) { throw "Production PSL verification failed." }

& .\gradlew.bat --no-daemon --console=plain :app:installDebug :app:installDebugAndroidTest
if ($LASTEXITCODE -ne 0) { throw "Android test APK installation failed." }

& adb push $ArtifactPath $RemoteTmp
if ($LASTEXITCODE -ne 0) { throw "Unable to push PSL artifact." }
& adb shell run-as $Package cp $RemoteTmp "files/$PrivateName"
if ($LASTEXITCODE -ne 0) { throw "Unable to copy PSL artifact into app storage." }

& adb shell am instrument -w `
  -e class $Class `
  -e pslArtifact $PrivateName `
  $Runner
if ($LASTEXITCODE -ne 0) { throw "Android PSL benchmark failed." }

& adb exec-out run-as $Package cat files/public-suffix.android-benchmark.json |
  Set-Content -Encoding utf8NoBOM $ReportPath
if ($LASTEXITCODE -ne 0) { throw "Unable to retrieve Android benchmark report." }

& adb shell rm -f $RemoteTmp | Out-Null
Write-Host "Android Public Suffix benchmark report: $ReportPath"
