[CmdletBinding()]
param(
    [string]$Normalized = "build/public-suffix.normalized.dat",
    [string]$Artifact = "build/public-suffix.bin",
    [string]$ValidationReport = "build/public-suffix.android-validation.json",
    [string]$BenchmarkReport = "build/public-suffix.android-benchmark.json",
    [string]$Serial
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"
$AssetName = "public_suffix.bin"
$GeneratedAssetDirectory = Join-Path $Root "app/build/generated/publicSuffixAndroidTestAssets"
$DeviceReport = "/sdcard/Android/data/io.github.xiangwang2000.dnsshield/files/public-suffix.android-benchmark.json"
$BenchmarkClass = "io.github.xiangwang2000.dnsshield.blocking.ProductionPublicSuffixInstrumentedBenchmarkTest"
$TestRunner = "io.github.xiangwang2000.dnsshield.test/androidx.test.runner.AndroidJUnitRunner"

if ((-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) -and
    (Test-Path -LiteralPath (Join-Path $AndroidStudioJbr "bin\java.exe"))) {
    $env:JAVA_HOME = $AndroidStudioJbr
}
if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    throw "JAVA_HOME is invalid and Android Studio JBR was not found."
}
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found on PATH."
}

function Get-FullPath([string]$Value) {
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $Root $Value))
}

function Invoke-Adb([string[]]$Arguments) {
    & adb -s $script:SelectedSerial @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed with exit code $LASTEXITCODE: $($Arguments -join ' ')"
    }
}

Set-Location $Root
$NormalizedPath = Get-FullPath $Normalized
$ArtifactPath = Get-FullPath $Artifact
$ValidationReportPath = Get-FullPath $ValidationReport
$BenchmarkReportPath = Get-FullPath $BenchmarkReport

if (-not (Test-Path -LiteralPath $NormalizedPath -PathType Leaf)) {
    throw "Normalized Public Suffix source not found: $NormalizedPath"
}
if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf)) {
    throw "Public Suffix artifact not found: $ArtifactPath"
}

if ($Serial) {
    $SelectedSerial = $Serial
} else {
    $ConnectedDevices = @(
        & adb devices |
            Select-Object -Skip 1 |
            Where-Object { $_ -match "^\S+\s+device$" } |
            ForEach-Object { ($_ -split "\s+")[0] }
    )
    if ($ConnectedDevices.Count -ne 1) {
        throw "Expected exactly one adb device; found $($ConnectedDevices.Count). Use -Serial when needed."
    }
    $SelectedSerial = $ConnectedDevices[0]
}
$script:SelectedSerial = $SelectedSerial

Write-Host "==> Verify production Public Suffix outputs"
& python tools/verify_public_suffix_production.py `
    --manifest tools/public_suffix_production.json `
    --source-manifest tools/public_suffix_source.json `
    --normalized $NormalizedPath `
    --artifact $ArtifactPath `
    --report-output $ValidationReportPath
if ($LASTEXITCODE -ne 0) {
    throw "Public Suffix production verification failed with exit code $LASTEXITCODE."
}

Write-Host "==> Prepare generated androidTest asset"
New-Item -ItemType Directory -Force -Path $GeneratedAssetDirectory | Out-Null
Copy-Item -LiteralPath $ArtifactPath -Destination (Join-Path $GeneratedAssetDirectory $AssetName) -Force

if (Test-Path -LiteralPath $BenchmarkReportPath) {
    Remove-Item -LiteralPath $BenchmarkReportPath -Force
}
Invoke-Adb @("shell", "rm", "-f", $DeviceReport)

$Model = (& adb -s $SelectedSerial shell getprop ro.product.model).Trim()
$AndroidRelease = (& adb -s $SelectedSerial shell getprop ro.build.version.release).Trim()
$ApiLevel = (& adb -s $SelectedSerial shell getprop ro.build.version.sdk).Trim()
$Abi = (& adb -s $SelectedSerial shell getprop ro.product.cpu.abi).Trim()
Write-Host "Device: $Model; Android: $AndroidRelease / API $ApiLevel; ABI: $Abi; Serial: $SelectedSerial"

$PreviousAndroidSerial = $env:ANDROID_SERIAL
try {
    $env:ANDROID_SERIAL = $SelectedSerial
    Write-Host "==> Build and install Android benchmark APKs"
    & .\gradlew.bat --no-daemon --no-configuration-cache --rerun-tasks --console=plain `
        :app:installDebug `
        :app:installDebugAndroidTest
    if ($LASTEXITCODE -ne 0) {
        throw "Android benchmark APK installation failed with exit code $LASTEXITCODE."
    }

    Write-Host "==> Run Android Public Suffix benchmark via adb"
    Invoke-Adb @(
        "shell", "am", "instrument", "-w", "-r",
        "-e", "class", $BenchmarkClass,
        $TestRunner
    )
} finally {
    $env:ANDROID_SERIAL = $PreviousAndroidSerial
}

Write-Host "==> Pull Android benchmark report"
$BenchmarkReportDirectory = Split-Path -Parent $BenchmarkReportPath
New-Item -ItemType Directory -Force -Path $BenchmarkReportDirectory | Out-Null
Invoke-Adb @("pull", $DeviceReport, $BenchmarkReportPath)

if (-not (Test-Path -LiteralPath $BenchmarkReportPath -PathType Leaf)) {
    throw "Android Public Suffix benchmark did not produce a report: $BenchmarkReportPath"
}

Write-Host "Validation report: $ValidationReportPath"
Write-Host "Android benchmark report: $BenchmarkReportPath"

