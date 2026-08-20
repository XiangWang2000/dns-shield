[CmdletBinding()]
param(
    [string]$Normalized = "build/public-suffix.normalized.dat",
    [string]$Artifact = "build/public-suffix.bin",
    [string]$ValidationReport = "build/public-suffix.validation.json",
    [string]$BenchmarkReport = "build/public-suffix.benchmark.json"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"

if ((-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) -and
    (Test-Path -LiteralPath (Join-Path $AndroidStudioJbr "bin\java.exe"))) {
    $env:JAVA_HOME = $AndroidStudioJbr
}

if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    throw "JAVA_HOME is invalid and Android Studio JBR was not found."
}

function Get-FullPath([string]$Value) {
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $Root $Value))
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

$BenchmarkStartedUtc = [DateTime]::UtcNow
$PreviousArtifact = $env:DNS_SHIELD_PSL_BENCHMARK_ARTIFACT
$PreviousReport = $env:DNS_SHIELD_PSL_BENCHMARK_REPORT
try {
    $env:DNS_SHIELD_PSL_BENCHMARK_ARTIFACT = $ArtifactPath
    $env:DNS_SHIELD_PSL_BENCHMARK_REPORT = $BenchmarkReportPath

    Write-Host "==> Run opt-in JVM Public Suffix benchmark"
    # The benchmark inputs are environment variables, which Gradle does not track as task inputs.
    # Force the test task to run so a cached result cannot suppress report generation.
    & .\gradlew.bat --no-daemon --rerun-tasks --console=plain `
        :app:testDebugUnitTest `
        --tests "io.github.xiangwang2000.dnsshield.blocking.ProductionPublicSuffixBenchmarkTest"
    if ($LASTEXITCODE -ne 0) {
        throw "Public Suffix JVM benchmark failed with exit code $LASTEXITCODE."
    }
} finally {
    $env:DNS_SHIELD_PSL_BENCHMARK_ARTIFACT = $PreviousArtifact
    $env:DNS_SHIELD_PSL_BENCHMARK_REPORT = $PreviousReport
}

if (-not (Test-Path -LiteralPath $BenchmarkReportPath -PathType Leaf)) {
    throw "Public Suffix benchmark did not produce a report: $BenchmarkReportPath"
}
$BenchmarkReportInfo = Get-Item -LiteralPath $BenchmarkReportPath
if ($BenchmarkReportInfo.LastWriteTimeUtc -lt $BenchmarkStartedUtc) {
    throw "Public Suffix benchmark did not update its report: $BenchmarkReportPath"
}

Write-Host "Validation report: $ValidationReportPath"
Write-Host "Benchmark report: $BenchmarkReportPath"
