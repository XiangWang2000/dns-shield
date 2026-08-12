[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"

if (Test-Path -LiteralPath (Join-Path $AndroidStudioJbr "bin\java.exe")) {
    $env:JAVA_HOME = $AndroidStudioJbr
}

if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    throw "JAVA_HOME is invalid and Android Studio JBR was not found."
}

Push-Location $Root
try {
    & .\gradlew.bat --no-daemon --console=plain :app:testDebugUnitTest `
        --tests io.github.xiangwang2000.dnsshield.service.DnsHotPathBenchmarkTest `
        --rerun-tasks
    if ($LASTEXITCODE -ne 0) {
        throw "DNS hot-path benchmark failed with exit code $LASTEXITCODE."
    }

    $Report = Join-Path $Root (
        "app\build\test-results\testDebugUnitTest\" +
        "TEST-io.github.xiangwang2000.dnsshield.service.DnsHotPathBenchmarkTest.xml"
    )
    $Result = [regex]::Match(
        (Get-Content -LiteralPath $Report -Raw -Encoding UTF8),
        "DNS_HOTPATH_BENCHMARK[^\r\n<\]]+"
    )
    if (-not $Result.Success) {
        throw "Benchmark result was not found in $Report."
    }

    Write-Output $Result.Value
} finally {
    Pop-Location
}
