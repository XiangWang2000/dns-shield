[CmdletBinding()]
param()

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

Set-Location $Root
Write-Host "==> Gradle build and tests"
& .\gradlew.bat --no-daemon --console=plain :app:assembleDebug :app:testDebugUnitTest :app:compileDebugKotlin
if ($LASTEXITCODE -ne 0) {
    throw "Gradle verification failed with exit code $LASTEXITCODE."
}

Write-Host "Verification passed."
