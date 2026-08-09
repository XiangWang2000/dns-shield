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

Write-Host "==> PowerShell packaging script syntax"
foreach ($scriptName in @(
    "prepare-public-suffix-production.ps1",
    "install-public-suffix-asset.ps1"
)) {
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $Root $scriptName),
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    if ($parseErrors.Count -ne 0) {
        $messages = ($parseErrors | ForEach-Object { $_.Message }) -join "; "
        throw "PowerShell syntax verification failed for $scriptName`: $messages"
    }
}

Write-Host "==> Python blocklist compiler tests"
& python -m unittest discover tools/tests
if ($LASTEXITCODE -ne 0) {
    throw "Python verification failed with exit code $LASTEXITCODE."
}

Write-Host "==> Gradle build and tests"
& .\gradlew.bat --no-daemon --console=plain `
    :app:assembleDebug `
    :app:assembleDebugAndroidTest `
    :app:testDebugUnitTest `
    :app:compileDebugKotlin
if ($LASTEXITCODE -ne 0) {
    throw "Gradle verification failed with exit code $LASTEXITCODE."
}

Write-Host "Verification passed."
