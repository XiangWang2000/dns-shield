[CmdletBinding()]
param(
    [switch]$ReuseGradleDaemon,
    [ValidateSet("Full", "Core", "Selected")]
    [string]$Scope = "Full",
    [ValidateSet("d03", "d04", "d08", "d14", "d15")]
    [string[]]$Variants = @()
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
if (($Scope -eq "Selected") -ne ($Variants.Count -gt 0)) {
    throw "Selected scope requires -Variants; Full/Core must not specify variants."
}
Write-Host "Verification scope: $Scope; variants: $($Variants -join ',')"
# CI reuses one JVM across the isolated builds; local verification stays one-shot.
$GradleDaemonOption = if ($ReuseGradleDaemon) { "--daemon" } else { "--no-daemon" }
$OnWindows = $env:OS -eq "Windows_NT"
$JavaExecutable = if ($OnWindows) { "bin/java.exe" } else { "bin/java" }
$GradleWrapper = if ($OnWindows) { "./gradlew.bat" } else { "./gradlew" }
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"

if ($OnWindows -and (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME $JavaExecutable))) -and
    (Test-Path -LiteralPath (Join-Path $AndroidStudioJbr $JavaExecutable))) {
    $env:JAVA_HOME = $AndroidStudioJbr
}

if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME $JavaExecutable))) {
    throw "JAVA_HOME is invalid and Android Studio JBR was not found."
}

Set-Location $Root

Write-Host "==> PowerShell script syntax"
foreach ($scriptName in @(
    "prepare-active-blocklist-production.ps1",
    "install-active-blocklist-asset.ps1",
    "benchmark-production-blocklist-android.ps1",
    "prepare-public-suffix-production.ps1",
    "install-public-suffix-asset.ps1",
    "benchmark-runtime-domain-policy-android.ps1",
    "tools/d14-device-test.ps1",
    "tools/d04-device-test.ps1",
    "release.ps1"
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

Write-Host "==> Packaged production Public Suffix asset"
$ProductionPublicSuffixAsset = Join-Path $Root "app/src/main/assets/public_suffix.bin"
if (-not (Test-Path -LiteralPath $ProductionPublicSuffixAsset -PathType Leaf)) {
    throw "Packaged production Public Suffix asset is missing: $ProductionPublicSuffixAsset"
}
& python ./tools/verify_public_suffix_asset.py `
    --manifest ./tools/public_suffix_production.json `
    --asset $ProductionPublicSuffixAsset
if ($LASTEXITCODE -ne 0) {
    throw "Packaged production Public Suffix asset verification failed with exit code $LASTEXITCODE."
}

Write-Host "==> Packaged production active blocklist"
$ProductionActiveBlocklistAsset = Join-Path $Root "app/src/main/assets/active.bin"
if (-not (Test-Path -LiteralPath $ProductionActiveBlocklistAsset -PathType Leaf)) {
    throw "Packaged production active blocklist is missing: $ProductionActiveBlocklistAsset"
}
& python ./tools/verify_active_blocklist_asset.py `
    --manifest ./tools/active_blocklist_production.json `
    --source-manifest ./tools/active_blocklist_source.json `
    --asset $ProductionActiveBlocklistAsset
if ($LASTEXITCODE -ne 0) {
    throw "Packaged production active blocklist verification failed with exit code $LASTEXITCODE."
}

Write-Host "==> Gradle build and tests"
& $GradleWrapper $GradleDaemonOption --console=plain `
    :app:assembleDebug `
    :app:assembleDebugAndroidTest `
    :app:lintDebug `
    :app:testDebugUnitTest `
    :app:compileDebugKotlin
if ($LASTEXITCODE -ne 0) {
    throw "Gradle verification failed with exit code $LASTEXITCODE."
}

if ($Scope -eq "Full" -or $Variants -contains "d14") {
    Write-Host "==> Isolated D14 device-test APKs"
    & $GradleWrapper $GradleDaemonOption --console=plain `
        -PandroidTestBuildType=d14DeviceTest `
        :app:assembleD14DeviceTest `
        :app:assembleD14DeviceTestAndroidTest
    if ($LASTEXITCODE -ne 0) {
        throw "D14 Gradle verification failed with exit code $LASTEXITCODE."
    }
}

if ($Scope -eq "Full" -or $Variants -contains "d04") {
    Write-Host "==> Isolated D04 device-test APKs"
    & $GradleWrapper $GradleDaemonOption --console=plain -PandroidTestBuildType=d04DeviceTest :app:assembleD04DeviceTest :app:assembleD04DeviceTestAndroidTest
    if ($LASTEXITCODE -ne 0) {
        throw "D04 Gradle verification failed with exit code $LASTEXITCODE."
    }
}

if ($Scope -eq "Full" -or $Variants -contains "d03") {
    Write-Host "==> Isolated D03 IPv6 pass-through acceptance APKs"
    & $GradleWrapper $GradleDaemonOption --console=plain -PandroidTestBuildType=d03test :app:assembleD03test :app:assembleD03testAndroidTest
    if ($LASTEXITCODE -ne 0) { throw "D03 APK build failed: $LASTEXITCODE" }
}

if ($Scope -eq "Full" -or $Variants -contains "d08") {
    Write-Host "==> Isolated D08 TLS/strict/resolver acceptance APKs (build only)"
    & $GradleWrapper $GradleDaemonOption --console=plain -PandroidTestBuildType=d08test :app:assembleD08test :app:assembleD08testAndroidTest
    if ($LASTEXITCODE -ne 0) { throw "D08 APK build failed: $LASTEXITCODE" }
}

if ($Scope -eq "Full" -or $Variants -contains "d15") {
    Write-Host "==> Isolated D15 lifecycle acceptance APKs (build only)"
    & $GradleWrapper $GradleDaemonOption --console=plain -PandroidTestBuildType=d15test :app:assembleD15test :app:assembleD15testAndroidTest
    if ($LASTEXITCODE -ne 0) { throw "D15 APK build failed: $LASTEXITCODE" }
}

Write-Host "Verification passed."
