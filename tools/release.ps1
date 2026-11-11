[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BaselineApk
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "release-guards.ps1")
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"
$PropertiesPath = Join-Path $Root "keystore.properties"

if ((-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) -and
    (Test-Path -LiteralPath (Join-Path $AndroidStudioJbr "bin\java.exe"))) {
    $env:JAVA_HOME = $AndroidStudioJbr
}
if (-not $env:JAVA_HOME -or -not (Test-Path -LiteralPath (Join-Path $env:JAVA_HOME "bin\java.exe"))) {
    throw "JAVA_HOME is invalid and Android Studio JBR was not found."
}

$hasEnvironmentSigning = @(
    $env:KEYSTORE_PATH,
    $env:STORE_PASSWORD,
    $env:KEY_ALIAS,
    $env:KEY_PASSWORD
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
if (-not (Test-Path -LiteralPath $PropertiesPath) -and $hasEnvironmentSigning.Count -ne 4) {
    throw "Release signing is not configured. Run tools/setup-release-signing.ps1 or provide all signing environment variables."
}

if (-not [System.IO.Path]::IsPathRooted($BaselineApk)) {
    $BaselineApk = Join-Path $Root $BaselineApk
}
if (-not (Test-Path -LiteralPath $BaselineApk -PathType Leaf)) {
    throw "The trusted previously released APK was not found: $BaselineApk"
}
$BaselineApk = (Resolve-Path -LiteralPath $BaselineApk).Path

$SdkRoot = @(
    $env:ANDROID_SDK_ROOT,
    $env:ANDROID_HOME,
    (Join-Path $env:LOCALAPPDATA "Android\Sdk")
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $SdkRoot) {
    throw "Android SDK was not found; cannot verify APK metadata and signature."
}

$BuildTools = Get-ChildItem -LiteralPath (Join-Path $SdkRoot "build-tools") -Directory |
    Sort-Object LastWriteTime -Descending
$ApkSigner = $BuildTools |
    ForEach-Object { Join-Path $_.FullName "apksigner.bat" } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
$Aapt = $BuildTools |
    ForEach-Object { Join-Path $_.FullName "aapt.exe" } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $ApkSigner) {
    throw "apksigner.bat was not found under $SdkRoot\build-tools."
}
if (-not $Aapt) {
    throw "aapt.exe was not found under $SdkRoot\build-tools."
}

$BaselineMetadata = Get-ApkMetadata -AaptPath $Aapt -ApkPath $BaselineApk
$BaselineSignerDigests = Get-ApkSignerDigests -ApkSignerPath $ApkSigner -ApkPath $BaselineApk
Write-Host "Trusted baseline APK: $BaselineApk"
Write-Host "Baseline application ID: $($BaselineMetadata.ApplicationId)"
Write-Host "Baseline versionCode: $($BaselineMetadata.VersionCode)"

Set-Location $Root
Write-Host "==> Running repository verification"
& .\verify.ps1
if ($LASTEXITCODE -ne 0) {
    throw "Repository verification failed with exit code $LASTEXITCODE."
}

Write-Host "==> Building signed release APK"
& .\gradlew.bat --no-daemon --console=plain :app:assembleRelease
if ($LASTEXITCODE -ne 0) {
    throw "Release build failed with exit code $LASTEXITCODE."
}

$ApkPath = Join-Path $Root "app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path -LiteralPath $ApkPath)) {
    throw "Release APK was not produced: $ApkPath"
}

$hashPath = "$ApkPath.sha256"
if (Test-Path -LiteralPath $hashPath) {
    Remove-Item -LiteralPath $hashPath -Force
}

Write-Host "==> Verifying APK signature"
$CandidateMetadata = Get-ApkMetadata -AaptPath $Aapt -ApkPath $ApkPath
$CandidateSignerDigests = Get-ApkSignerDigests -ApkSignerPath $ApkSigner -ApkPath $ApkPath
Assert-ReleaseCompatibility `
    -BaselineMetadata $BaselineMetadata `
    -CandidateMetadata $CandidateMetadata `
    -BaselineSignerDigests $BaselineSignerDigests `
    -CandidateSignerDigests $CandidateSignerDigests
Write-Host "APK metadata and signer match the trusted baseline, with an increased versionCode."

$hash = (Get-FileHash -LiteralPath $ApkPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(
    $hashPath,
    "$hash  app-release.apk`r`n",
    (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "Release APK: $ApkPath"
Write-Host "SHA-256: $hash"
Write-Host "Checksum file: $hashPath"
