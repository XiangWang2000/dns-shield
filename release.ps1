[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
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
    throw "Release signing is not configured. Run setup-release-signing.ps1 or provide all signing environment variables."
}

Set-Location $Root
Write-Host "==> Building signed release APK"
& .\gradlew.bat --no-daemon --console=plain :app:assembleRelease
if ($LASTEXITCODE -ne 0) {
    throw "Release build failed with exit code $LASTEXITCODE."
}

$ApkPath = Join-Path $Root "app\build\outputs\apk\release\app-release.apk"
if (-not (Test-Path -LiteralPath $ApkPath)) {
    throw "Release APK was not produced: $ApkPath"
}

$SdkRoot = @(
    $env:ANDROID_SDK_ROOT,
    $env:ANDROID_HOME,
    (Join-Path $env:LOCALAPPDATA "Android\Sdk")
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $SdkRoot) {
    throw "Android SDK was not found; cannot verify APK signature."
}

$ApkSigner = Get-ChildItem -LiteralPath (Join-Path $SdkRoot "build-tools") -Directory |
    Sort-Object LastWriteTime -Descending |
    ForEach-Object { Join-Path $_.FullName "apksigner.bat" } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $ApkSigner) {
    throw "apksigner.bat was not found under $SdkRoot\build-tools."
}

Write-Host "==> Verifying APK signature"
& $ApkSigner verify --verbose --print-certs $ApkPath
if ($LASTEXITCODE -ne 0) {
    throw "APK signature verification failed with exit code $LASTEXITCODE."
}

$hash = (Get-FileHash -LiteralPath $ApkPath -Algorithm SHA256).Hash.ToLowerInvariant()
$hashPath = "$ApkPath.sha256"
[System.IO.File]::WriteAllText(
    $hashPath,
    "$hash  app-release.apk`r`n",
    (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "Release APK: $ApkPath"
Write-Host "SHA-256: $hash"
Write-Host "Checksum file: $hashPath"
