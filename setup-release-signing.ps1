[CmdletBinding()]
param(
    [string]$DistinguishedName = "CN=DNS Shield, OU=Open Source, O=DNS Shield, L=Taipei, ST=Taiwan, C=TW"
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$AndroidStudioJbr = "C:\Program Files\Android\Android Studio\jbr"
$ReleaseDirectory = Join-Path $Root "release"
$KeystorePath = Join-Path $ReleaseDirectory "dns-shield-upload.p12"
$PropertiesPath = Join-Path $Root "keystore.properties"

if (Test-Path -LiteralPath $KeystorePath) {
    throw "Release keystore already exists: $KeystorePath"
}
if (Test-Path -LiteralPath $PropertiesPath) {
    throw "Signing properties already exist: $PropertiesPath"
}

$Keytool = Join-Path $AndroidStudioJbr "bin\keytool.exe"
if (-not (Test-Path -LiteralPath $Keytool)) {
    throw "Android Studio keytool was not found: $Keytool"
}

New-Item -ItemType Directory -Path $ReleaseDirectory -Force | Out-Null

$randomBytes = New-Object byte[] 32
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $random.GetBytes($randomBytes)
} finally {
    $random.Dispose()
}
$password = ([System.BitConverter]::ToString($randomBytes)).Replace("-", "")
$alias = "dns-shield"

& $Keytool -genkeypair -v `
    -keystore $KeystorePath `
    -storetype PKCS12 `
    -storepass $password `
    -alias $alias `
    -keypass $password `
    -keyalg RSA `
    -keysize 4096 `
    -validity 10000 `
    -dname $DistinguishedName
if ($LASTEXITCODE -ne 0) {
    throw "keytool failed with exit code $LASTEXITCODE."
}

$properties = @(
    "storeFile=release/dns-shield-upload.p12"
    "storePassword=$password"
    "keyAlias=$alias"
    "keyPassword=$password"
) -join "`r`n"
[System.IO.File]::WriteAllText(
    $PropertiesPath,
    "$properties`r`n",
    (New-Object System.Text.UTF8Encoding($false))
)

Write-Host "Release signing key created."
Write-Host "Keystore: $KeystorePath"
Write-Host "Properties: $PropertiesPath"
Write-Host "Back up both files securely. Losing this key prevents signed upgrades."
