[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Build", "Install", "Run", "Uninstall")]
    [string]$Action,
    [string]$Serial
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ProductionPackage = "io.github.xiangwang2000.dnsshield"
$TestPackage = "$ProductionPackage.d04test"
$TestInstrumentationPackage = "$TestPackage.test"
$TestClass = "io.github.xiangwang2000.dnsshield.service.VpnLifecycleDeviceTest"
$Gradle = Join-Path $Root "gradlew.bat"
$Adb = (Get-Command adb -ErrorAction Stop).Source

if ($TestPackage -eq $ProductionPackage -or $TestInstrumentationPackage -eq $ProductionPackage) {
    throw "D04 package guard failed: test and production application IDs must differ."
}

function Invoke-Gradle {
    param([string[]]$Arguments)
    Push-Location $Root
    try {
        & $Gradle @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Gradle failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

function Resolve-Device {
    $lines = & $Adb devices
    if ($LASTEXITCODE -ne 0) {
        throw "adb devices failed."
    }
    $connected = @()
    foreach ($line in ($lines | Select-Object -Skip 1)) {
        if ($line -match '^\s*(\S+)\s+device(\s|$)') {
            $connected += $Matches[1]
        }
    }
    if ($Serial) {
        if ($connected -notcontains $Serial) {
            throw "Requested device '$Serial' is not in adb state 'device'."
        }
        return $Serial
    }
    if ($connected.Count -ne 1) {
        throw "Connect exactly one adb device or pass -Serial. Found $($connected.Count)."
    }
    return $connected[0]
}

function Invoke-Adb {
    param([string]$Device, [string[]]$Arguments)
    & $Adb -s $Device @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "adb $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Get-PackagePath {
    param([string]$Device, [string]$Package)
    $output = & $Adb -s $Device shell pm path $Package 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ($output | Select-Object -First 1)
}

function Get-D04Apk {
    $metadataPath = Join-Path $Root "app\build\outputs\apk\d04DeviceTest\output-metadata.json"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "D04 APK metadata is missing. Run -Action Build first."
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.applicationId -ne $TestPackage -or $metadata.variantName -ne "d04DeviceTest") {
        throw "Refusing APK with identity '$($metadata.applicationId)' for variant '$($metadata.variantName)'."
    }
    if ($metadata.elements.Count -ne 1) {
        throw "Expected one D04 APK output."
    }
    $apk = Join-Path (Split-Path -Parent $metadataPath) $metadata.elements[0].outputFile
    if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
        throw "D04 APK is missing: $apk"
    }
    return $apk
}

function Get-D04AndroidTestApk {
    $metadataPath = Join-Path $Root "app\build\outputs\apk\androidTest\d04DeviceTest\output-metadata.json"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "D04 AndroidTest APK metadata is missing. Run -Action Build first."
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.applicationId -ne $TestInstrumentationPackage -or $metadata.variantName -ne "d04DeviceTestAndroidTest") {
        throw "Refusing AndroidTest APK with identity '$($metadata.applicationId)' for variant '$($metadata.variantName)'."
    }
    if ($metadata.elements.Count -ne 1) {
        throw "Expected one D04 AndroidTest APK output."
    }
    $apk = Join-Path (Split-Path -Parent $metadataPath) $metadata.elements[0].outputFile
    if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
        throw "D04 AndroidTest APK is missing: $apk"
    }
    return $apk
}

switch ($Action) {
    "Build" {
        Invoke-Gradle @(
            "--no-daemon", "--console=plain",
            "-PandroidTestBuildType=d04DeviceTest",
            ":app:assembleD04DeviceTest",
            ":app:assembleD04DeviceTestAndroidTest"
        )
        Write-Host "Built isolated D04 app and AndroidTest APKs."
    }
    "Install" {
        $device = Resolve-Device
        $productionWasInstalled = [bool](Get-PackagePath $device $ProductionPackage)
        Invoke-Gradle @(
            "--no-daemon", "--console=plain",
            "-PandroidTestBuildType=d04DeviceTest",
            ":app:assembleD04DeviceTest",
            ":app:assembleD04DeviceTestAndroidTest"
        )
        foreach ($package in @($TestInstrumentationPackage, $TestPackage)) {
            if (Get-PackagePath $device $package) {
                Invoke-Adb $device @("uninstall", $package)
            }
        }
        Invoke-Adb $device @("install", "-r", (Get-D04Apk))
        Invoke-Adb $device @("install", "-r", (Get-D04AndroidTestApk))
        if (-not (Get-PackagePath $device $TestPackage)) {
            throw "D04 isolated test package was not installed."
        }
        if (-not (Get-PackagePath $device $TestInstrumentationPackage)) {
            throw "D04 instrumentation package was not installed."
        }
        if ($productionWasInstalled -and -not (Get-PackagePath $device $ProductionPackage)) {
            throw "Production package disappeared after isolated install; stop and inspect the device."
        }
        Write-Host "Installed $TestPackage and $TestInstrumentationPackage on $device. Production package: $ProductionPackage"
    }
    "Run" {
        $device = Resolve-Device
        if (-not (Get-PackagePath $device $TestPackage) -or -not (Get-PackagePath $device $TestInstrumentationPackage)) {
            throw "Install D04 packages first with -Action Install."
        }
        if ($TestPackage -eq $ProductionPackage) {
            throw "Refusing to run an instrumentation target that matches production."
        }
        Write-Host "The ordered test first verifies an unapproved .d04test VPN start, then may show Android VPN consent."
        Write-Host "Approve the .d04test request. In the final test, start VPN in a different package to revoke .d04test."
        Write-Host "The installed production DNS Shield app can be used as that second package; stop its VPN after the suite."
        $component = "$TestInstrumentationPackage/androidx.test.runner.AndroidJUnitRunner"
        $output = & $Adb -s $device shell am instrument -w -r -e class $TestClass $component 2>&1
        $testExitCode = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        $combined = [string]::Join([Environment]::NewLine, $output)
        if ($testExitCode -ne 0 -or $combined -match "FAILURES!!!|INSTRUMENTATION_FAILED") {
            throw "D04 instrumentation failed with exit code $testExitCode."
        }
    }
    "Uninstall" {
        $device = Resolve-Device
        if ($TestInstrumentationPackage -eq $ProductionPackage -or $TestPackage -eq $ProductionPackage) {
            throw "Refusing to uninstall the production package."
        }
        $productionWasInstalled = [bool](Get-PackagePath $device $ProductionPackage)
        foreach ($package in @($TestInstrumentationPackage, $TestPackage)) {
            if (Get-PackagePath $device $package) {
                Invoke-Adb $device @("uninstall", $package)
            }
        }
        if ($productionWasInstalled -and -not (Get-PackagePath $device $ProductionPackage)) {
            throw "Production package disappeared during D04 cleanup."
        }
        Write-Host "Removed isolated D04 packages; production package remains: $ProductionPackage"
    }
}
