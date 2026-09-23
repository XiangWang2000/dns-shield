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
$TestPackage = "io.github.xiangwang2000.dnsshield.d14test"
$TestInstrumentationPackage = "$TestPackage.test"
$TestClass = "io.github.xiangwang2000.dnsshield.service.D14TunEndToEndBenchmarkTest"
$Gradle = Join-Path $Root "gradlew.bat"
$Adb = (Get-Command adb -ErrorAction Stop).Source

if ($TestPackage -eq $ProductionPackage) {
    throw "D14 package guard failed: test and production application IDs must differ."
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

function Get-D14Apk {
    $metadataPath = Join-Path $Root "app\build\outputs\apk\d14DeviceTest\output-metadata.json"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "D14 APK metadata is missing. Run -Action Build first."
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.applicationId -ne $TestPackage -or $metadata.variantName -ne "d14DeviceTest") {
        throw "Refusing APK with identity '$($metadata.applicationId)' for variant '$($metadata.variantName)'."
    }
    if ($metadata.elements.Count -ne 1) {
        throw "Expected one universal D14 APK output."
    }
    $apk = Join-Path (Split-Path -Parent $metadataPath) $metadata.elements[0].outputFile
    if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
        throw "D14 APK is missing: $apk"
    }
    return $apk
}

function Get-D14AndroidTestApk {
    $metadataPath = Join-Path $Root "app\build\outputs\apk\androidTest\d14DeviceTest\output-metadata.json"
    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        throw "D14 AndroidTest APK metadata is missing. Run -Action Build first."
    }
    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.applicationId -ne $TestInstrumentationPackage -or $metadata.variantName -ne "d14DeviceTestAndroidTest") {
        throw "Refusing AndroidTest APK with identity '$($metadata.applicationId)' for variant '$($metadata.variantName)'."
    }
    if ($metadata.elements.Count -ne 1) {
        throw "Expected one D14 AndroidTest APK output."
    }
    $apk = Join-Path (Split-Path -Parent $metadataPath) $metadata.elements[0].outputFile
    if (-not (Test-Path -LiteralPath $apk -PathType Leaf)) {
        throw "D14 AndroidTest APK is missing: $apk"
    }
    return $apk
}

function Get-D14Reports {
    param([string]$Device, [string]$Package)
    $output = & $Adb -s $Device shell "run-as $Package sh -c 'ls -1t files/d14-e2e-*.json 2>/dev/null'" 2>$null
    if ($LASTEXITCODE -ne 0) {
        return @()
    }
    return @($output | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

switch ($Action) {
    "Build" {
        Invoke-Gradle @(
            "--no-daemon", "--console=plain",
            "-PandroidTestBuildType=d14DeviceTest",
            ":app:assembleD14DeviceTest",
            ":app:assembleD14DeviceTestAndroidTest"
        )
        $apk = Get-D14Apk
        Write-Host "Built isolated D14 APK: $apk"
    }
    "Install" {
        $device = Resolve-Device
        $productionWasInstalled = [bool](Get-PackagePath $device $ProductionPackage)
        Invoke-Gradle @(
            "--no-daemon", "--console=plain",
            "-PandroidTestBuildType=d14DeviceTest",
            ":app:assembleD14DeviceTest",
            ":app:assembleD14DeviceTestAndroidTest"
        )
        $apk = Get-D14Apk
        $instrumentationApk = Get-D14AndroidTestApk
        Invoke-Adb $device @("install", "-r", $apk)
        Invoke-Adb $device @("install", "-r", $instrumentationApk)
        if (-not (Get-PackagePath $device $TestPackage)) {
            throw "D14 test package was not installed."
        }
        if (-not (Get-PackagePath $device $TestInstrumentationPackage)) {
            throw "D14 instrumentation package was not installed."
        }
        if ($productionWasInstalled -and -not (Get-PackagePath $device $ProductionPackage)) {
            throw "Production package disappeared after D14 install; stop and inspect the device."
        }
        Write-Host "Installed $TestPackage and $TestInstrumentationPackage on $device. Production package: $ProductionPackage"
    }
    "Run" {
        $device = Resolve-Device
        if (-not (Get-PackagePath $device $TestPackage)) {
            throw "Install $TestPackage first with -Action Install."
        }
        if (-not (Get-PackagePath $device $TestInstrumentationPackage)) {
            throw "Install $TestInstrumentationPackage first with -Action Install."
        }
        if ($TestPackage -eq $ProductionPackage) {
            throw "Refusing to run an instrumentation target that matches production."
        }
        $reportDirectory = Join-Path $Root "captures\d14"
        New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
        $before = @(Get-D14Reports $device $TestPackage)
        $previousReports = @($before | ForEach-Object { [IO.Path]::GetFileName($_) })
        Write-Host "The D14 run may show Android VPN consent. Approve the .d14test package; later, switch Wi-Fi off and back on (or between Wi-Fi and cellular) when the test prints its network-handoff prompt. Keep USB connected."
        $component = "$TestInstrumentationPackage/androidx.test.runner.AndroidJUnitRunner"
        $testOutput = & $Adb -s $device shell am instrument -w -e class $TestClass $component 2>&1
        $testExitCode = $LASTEXITCODE
        $testOutput | ForEach-Object { Write-Host $_ }
        $combinedTestOutput = $testOutput -join "`n"
        $instrumentationFailed = ($testExitCode -ne 0) -or
            ($combinedTestOutput -match 'INSTRUMENTATION_CODE:\s*-1|INSTRUMENTATION_FAILED|FAILURES!!!')
        if ($instrumentationFailed) {
            Write-Host "D14 instrumentation failed; keeping both packages installed to retrieve its report."
        }

        $after = @(Get-D14Reports $device $TestPackage)
        $newReport = $after | Where-Object {
            $previousReports -notcontains [IO.Path]::GetFileName($_)
        } | Select-Object -First 1
        if (-not $newReport) {
            if ($testExitCode -ne 0) {
                throw "D14 instrumentation failed with exit code $testExitCode and produced no report."
            }
            throw "D14 instrumentation completed without producing a fresh report."
        }
        $reportFileName = [IO.Path]::GetFileName($newReport)
        $encodedReport = & $Adb -s $device shell "run-as $TestPackage base64 $newReport" 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read the private D14 report from $TestPackage."
        }
        try {
            $reportBytes = [Convert]::FromBase64String(($encodedReport -join "").Trim())
        }
        catch {
            throw "The D14 report could not be decoded from the app's private files."
        }
        $localReport = Join-Path $reportDirectory $reportFileName
        [IO.File]::WriteAllBytes($localReport, $reportBytes)
        if (-not (Test-Path -LiteralPath $localReport -PathType Leaf) -or (Get-Item -LiteralPath $localReport).Length -eq 0) {
            throw "The D14 report was not saved locally: $localReport"
        }
        Write-Host "Saved D14 report: $localReport"
        if ($instrumentationFailed) {
            throw "D14 instrumentation failed; report saved at $localReport."
        }
    }
    "Uninstall" {
        $device = Resolve-Device
        if ($TestPackage -eq $ProductionPackage) {
            throw "Refusing to uninstall: D14 package equals production package."
        }
        $testInstalled = [bool](Get-PackagePath $device $TestPackage)
        $instrumentationInstalled = [bool](Get-PackagePath $device $TestInstrumentationPackage)
        if (-not $testInstalled -and -not $instrumentationInstalled) {
            Write-Host "Neither isolated D14 package is installed on $device."
            break
        }
        if ($instrumentationInstalled) {
            Invoke-Adb $device @("uninstall", $TestInstrumentationPackage)
        }
        if ($testInstalled) {
            Invoke-Adb $device @("uninstall", $TestPackage)
        }
        if ((Get-PackagePath $device $TestPackage) -or (Get-PackagePath $device $TestInstrumentationPackage)) {
            throw "An isolated D14 package remains installed after uninstall."
        }
        Write-Host "Removed only $TestPackage and $TestInstrumentationPackage. Production package $ProductionPackage was not targeted."
    }
}
