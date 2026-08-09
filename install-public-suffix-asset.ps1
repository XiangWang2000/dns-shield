param(
    [string]$Python = "python",
    [string]$Source = "",
    [string]$Normalized = "build/public-suffix.normalized.dat",
    [string]$Artifact = "build/public-suffix.bin",
    [string]$Destination = "app/src/main/assets/public_suffix.bin"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Resolve-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

$manifest = Join-Path $repoRoot "tools/public_suffix_production.json"
$sourceManifest = Join-Path $repoRoot "tools/public_suffix_source.json"
$fullVerifier = Join-Path $repoRoot "tools/verify_public_suffix_production.py"
$assetVerifier = Join-Path $repoRoot "tools/verify_public_suffix_asset.py"
$prepareProduction = Join-Path $repoRoot "prepare-public-suffix-production.ps1"
$normalizedPath = Resolve-RepoPath $Normalized
$artifactPath = Resolve-RepoPath $Artifact
$destinationPath = Resolve-RepoPath $Destination

foreach ($requiredPath in @(
    $manifest,
    $sourceManifest,
    $fullVerifier,
    $assetVerifier,
    $prepareProduction
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required Public Suffix tooling file not found: $requiredPath"
    }
}

if (
    -not (Test-Path -LiteralPath $normalizedPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $artifactPath -PathType Leaf)
) {
    Write-Host "Production Public Suffix build outputs are missing; rebuilding the pinned artifact..."
    $prepareArguments = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $prepareProduction,
        "-Python", $Python,
        "-Normalized", $Normalized,
        "-Artifact", $Artifact
    )
    if (-not [string]::IsNullOrWhiteSpace($Source)) {
        $prepareArguments += @("-Source", $Source)
    }
    & powershell @prepareArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Pinned Public Suffix rebuild failed with exit code $LASTEXITCODE"
    }
}

foreach ($requiredOutput in @($normalizedPath, $artifactPath)) {
    if (-not (Test-Path -LiteralPath $requiredOutput -PathType Leaf)) {
        throw "Required Public Suffix build output not found after rebuild: $requiredOutput"
    }
}

Write-Host "Verifying deterministic production Public Suffix outputs..."
& $Python $fullVerifier `
    --manifest $manifest `
    --source-manifest $sourceManifest `
    --normalized $normalizedPath `
    --artifact $artifactPath
if ($LASTEXITCODE -ne 0) {
    throw "Production Public Suffix verification failed with exit code $LASTEXITCODE"
}

if (Test-Path -LiteralPath $destinationPath) {
    Write-Host "Destination already exists; verifying it before doing anything..."
    & $Python $assetVerifier --manifest $manifest --asset $destinationPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Verified Public Suffix asset is already installed: $destinationPath"
        exit 0
    }
    throw "Destination contains an unverified Public Suffix asset; refusing to overwrite it: $destinationPath"
}

$destinationDirectory = Split-Path -Parent $destinationPath
New-Item -ItemType Directory -Force -Path $destinationDirectory | Out-Null
$temporaryPath = "$destinationPath.tmp.$PID"

try {
    Copy-Item -LiteralPath $artifactPath -Destination $temporaryPath -Force

    Write-Host "Verifying staged APK asset..."
    & $Python $assetVerifier --manifest $manifest --asset $temporaryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Staged Public Suffix asset verification failed with exit code $LASTEXITCODE"
    }

    Move-Item -LiteralPath $temporaryPath -Destination $destinationPath
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

Write-Host "Installed verified Public Suffix asset: $destinationPath"
