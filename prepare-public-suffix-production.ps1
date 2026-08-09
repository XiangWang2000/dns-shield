param(
    [string]$Python = "python",
    [string]$Source = "",
    [string]$Normalized = "build/public-suffix.normalized.dat",
    [string]$Artifact = "build/public-suffix.bin",
    [string]$Metadata = "build/public-suffix.source-preparation.json"
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

function Invoke-PythonStep([string]$Description, [string[]]$Arguments) {
    Write-Host $Description
    & $Python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

$sourceManifestPath = Join-Path $repoRoot "tools/public_suffix_source.json"
$productionManifestPath = Join-Path $repoRoot "tools/public_suffix_production.json"
$prepareScript = Join-Path $repoRoot "tools/prepare_public_suffix_source.py"
$buildScript = Join-Path $repoRoot "tools/build_public_suffix.py"
$verifyScript = Join-Path $repoRoot "tools/verify_public_suffix_production.py"
$downloadScript = Join-Path $repoRoot "tools/download_public_suffix_source.py"

foreach ($requiredPath in @(
    $sourceManifestPath,
    $productionManifestPath,
    $prepareScript,
    $buildScript,
    $verifyScript,
    $downloadScript
)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required Public Suffix file not found: $requiredPath"
    }
}

$sourceManifest = Get-Content -LiteralPath $sourceManifestPath -Raw | ConvertFrom-Json
if ($sourceManifest.source_name -ne "publicsuffix/list") {
    throw "Unsupported Public Suffix source_name: $($sourceManifest.source_name)"
}
if ($sourceManifest.source_revision -notmatch '^[0-9a-f]{40}$') {
    throw "Invalid pinned Public Suffix source revision: $($sourceManifest.source_revision)"
}

$normalizedPath = Resolve-RepoPath $Normalized
$artifactPath = Resolve-RepoPath $Artifact
$metadataPath = Resolve-RepoPath $Metadata
$stageDirectory = Join-Path $repoRoot "build/public-suffix.prepare.$PID"

New-Item -ItemType Directory -Force -Path $stageDirectory | Out-Null

try {
    if ([string]::IsNullOrWhiteSpace($Source)) {
        $sourcePath = Join-Path $stageDirectory "public_suffix_list.dat"
        Invoke-PythonStep "Downloading pinned Public Suffix source revision $($sourceManifest.source_revision)..." @(
            $downloadScript,
            "--manifest", $sourceManifestPath,
            "--output", $sourcePath
        )
    } else {
        $sourcePath = Resolve-RepoPath $Source
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Pinned Public Suffix source file not found: $sourcePath"
        }
        Write-Host "Using local Public Suffix source candidate: $sourcePath"
    }

    $stageNormalized = Join-Path $stageDirectory "public-suffix.normalized.dat"
    $stageArtifact = Join-Path $stageDirectory "public-suffix.bin"
    $stageMetadata = Join-Path $stageDirectory "public-suffix.source-preparation.json"

    Invoke-PythonStep "Preparing and verifying pinned Public Suffix source..." @(
        $prepareScript,
        "--manifest", $sourceManifestPath,
        "--input", $sourcePath,
        "--output", $stageNormalized,
        "--metadata-output", $stageMetadata
    )

    Invoke-PythonStep "Building deterministic Public Suffix artifact..." @(
        $buildScript,
        "--input", $stageNormalized,
        "--output", $stageArtifact
    )

    Invoke-PythonStep "Verifying deterministic production Public Suffix outputs..." @(
        $verifyScript,
        "--manifest", $productionManifestPath,
        "--source-manifest", $sourceManifestPath,
        "--normalized", $stageNormalized,
        "--artifact", $stageArtifact
    )

    foreach ($destination in @($normalizedPath, $artifactPath, $metadataPath)) {
        $directory = Split-Path -Parent $destination
        if ($directory) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
    }

    Copy-Item -LiteralPath $stageNormalized -Destination $normalizedPath -Force
    Copy-Item -LiteralPath $stageArtifact -Destination $artifactPath -Force
    Copy-Item -LiteralPath $stageMetadata -Destination $metadataPath -Force
} finally {
    if (Test-Path -LiteralPath $stageDirectory) {
        Remove-Item -LiteralPath $stageDirectory -Recurse -Force
    }
}

Write-Host "Prepared verified production Public Suffix outputs:"
Write-Host "  normalized: $normalizedPath"
Write-Host "  artifact:   $artifactPath"
Write-Host "  metadata:   $metadataPath"
