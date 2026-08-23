param(
    [string]$Python = "python",
    [string]$Source = "",
    [string]$Artifact = "build/active.bin"
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

$sourceManifestPath = Join-Path $repoRoot "tools/active_blocklist_source.json"
$productionManifestPath = Join-Path $repoRoot "tools/active_blocklist_production.json"
$downloadScript = Join-Path $repoRoot "tools/download_active_blocklist_source.py"
$verifySourceScript = Join-Path $repoRoot "tools/verify_active_blocklist_source.py"
$buildScript = Join-Path $repoRoot "tools/build_blocklist.py"
$verifyScript = Join-Path $repoRoot "tools/verify_active_blocklist_asset.py"
$artifactPath = Resolve-RepoPath $Artifact
$stageDirectory = Join-Path $repoRoot "build/active-blocklist.prepare.$PID"

New-Item -ItemType Directory -Force -Path $stageDirectory | Out-Null
try {
    if ([string]::IsNullOrWhiteSpace($Source)) {
        $sourcePath = Join-Path $stageDirectory "1hosts-lite.domains.txt"
        Invoke-PythonStep "Downloading pinned production blocklist source..." @(
            $downloadScript,
            "--manifest", $sourceManifestPath,
            "--output", $sourcePath
        )
    } else {
        $sourcePath = Resolve-RepoPath $Source
        if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw "Pinned blocklist source file not found: $sourcePath"
        }
    }

    Invoke-PythonStep "Verifying pinned production blocklist source..." @(
        $verifySourceScript,
        "--manifest", $sourceManifestPath,
        "--input", $sourcePath
    )

    $stageArtifact = Join-Path $stageDirectory "active.bin"
    Invoke-PythonStep "Building deterministic production blocklist..." @(
        $buildScript,
        "--input", $sourcePath,
        "--output", $stageArtifact
    )
    Invoke-PythonStep "Verifying production blocklist contract..." @(
        $verifyScript,
        "--manifest", $productionManifestPath,
        "--source-manifest", $sourceManifestPath,
        "--asset", $stageArtifact
    )

    $artifactDirectory = Split-Path -Parent $artifactPath
    New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
    Copy-Item -LiteralPath $stageArtifact -Destination $artifactPath -Force
} finally {
    if (Test-Path -LiteralPath $stageDirectory) {
        Remove-Item -LiteralPath $stageDirectory -Recurse -Force
    }
}

Write-Host "Prepared verified production blocklist: $artifactPath"
