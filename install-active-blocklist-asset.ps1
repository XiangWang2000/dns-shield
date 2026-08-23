param(
    [string]$Artifact = "build/active.bin"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$artifactPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Artifact))
$assetPath = Join-Path $repoRoot "app/src/main/assets/active.bin"
$manifestPath = Join-Path $repoRoot "tools/active_blocklist_production.json"
$sourceManifestPath = Join-Path $repoRoot "tools/active_blocklist_source.json"
$verifyScript = Join-Path $repoRoot "tools/verify_active_blocklist_asset.py"

& python $verifyScript --manifest $manifestPath --source-manifest $sourceManifestPath --asset $artifactPath
if ($LASTEXITCODE -ne 0) {
    throw "Candidate active.bin verification failed with exit code $LASTEXITCODE"
}

Copy-Item -LiteralPath $artifactPath -Destination $assetPath -Force
& python $verifyScript --manifest $manifestPath --source-manifest $sourceManifestPath --asset $assetPath
if ($LASTEXITCODE -ne 0) {
    throw "Installed active.bin verification failed with exit code $LASTEXITCODE"
}

Write-Host "Installed verified production blocklist asset: $assetPath"
