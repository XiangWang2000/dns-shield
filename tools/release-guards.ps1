function Get-ApkMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AaptPath,
        [Parameter(Mandatory = $true)]
        [string]$ApkPath
    )

    $badging = (& $AaptPath dump badging $ApkPath 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read APK metadata from $ApkPath."
    }
    $match = [regex]::Match($badging, "(?m)^package: name='(?<applicationId>[^']+)' versionCode='(?<versionCode>\d+)'")
    if (-not $match.Success) {
        throw "Could not parse application ID and versionCode from $ApkPath."
    }
    [pscustomobject]@{
        ApplicationId = $match.Groups['applicationId'].Value
        VersionCode = [long]$match.Groups['versionCode'].Value
    }
}

function Get-ApkSignerDigests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApkSignerPath,
        [Parameter(Mandatory = $true)]
        [string]$ApkPath
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $verification = (& $ApkSignerPath verify --verbose --print-certs $ApkPath 2>&1 | Out-String)
        $signerExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($signerExitCode -ne 0) {
        throw "APK signature verification failed for $ApkPath."
    }
    return Get-CertificateSha256Digests -VerificationOutput $verification -ApkPath $ApkPath
}

function Get-CertificateSha256Digests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VerificationOutput,
        [string]$ApkPath = "APK"
    )

    $digests = [regex]::Matches(
        $VerificationOutput,
        "(?im)^(?:Signer #\d+(?::? certificate)|V\d+(?:\.\d+)? Signer: certificate) SHA-256 digest:\s*(?<digest>[0-9a-f]{64})\s*$"
    ) | ForEach-Object { $_.Groups['digest'].Value.ToLowerInvariant() } | Sort-Object -Unique
    if (-not $digests) {
        throw "No APK signer certificate SHA-256 digest was reported for $ApkPath."
    }
    return @($digests)
}

function Assert-ReleaseCompatibility {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$BaselineMetadata,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$CandidateMetadata,
        [Parameter(Mandatory = $true)]
        [string[]]$BaselineSignerDigests,
        [Parameter(Mandatory = $true)]
        [string[]]$CandidateSignerDigests
    )

    if ($CandidateMetadata.ApplicationId -cne $BaselineMetadata.ApplicationId) {
        throw "Release application ID '$($CandidateMetadata.ApplicationId)' does not match baseline '$($BaselineMetadata.ApplicationId)'."
    }
    if ([long]$CandidateMetadata.VersionCode -le [long]$BaselineMetadata.VersionCode) {
        throw "Release versionCode $($CandidateMetadata.VersionCode) must be greater than baseline $($BaselineMetadata.VersionCode)."
    }
    if ((($CandidateSignerDigests | Sort-Object) -join ',') -ne (($BaselineSignerDigests | Sort-Object) -join ',')) {
        throw "Release signer certificate does not match the trusted baseline APK."
    }
}
