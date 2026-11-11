# PREVIEW ONLY. This script has no path that imports/removes certificates.
[CmdletBinding()]
param([string]$OutputFile)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'trust-plan-core.ps1')
$cer = Join-Path $PSScriptRoot 'signing\homelab-fastboot-1010-public.cer'
$cat = Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.cat'
$inf = Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.inf'
if ((Get-FileHash -LiteralPath $cer -Algorithm SHA256).Hash -cne $script:Fastboot1010TrustCertificateSha256) { throw 'Certificate file changed' }
if ((Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash -ne '43E43A010714D819E045370F4807814880BEEB5148456E32CBF7523765FD72BE') { throw 'Signed catalog changed' }
if ((Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash -ne '989F050A19ACF2DB917F228BA4761150D01F298D222CC11F3CE82C9F3FE05A13') { throw 'Reviewed INF changed' }
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cer)
try {
    if ($certificate.Thumbprint -cne $script:Fastboot1010TrustThumbprint -or $certificate.HasPrivateKey) { throw 'Unexpected certificate or private key' }
    if ($certificate.Subject -cne 'CN=Homelab Fastboot 1010 Local Package' -or $certificate.Issuer -cne $certificate.Subject) { throw 'Unexpected subject/issuer' }
    $now = [DateTime]::UtcNow
    if ($certificate.NotBefore.ToUniversalTime() -gt $now -or $certificate.NotAfter.ToUniversalTime() -le $now) { throw 'Certificate not currently valid; review before any import' }
    $eku = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
    if ($eku.Count -ne 1 -or $eku[0].EnhancedKeyUsages.Count -ne 1 -or $eku[0].EnhancedKeyUsages[0].Value -ne '1.3.6.1.5.5.7.3.3') { throw 'Unexpected enhanced key usage' }
    $state = @()
    foreach ($store in $script:Fastboot1010TrustStores) {
        $path = $store+'\'+$script:Fastboot1010TrustThumbprint
        $present = Test-Path -LiteralPath $path
        $sha = $null
        if ($present) {
            $stored = Get-Item -LiteralPath $path
            $sha = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stored.RawData))
        }
        $state += [pscustomobject]@{store=$store;exists=$present;sha256=$sha}
    }
    $delta = @(Get-Fastboot1010TrustDelta -StoreState $state)
    $receiptTemplate = [ordered]@{
        schema=1;state='TEMPLATE_NOT_AN_IMPORT_RECEIPT';certificate_thumbprint=$script:Fastboot1010TrustThumbprint;certificate_sha256=$script:Fastboot1010TrustCertificateSha256
        entries=@($delta | ForEach-Object { @{store=$_.store;present_before=$_.present_before;added_by_this_operation=$false} })
    }
    $report = [ordered]@{
        utc=[DateTime]::UtcNow.ToString('o');preview_only=$true
        certificate_subject=$certificate.Subject;certificate_thumbprint=$script:Fastboot1010TrustThumbprint;certificate_sha256=$script:Fastboot1010TrustCertificateSha256
        has_private_key=$certificate.HasPrivateKey;not_after_utc=$certificate.NotAfter.ToUniversalTime().ToString('o');eku='Code Signing only'
        scope='Machine-wide code-signing trust; not cryptographically limited to VID/PID or this INF'
        proposed_changes=$delta;rollback_receipt_template=$receiptTemplate
        future_import_commands=@($delta | Where-Object { $_.action -eq 'ProposedAdd' } | ForEach-Object { "Import-Certificate -FilePath '$cer' -CertStoreLocation '$($_.store)'" })
        commands_are_text_only=$true;certificate_import_performed=$false;driver_installation=$false;tablet_reboot=$false
    }
    $json = $report | ConvertTo-Json -Depth 8
    if ($OutputFile) {
        $stream = [IO.File]::Open([IO.Path]::GetFullPath($OutputFile),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    }
    Write-Output $json
} finally { $certificate.Dispose() }
