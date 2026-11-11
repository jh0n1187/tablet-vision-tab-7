# Receipt-bound trust rollback. Default is preview; never touches drivers/USB.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReceiptPath,[switch]$Apply)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'trust-plan-core.ps1')
$receipt=Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
$targets=@(Get-Efe8OwnedTrustRemoval $receipt)
foreach ($entry in $receipt.entries) {
    $path=$entry.store+'\'+$script:Efe8TrustThumbprint
    if ($entry.import_intent_recorded -and -not $entry.present_before -and -not $entry.added_by_this_operation -and (Test-Path -LiteralPath $path)) { throw 'Ambiguous partial import; manual ownership review required' }
}
foreach ($target in $targets) {
    $path=$target.store+'\'+$target.thumbprint
    if (Test-Path -LiteralPath $path) {
        $cert=Get-Item -LiteralPath $path
        $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($cert.RawData))
        if ($hash -cne $script:Efe8TrustCertificateSha256 -or $cert.HasPrivateKey) { throw 'Certificate data mismatch; no removal' }
    }
}
if (-not $Apply) { [ordered]@{preview_only=$true;receipt=$ReceiptPath;owned_removals=$targets;certificates_removed=$false;driver_changed=$false;tablet_rebooted=$false} | ConvertTo-Json -Depth 7; return }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrative Windows token required' }
$removed=@()
foreach ($target in @($targets | Sort-Object store -Descending)) {
    $path=$target.store+'\'+$target.thumbprint
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path; $removed+=$path }
}
$report=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');receipt=$ReceiptPath;removed=$removed;driver_changed=$false;tablet_rebooted=$false}
$out=$ReceiptPath+'.rollback-'+[DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff')+'.json'
$stream=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 7));$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$report | ConvertTo-Json -Depth 7
