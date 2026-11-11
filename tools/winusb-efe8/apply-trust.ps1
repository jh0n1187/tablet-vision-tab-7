# Applies only the separately authorized certificate trust, never drivers/USB.
# Default is a fresh preview; -Apply additionally requires an elevated same-user process.
[CmdletBinding()]
param([switch]$Apply,[string]$ReceiptPath,[string]$ExpectedUserSid)
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
. (Join-Path $root 'trust-plan-core.ps1')
$plan = (& (Join-Path $root 'preview-trust.ps1') | ConvertFrom-Json)
if (-not $Apply) { $plan | ConvertTo-Json -Depth 8; return }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrative Windows token required; no import performed' }
if (-not $ExpectedUserSid -or $identity.User.Value -cne $ExpectedUserSid) { throw 'Elevation identity differs from reviewed user' }
$receiptRoot=[IO.Path]::GetFullPath((Join-Path $root 'trust-receipts'))+[IO.Path]::DirectorySeparatorChar
$receiptFile=[IO.Path]::GetFullPath($ReceiptPath)
if (-not $receiptFile.StartsWith($receiptRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($receiptFile) -ne '.json') { throw 'Receipt must be a JSON in project trust-receipts' }
if (Test-Path -LiteralPath $receiptFile) { throw 'Receipt already exists; no import performed' }
$cer=Join-Path $root 'signing\homelab-fel-efe8-public.cer'
function Save-Receipt {
    param($Data,[switch]$Initial)
    $json=$Data | ConvertTo-Json -Depth 9
    $target=if ($Initial) { $receiptFile } else { $receiptFile+'.tmp' }
    $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    if (-not $Initial) { Move-Item -LiteralPath $target -Destination $receiptFile -Force }
}
$receipt=[ordered]@{
    schema=1;state='PLANNED';operation_id=[guid]::NewGuid().ToString();started_utc=[DateTime]::UtcNow.ToString('o');user_sid=$identity.User.Value
    certificate_thumbprint=$script:Efe8TrustThumbprint;certificate_sha256=$script:Efe8TrustCertificateSha256
    entries=@($plan.proposed_changes | ForEach-Object { [ordered]@{store=$_.store;present_before=[bool]$_.present_before;import_intent_recorded=$false;added_by_this_operation=$false} })
    current_user_my_before=@(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint | Sort-Object)
    driver_installed=$false;tablet_commands_sent=$false;windows_protections_changed=$false
}
Save-Receipt $receipt -Initial
try {
    foreach ($entry in $receipt.entries) {
        $store=$entry.store;$path=$store+'\'+$script:Efe8TrustThumbprint
        if ($entry.present_before) { continue }
        if (Test-Path -LiteralPath $path) { throw 'Concurrent certificate addition detected; ownership not assumed' }
        $entry.import_intent_recorded=$true;Save-Receipt $receipt
        $imported=@(Import-Certificate -FilePath $cer -CertStoreLocation $store -ErrorAction Stop)
        # Persist ownership immediately after the import successfully returns.
        $entry.added_by_this_operation=$true;Save-Receipt $receipt
        if ($imported.Count -ne 1 -or $imported[0].Thumbprint -cne $script:Efe8TrustThumbprint) { throw 'Unexpected imported certificate identity' }
        $stored=Get-Item -LiteralPath $path
        $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stored.RawData))
        if ($hash -cne $script:Efe8TrustCertificateSha256 -or $stored.HasPrivateKey) { throw 'Imported certificate data mismatch' }
        $entry['verified_der_sha256']=$hash
        Save-Receipt $receipt
    }
    $receipt['current_user_my_after']=@(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint | Sort-Object)
    if (($receipt.current_user_my_before -join ',') -cne ($receipt.current_user_my_after -join ',')) { throw 'Unexpected CurrentUser My change' }
    $receipt.state='APPLIED';$receipt['completed_utc']=[DateTime]::UtcNow.ToString('o');Save-Receipt $receipt
    Write-Output ('Certificate trust imported only in the two reviewed stores. Receipt: '+$receiptFile)
} catch {
    $receipt.state='PARTIAL';$receipt['error']=$_.Exception.Message;Save-Receipt $receipt
    throw
}
