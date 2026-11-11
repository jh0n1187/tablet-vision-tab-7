# Stage one hash-pinned 1010 package. Never restarts or opens a USB device.
[CmdletBinding()]
param([switch]$Apply,[string]$ReceiptPath,[string]$ExpectedUserSid)
$ErrorActionPreference='Stop'
$inf=Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.inf'
$cat=Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.cat'
$infHash='989F050A19ACF2DB917F228BA4761150D01F298D222CC11F3CE82C9F3FE05A13'
$catHash='43E43A010714D819E045370F4807814880BEEB5148456E32CBF7523765FD72BE'
if ((Get-FileHash $inf).Hash -cne $infHash -or (Get-FileHash $cat).Hash -cne $catHash) { throw 'Reviewed package hash mismatch' }
$signature=Get-AuthenticodeSignature $cat
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne 'F1D9D3825930C5768826BC2274E6C1F047356854') { throw 'Reviewed catalog signature not trusted' }
if (-not $Apply) { [pscustomobject]@{preview_only=$true;command=@('pnputil.exe','/add-driver',$inf);install_flag=$false;reboot=$false;payload=$false} | ConvertTo-Json;return }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or $identity.User.Value -cne $ExpectedUserSid) { throw 'Elevated same-user token required' }
$receiptRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'driver-receipts'))+'\'
$receiptFile=[IO.Path]::GetFullPath($ReceiptPath)
if (-not $receiptFile.StartsWith($receiptRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($receiptFile) -ne '.json' -or (Test-Path -LiteralPath $receiptFile)) { throw 'Fresh project receipt required' }
function Get-OemInventory { @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'INF') -Filter 'oem*.inf' -File | Sort-Object Name | ForEach-Object { [ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash} }) }
$before=@(Get-OemInventory)
if (@($before | Where-Object sha256 -eq $infHash).Count -ne 0) { throw 'Package already published; ownership cannot be assumed' }
$receipt=[ordered]@{schema=1;state='PLANNED';started_utc=[DateTime]::UtcNow.ToString('o');inf_sha256=$infHash;catalog_sha256=$catHash;hardware_id='USB\VID_1F3A&PID_1010';before=$before;published_name=$null;added_by_this_operation=$false;command=@('pnputil.exe','/add-driver',$inf);tablet_commands_sent=$false;reboot_requested=$false;payload_loaded=$false}
function Save-Receipt {
    $target=if (Test-Path -LiteralPath $receiptFile) {$receiptFile+'.tmp'} else {$receiptFile}
    $stream=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
    try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($receipt | ConvertTo-Json -Depth 9));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
    if ($target -ne $receiptFile) {Move-Item -LiteralPath $target -Destination $receiptFile -Force}
}
Save-Receipt
try {
    $receipt.state='STAGING';Save-Receipt
    $output=& (Join-Path $env:SystemRoot 'System32\pnputil.exe') /add-driver $inf 2>&1
    $receipt['pnputil_exit_code']=$LASTEXITCODE
    $receipt['pnputil_output']=@($output | ForEach-Object ToString)
    $after=@(Get-OemInventory);$receipt['after']=$after
    $matching=@($after | Where-Object sha256 -eq $infHash)
    if ($matching.Count -eq 1 -and $matching[0].name -notin $before.name) {
        $receipt.published_name=$matching[0].name;$receipt.added_by_this_operation=$true
    }
    Save-Receipt
    if ($receipt.pnputil_exit_code -ne 0) { throw ('PnPUtil returned '+$receipt.pnputil_exit_code+'; no reboot will be performed') }
    if (-not $receipt.added_by_this_operation) { throw 'Unique newly published package could not be identified' }
    $receipt.state='STAGED';$receipt['completed_utc']=[DateTime]::UtcNow.ToString('o');Save-Receipt
} catch {$receipt.state='REVIEW_REQUIRED';$receipt['error']=$_.Exception.Message;Save-Receipt;throw}
