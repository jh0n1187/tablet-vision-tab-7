# Default: preview. Exact receipt-owned 1010 package only, after returning to Android.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReceiptPath,[switch]$Apply)
$ErrorActionPreference='Stop'
$r=Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
$pin='989F050A19ACF2DB917F228BA4761150D01F298D222CC11F3CE82C9F3FE05A13'
if($r.schema -ne 1 -or $r.state -ne 'STAGED' -or $r.added_by_this_operation -cne $true -or $r.inf_sha256 -cne $pin -or $r.hardware_id -cne 'USB\VID_1F3A&PID_1010' -or $r.published_name -notmatch '^oem[0-9]+\.inf$' -or $r.published_name -in $r.before.name){throw 'Invalid package ownership receipt'}
$published=Join-Path $env:SystemRoot ('INF\'+$r.published_name)
if(-not(Test-Path -LiteralPath $published) -or (Get-FileHash -LiteralPath $published -Algorithm SHA256).Hash -cne $pin){throw 'Published package hash mismatch'}
$devices=@(Get-PnpDevice)
if(-not @($devices|Where-Object {$_.Present -and $_.Status -eq 'OK' -and $_.InstanceId -match '^USB\\VID_1F3A&PID_4EE7(&|\\)'}).Count){throw 'Android 4EE7 must be present and healthy before rollback'}
if(@($devices|Where-Object {$_.Present -and $_.InstanceId -match '^USB\\VID_1F3A&PID_1010(&|\\)'}).Count){throw 'Return to Android before removing the bootloader driver'}
$associated=@(foreach($node in $devices){
    $p=Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName DEVPKEY_Device_DriverInfPath -ErrorAction SilentlyContinue
    if($p.Data -eq $r.published_name){
        if($node.InstanceId -notmatch '^USB\\VID_1F3A&PID_1010(&|\\)'){throw 'Package associated with an unexpected device; no removal'}
        $node
    }
})
$command=@('pnputil.exe','/delete-driver',$r.published_name,'/uninstall')
if(-not $Apply){[ordered]@{preview_only=$true;command=$command;associated_1010_nodes=$associated.Count;force=$false;reboot=$false;adb_and_efe8_untouched=$true;trust_not_removed=$true}|ConvertTo-Json;return}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if(-not([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator required'}
$output=& (Join-Path $env:SystemRoot 'System32\pnputil.exe') /delete-driver $r.published_name /uninstall 2>&1
$code=$LASTEXITCODE
$result=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');command=$command;exit_code=$code;output=@($output|ForEach-Object ToString);reboot_performed=$false;trust_removed=$false}
$out=$ReceiptPath+'.associated-rollback-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json'
$stream=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try{$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result|ConvertTo-Json -Depth 6));$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
if($code -ne 0){throw ('Rollback needs review; no reboot performed. Receipt: '+$out)}
$result|ConvertTo-Json -Depth 6
