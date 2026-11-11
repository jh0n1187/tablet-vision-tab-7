# Default is read-only preview. Remove only the receipt-owned, unused OEM package.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReceiptPath,[switch]$Apply)
$ErrorActionPreference='Stop'
$r=Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
$pin='989F050A19ACF2DB917F228BA4761150D01F298D222CC11F3CE82C9F3FE05A13'
if ($r.schema -ne 1 -or $r.state -ne 'STAGED' -or $r.added_by_this_operation -cne $true -or $r.inf_sha256 -cne $pin -or $r.hardware_id -cne 'USB\VID_1F3A&PID_1010' -or $r.published_name -notmatch '^oem[0-9]+\.inf$' -or $r.published_name -in $r.before.name) { throw 'Invalid package ownership receipt' }
$path=Join-Path (Join-Path $env:SystemRoot 'INF') $r.published_name
if (-not (Test-Path -LiteralPath $path) -or (Get-FileHash -LiteralPath $path).Hash -cne $pin) { throw 'Published package missing or differs from receipt' }
$users=@(Get-CimInstance Win32_PnPSignedDriver | Where-Object InfName -eq $r.published_name)
$nodeUsers=@(Get-PnpDevice | ForEach-Object { $node=$_; $prop=Get-PnpDeviceProperty -InstanceId $node.InstanceId -KeyName DEVPKEY_Device_DriverInfPath -ErrorAction SilentlyContinue; if ($prop.Data -eq $r.published_name) {$node.InstanceId} })
if ($users.Count -or $nodeUsers.Count) { throw 'Package is associated with devices; review targeted uninstall separately' }
$command=@('pnputil.exe','/delete-driver',$r.published_name)
if (-not $Apply) { [ordered]@{preview_only=$true;receipt=$ReceiptPath;command=$command;inf_sha256=$pin;associated_device_count=0;uninstall_flag=$false;force=$false;reboot=$false;certificates_removed=$false} | ConvertTo-Json;return }
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator required' }
$output=& (Join-Path $env:SystemRoot 'System32\pnputil.exe') /delete-driver $r.published_name 2>&1
$code=$LASTEXITCODE
$result=[ordered]@{utc=[DateTime]::UtcNow.ToString('o');receipt=$ReceiptPath;command=$command;exit_code=$code;output=@($output | ForEach-Object ToString);reboot_requested=$false;certificates_removed=$false}
$out=$ReceiptPath+'.rollback-'+[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')+'.json'
$stream=[IO.File]::Open($out,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try {$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($result | ConvertTo-Json -Depth 6));$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)} finally {$stream.Dispose()}
if ($code -ne 0) {throw ('Removal incomplete; see '+$out)}
$result | ConvertTo-Json -Depth 6
