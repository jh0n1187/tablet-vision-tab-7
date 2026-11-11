param([switch]$Execute, [string]$RunDirectory)
if(-not $env:T307F_SERIAL){throw 'Defina T307F_SERIAL antes de acessar o tablet'}
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$usbipd = 'C:\Program Files\usbipd-win\usbipd.exe'
$target = 'USB\VID_1F3A&PID_EFE8\5&551BC54&0&2'
$normal = ('USB\VID_1F3A&PID_4EE7\' + $env:T307F_SERIAL)
$guidPattern = '\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b'
if (-not $Execute) {
    [ordered]@{preview_only=$true;busid='1-2';hardware_id='1f3a:efe8';
        policy='Allow AutoBind, both selectors required';maximum_seconds=120;
        cleanup='Remove owned policy GUID; unbind only new GUID of exact EFE8 instance';
        reboot=$false;attach=$false;version=$false} | ConvertTo-Json
    return
}
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated, explicitly authorized PowerShell child is required for this policy only'
}
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../../../..')).Path
$run = (Resolve-Path -LiteralPath $RunDirectory).Path
if (-not $run.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Run directory must be inside the tablet project'
}
$marker = Join-Path $run 'policy-started.json'
if (Test-Path -LiteralPath $marker) {throw 'Used run directory; no repeat'}
if (Test-Path -LiteralPath (Join-Path $run 'finished')) {throw 'Coordinator already finished; do not apply policy'}
$beforeJson = & $usbipd state
if ($LASTEXITCODE -ne 0) {throw 'Cannot read USB/IP baseline'}
$before = ($beforeJson | ConvertFrom-Json).Devices
$adb = @($before | Where-Object InstanceId -EQ $normal)
if ($adb.Count -ne 1 -or $adb[0].BusId -ne '1-2' -or $adb[0].PersistedGuid -or $adb[0].IsForced -or $adb[0].ClientIPAddress) {
    throw 'ADB target/port changed or is already shared'
}
if (@($before | Where-Object InstanceId -EQ $target).Count) {throw 'EFE8 already present/persisted'}
$policies = & $usbipd policy list
if ($LASTEXITCODE -ne 0 -or [regex]::Matches(($policies -join "`n"), $guidPattern).Count) {
    throw 'Expected no preexisting policies; refuse to modify ambiguous state'
}
$beforeJson | Set-Content -LiteralPath (Join-Path $run 'policy-devices-before.json') -Encoding UTF8
[ordered]@{time=[DateTime]::UtcNow.ToString('o');pid=$PID;scope='1-2 AND 1f3a:efe8';maximum_seconds=120} |
    ConvertTo-Json | Set-Content -LiteralPath $marker -Encoding UTF8
$ownedGuid = $null
$receipt = [ordered]@{policy_guid=$null;policy_removed=$false;unbind_guids=@();errors=@()}
try {
    $result = & $usbipd policy add --effect Allow --operation AutoBind --busid 1-2 --hardware-id 1f3a:efe8 2>&1
    $code = $LASTEXITCODE
    $matches = [regex]::Matches(($result -join "`n"), $guidPattern)
    if ($code -ne 0 -or $matches.Count -ne 1) {throw 'Policy add failed or did not return one ownership GUID'}
    $ownedGuid = $matches[0].Value
    $receipt.policy_guid = $ownedGuid
    $result | Set-Content -LiteralPath (Join-Path $run 'policy-add.txt') -Encoding UTF8
    [ordered]@{policy_guid=$ownedGuid;time=[DateTime]::UtcNow.ToString('o')} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'policy-ready.json') -Encoding UTF8
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 120 -and -not (Test-Path -LiteralPath (Join-Path $run 'finished'))) {
        Start-Sleep -Milliseconds 200
    }
} catch {
    $receipt.errors += $_.Exception.Message
} finally {
    if ($ownedGuid) {
        & $usbipd policy remove --guid $ownedGuid 2>&1 |
            Set-Content -LiteralPath (Join-Path $run 'policy-remove.txt') -Encoding UTF8
        $receipt.policy_removed = ($LASTEXITCODE -eq 0)
    }
    try {
        $afterJson = & $usbipd state
        if ($LASTEXITCODE -ne 0) {throw 'Cannot read final USB/IP state'}
        $after = ($afterJson | ConvertFrom-Json).Devices
        $owned = @($after | Where-Object { $_.InstanceId -eq $target -and $_.PersistedGuid })
        if ($owned.Count -gt 1) {throw 'Ambiguous EFE8 binding; manual review needed'}
        foreach ($device in $owned) {
            $binding = [guid]$device.PersistedGuid
            & $usbipd unbind --guid $binding.ToString() 2>&1 |
                Set-Content -LiteralPath (Join-Path $run 'policy-unbind.txt') -Encoding UTF8
            if ($LASTEXITCODE -ne 0) {throw 'Owned EFE8 unbind failed'}
            $receipt.unbind_guids += $binding.ToString()
        }
        & $usbipd state | Set-Content -LiteralPath (Join-Path $run 'policy-devices-final.json') -Encoding UTF8
        & $usbipd policy list | Set-Content -LiteralPath (Join-Path $run 'policies-final.txt') -Encoding UTF8
    } catch { $receipt.errors += $_.Exception.Message }
    $receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $run 'policy-cleanup.json') -Encoding UTF8
}
