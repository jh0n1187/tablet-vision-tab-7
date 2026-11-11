# Read-only system inventory. Writes evidence files only in the workspace.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputFile)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputFile) { throw 'Arquivo existente; recusa sobrescrita' }
$devices = @()
foreach ($device in @(Get-PnpDevice | Where-Object { $_.InstanceId -match '^USB\\VID_1F3A&PID_(4EE7|EFE8)(&|\\)' })) {
    $null = $device.InstanceId -match 'PID_([0-9A-F]{4})'
    $record = [ordered]@{pid=$Matches[1].ToUpperInvariant();instance_id=$device.InstanceId;present=$device.Present;status=$device.Status;name=$device.FriendlyName}
    foreach ($prop in @(Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName @(
        'DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_Service','DEVPKEY_Device_HardwareIds',
        'DEVPKEY_Device_CompatibleIds','DEVPKEY_Device_DriverProvider','DEVPKEY_Device_DriverVersion'
    ) -ErrorAction SilentlyContinue)) { $record[$prop.KeyName] = $prop.Data }
    $parameterPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\'+$device.InstanceId+'\Device Parameters'
    $parameterState = [ordered]@{key_exists=$false;read_error=$null;values=@{}}
    try {
        $parameterKey = Get-Item -LiteralPath $parameterPath -ErrorAction Stop
        $parameterState.key_exists = $true
        foreach ($valueName in @('DeviceInterfaceGUIDs','DeviceInterfaceGUID')) {
            if ($parameterKey.GetValueNames() -contains $valueName) {
                $parameterState.values[$valueName] = @{exists=$true;kind=$parameterKey.GetValueKind($valueName).ToString();data=$parameterKey.GetValue($valueName)}
            } else { $parameterState.values[$valueName] = @{exists=$false} }
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        $parameterState.key_exists = $false
    } catch { $parameterState.read_error = $_.Exception.Message }
    $record['device_parameters'] = $parameterState
    $devices += $record
}
$files = @()
foreach ($path in @((Join-Path $env:SystemRoot 'INF\winusb.inf'),(Join-Path $env:SystemRoot 'System32\drivers\WinUSB.sys'))) {
    $record = [ordered]@{path=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
    if ($path -like '*.sys') {
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        $record['signature_status'] = $signature.Status.ToString()
        $record['signer'] = $signature.SignerCertificate.Subject
    }
    $files += $record
}
$stores = @()
foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher')) {
    $stores += [ordered]@{store=$store;thumbprints=@(Get-ChildItem -LiteralPath $store | Select-Object -ExpandProperty Thumbprint | Sort-Object)}
}
$published = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'INF') -Filter 'oem*.inf' -File | Sort-Object Name | ForEach-Object { @{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash} })
$evidence = [ordered]@{utc=[DateTime]::UtcNow.ToString('o');architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();devices=$devices;inbox_files=$files;certificate_stores=$stores;published_oem_infs=$published;operations='Read-only PnP, registry Device Parameters, INF hashes, existing driver signature and public certificate thumbprints'}
$json = $evidence | ConvertTo-Json -Depth 8
$stream = [IO.File]::Open([IO.Path]::GetFullPath($OutputFile),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream.Write($bytes,0,$bytes.Length)
} finally { $stream.Dispose() }
Write-Output ('Inventario salvo sem alterar drivers: '+$OutputFile)
