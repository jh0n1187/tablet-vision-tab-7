# Captura metadados PnP e logs Windows; nao abre endpoints USB.
# O unico comando mutante opcional e UM adb reboot efex no T307F confirmado.
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateRange(10,180)][int]$DurationSeconds = 90,
    [ValidateRange(100,5000)][int]$PollMilliseconds = 500,
    [switch]$ReiniciarEfex,
    [string]$AdbPath = 'C:\Users\Jonathan\AppData\Local\Android\Sdk\platform-tools\adb.exe',
    [switch]$Autoteste
)
$ErrorActionPreference = 'Stop'

function New-FelSnapshot {
    param([object[]]$Devices, [double]$ElapsedSeconds, [scriptblock]$PropertyReader)
    $items = @()
    foreach ($device in $Devices) {
        if ($device.InstanceId -notmatch '^USB\\VID_1F3A&PID_([0-9A-F]{4})(&|\\)') { continue }
        $productId = $Matches[1].ToUpperInvariant()
        $properties = & $PropertyReader $device.InstanceId
        $hashBytes = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($device.InstanceId))
        $key = [Convert]::ToHexString($hashBytes).Substring(0,16)
        $items += [ordered]@{
            key=$key;vid='1F3A';pid=$productId;status=$device.Status
            name=$device.FriendlyName;class=$device.Class;properties=$properties
        }
    }
    [pscustomobject][ordered]@{
        utc=[DateTime]::UtcNow.ToString('o');elapsed_seconds=[math]::Round($ElapsedSeconds,3)
        devices=@($items | Sort-Object { $_.key })
    }
}

function Get-FelStateKey {
    param($Snapshot)
    ConvertTo-Json -InputObject @($Snapshot.devices) -Depth 8 -Compress
}

if ($Autoteste) {
    $fixture = @(
        [pscustomobject]@{InstanceId='USB\VID_1F3A&PID_4EE7\SYNTHETIC';Status='OK';FriendlyName='T307F';Class='USBDevice'},
        [pscustomobject]@{InstanceId='USB\VID_1F3A&PID_EFE8\SYNTHETIC';Status='Error';FriendlyName='';Class='Unknown'},
        [pscustomobject]@{InstanceId='USB\VID_1234&PID_EFE8\OTHER';Status='OK';FriendlyName='Other';Class='USBDevice'}
    )
    $reader = { param($id) if ($id -match 'PID_EFE8') { @{DEVPKEY_Device_ProblemCode=28;DEVPKEY_Device_Service=$null} } else { @{DEVPKEY_Device_ProblemCode=0;DEVPKEY_Device_Service='WINUSB'} } }
    $snapshot = New-FelSnapshot -Devices $fixture -ElapsedSeconds 1.2345 -PropertyReader $reader
    if ($snapshot.devices.Count -ne 2) { throw 'Filtro VID falhou' }
    $fel = @($snapshot.devices | Where-Object { $_.pid -eq 'EFE8' })[0]
    if ($fel.properties.DEVPKEY_Device_ProblemCode -ne 28) { throw 'Codigo de problema nao preservado' }
    if ((Get-FelStateKey $snapshot) -match 'SYNTHETIC') { throw 'Instancia nao foi pseudonimizada' }
    $repeat = New-FelSnapshot -Devices $fixture -ElapsedSeconds 2 -PropertyReader $reader
    if ((Get-FelStateKey $snapshot) -ne (Get-FelStateKey $repeat)) { throw 'Tempo criou transicao falsa' }
    $empty = New-FelSnapshot -Devices @() -ElapsedSeconds 3 -PropertyReader $reader
    if ($empty.devices.Count -ne 0) { throw 'Desconexao nao representada' }
    if ((Get-FelStateKey $snapshot) -eq (Get-FelStateKey $empty)) { throw 'Desconexao nao detectada' }
    $changed = New-FelSnapshot -Devices $fixture -ElapsedSeconds 4 -PropertyReader { param($id) @{DEVPKEY_Device_ProblemCode=10} }
    if ((Get-FelStateKey $snapshot) -eq (Get-FelStateKey $changed)) { throw 'Mudanca de erro nao detectada' }
    Write-Output '7 verificacoes sinteticas aprovadas; nenhum inventario real ou ADB consultado.'
    return
}

if (-not $OutputDirectory) { throw 'OutputDirectory obrigatorio' }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Pasta de captura deve ser nova; nada sera sobrescrito' }

$transport = $null
$preflight = [ordered]@{reboot_requested=[bool]$ReiniciarEfex;model=$null;hardware=$null;battery=$null}
if ($ReiniciarEfex) {
    $flashProcesses = @(Get-Process | Where-Object { $_.ProcessName -match 'Phoenix|LiveSuit|PhoenixUSB|EFT' })
    if ($flashProcesses.Count) { throw 'Ferramenta de assistencia detectada; nao reiniciar' }
    $targets = @(& $AdbPath devices -l | Where-Object { $_ -match '\sdevice\s.*model:T307F\b' })
    if ($targets.Count -ne 1 -or $targets[0] -notmatch 'transport_id:(\d+)') { throw 'T307F ADB nao identificado de forma unica' }
    $transport = $Matches[1]
    $preflight.model = (& $AdbPath -t $transport shell getprop ro.product.model | Out-String).Trim()
    $preflight.hardware = (& $AdbPath -t $transport shell getprop ro.hardware | Out-String).Trim()
    if ($preflight.model -ne 'T307F' -or $preflight.hardware -ne 'sun55iw3p1') { throw 'Identidade T307F/A523 divergente' }
    $preflight.battery = @(& $AdbPath -t $transport shell dumpsys battery)
    if ($LASTEXITCODE -ne 0) { throw 'Nao foi possivel ler bateria' }
    $batteryText = $preflight.battery -join "`n"
    if ($batteryText -notmatch '(?m)^\s*level:\s*(\d+)\s*$') { throw 'Nivel de bateria nao identificado' }
    if ([int]$Matches[1] -lt 10) { throw 'Bateria abaixo de 10%; nao reiniciar' }
    if ($batteryText -notmatch 'USB powered: true') { throw 'USB nao informado como alimentacao presente' }
}

$null = New-Item -ItemType Directory -Path $destination
$preflight | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $destination 'preflight.json') -Encoding utf8
$start = Get-Date
$setupLog = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
$setupOffset = if (Test-Path -LiteralPath $setupLog) { (Get-Item -LiteralPath $setupLog).Length } else { 0 }
$clock = [Diagnostics.Stopwatch]::StartNew()
$reader = {
    param($id)
    $errorsReading = @()
    $props = @(Get-PnpDeviceProperty -InstanceId $id -KeyName @(
        'DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_Service',
        'DEVPKEY_Device_DriverDesc','DEVPKEY_Device_DriverInfPath','DEVPKEY_Device_CompatibleIds',
        'DEVPKEY_Device_BusReportedDeviceDesc','DEVPKEY_Device_DevNodeStatus'
    ) -ErrorAction SilentlyContinue -ErrorVariable errorsReading)
    $map = [ordered]@{}
    foreach ($prop in $props) { $map[$prop.KeyName] = $prop.Data }
    $map['property_read_errors'] = $errorsReading.Count
    $map
}
$previous = ''
$sampleCount = 0
$transitionCount = 0
$rebootSent = $false
$rebootExitCode = $null
$rebootElapsed = $null
$rebootProcess = $null
$writer = [IO.StreamWriter]::new((Join-Path $destination 'samples.jsonl'),$false,[Text.UTF8Encoding]::new($false))
$writer.AutoFlush = $true
try {
    while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {
        $sampleStart = $clock.Elapsed.TotalSeconds
        $devices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object { $_.InstanceId -match '^USB\\VID_1F3A&PID_' })
        $snapshot = New-FelSnapshot -Devices $devices -ElapsedSeconds $sampleStart -PropertyReader $reader
        $snapshot | Add-Member -NotePropertyName collection_completed_seconds -NotePropertyValue ([math]::Round($clock.Elapsed.TotalSeconds,3))
        $writer.WriteLine(($snapshot | ConvertTo-Json -Depth 9 -Compress))
        $sampleCount++
        $state = Get-FelStateKey $snapshot
        if ($state -ne $previous) {
            $summary = @($snapshot.devices | ForEach-Object {
                '1F3A:'+$_.pid+' status='+$_.status+' problem='+$_.properties.DEVPKEY_Device_ProblemCode+' service='+$_.properties.DEVPKEY_Device_Service
            }) -join '; '
            if (-not $summary) { $summary = 'sem Allwinner presente' }
            $line = '{0:N3}s | {1}' -f $snapshot.elapsed_seconds,$summary
            Write-Output $line
            Add-Content -LiteralPath (Join-Path $destination 'transitions.txt') -Value $line -Encoding utf8
            $previous = $state
            $transitionCount++
        }
        # Baseline fully captured before the single, explicitly requested reboot.
        if ($ReiniciarEfex -and -not $rebootSent) {
            $rebootSent = $true
            $rebootElapsed = [math]::Round($clock.Elapsed.TotalSeconds,3)
            $startInfo = [Diagnostics.ProcessStartInfo]::new()
            $startInfo.FileName = $AdbPath
            foreach ($argument in @('-t',$transport,'reboot','efex')) { $startInfo.ArgumentList.Add($argument) }
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $rebootProcess = [Diagnostics.Process]::new()
            $rebootProcess.StartInfo = $startInfo
            if (-not $rebootProcess.Start()) { throw 'Cliente ADB nao iniciou; nao repetir automaticamente' }
            Write-Output 'adb reboot efex iniciado UMA vez em processo sem janela; polling continua sem aguardar o cliente.'
        }
        if ($null -ne $rebootProcess -and $null -eq $rebootExitCode -and $rebootProcess.HasExited) {
            $rebootExitCode = $rebootProcess.ExitCode
            $rebootProcess.StandardOutput.ReadToEnd() | Set-Content -LiteralPath (Join-Path $destination 'adb-reboot-stdout.txt') -Encoding utf8
            $rebootProcess.StandardError.ReadToEnd() | Set-Content -LiteralPath (Join-Path $destination 'adb-reboot-stderr.txt') -Encoding utf8
            Write-Output ('Cliente ADB terminou; codigo='+$rebootExitCode)
        }
        # Do not stop on EFE8: collect disappearance and return as well.
        Start-Sleep -Milliseconds $PollMilliseconds
    }
} finally {
    $writer.Dispose()
    if ($null -ne $rebootProcess) { $rebootProcess.Dispose() }
}

$eventSummary = @()
$postmortem = @()
foreach ($device in @(Get-PnpDevice | Where-Object { $_.InstanceId -match '^USB\\VID_1F3A&PID_EFE8(&|\\)' })) {
    $record = [ordered]@{vid='1F3A';pid='EFE8';present=$device.Present;status=$device.Status;collected_utc=[DateTime]::UtcNow.ToString('o')}
    foreach ($prop in @(Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName @(
        'DEVPKEY_Device_ProblemCode','DEVPKEY_Device_ProblemStatus','DEVPKEY_Device_IsPresent',
        'DEVPKEY_Device_LastArrivalDate','DEVPKEY_Device_LastRemovalDate','DEVPKEY_Device_Service',
        'DEVPKEY_Device_DriverInfPath'
    ) -ErrorAction SilentlyContinue)) { $record[$prop.KeyName]=$prop.Data }
    $postmortem += $record
}
ConvertTo-Json -InputObject $postmortem -Depth 6 | Set-Content -LiteralPath (Join-Path $destination 'postmortem-efe8.json') -Encoding utf8
foreach ($logName in @('Microsoft-Windows-Kernel-PnP/Configuration','Microsoft-Windows-UserPnp/DeviceInstall','Microsoft-Windows-DeviceSetupManager/Admin','Microsoft-Windows-DriverFrameworks-UserMode/Operational','System')) {
    $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if (-not $log -or -not $log.IsEnabled) { $eventSummary += @{log=$logName;queried=$false;reason='unavailable or disabled; not enabled by this script'}; continue }
    $events = @(Get-WinEvent -FilterHashtable @{LogName=$logName;StartTime=$start} -MaxEvents 1500 -ErrorAction SilentlyContinue | Where-Object {
        $_.ToXml() -match 'VID_1F3A|pid_efe8|sunxi'
    })
    $eventSummary += @{log=$logName;queried=$true;matching_events=$events.Count}
    foreach ($event in $events) {
        [ordered]@{utc=$event.TimeCreated.ToUniversalTime().ToString('o');log=$logName;id=$event.Id;level=$event.LevelDisplayName;xml=$event.ToXml();message=$event.Message} |
            ConvertTo-Json -Depth 7 -Compress | Add-Content -LiteralPath (Join-Path $destination 'windows-events.jsonl') -Encoding utf8
    }
}

if (Test-Path -LiteralPath $setupLog) {
    $stream = [IO.File]::Open($setupLog,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $offset = if ($stream.Length -ge $setupOffset) { $setupOffset } else { 0 }
        $null = $stream.Seek($offset,[IO.SeekOrigin]::Begin)
        $bytes = [byte[]]::new([int][math]::Min(2097152,$stream.Length-$offset))
        $count = $stream.Read($bytes,0,$bytes.Length)
        [Text.Encoding]::UTF8.GetString($bytes,0,$count) | Set-Content -LiteralPath (Join-Path $destination 'setupapi-appended.txt') -Encoding utf8
    } finally { $stream.Dispose() }
}

[ordered]@{start_utc=$start.ToUniversalTime().ToString('o');end_utc=[DateTime]::UtcNow.ToString('o');samples=$sampleCount;state_changes=$transitionCount;
    requested_duration_seconds=$DurationSeconds;requested_poll_sleep_ms=$PollMilliseconds;reboot_sent=$rebootSent;reboot_elapsed_seconds=$rebootElapsed;reboot_exit_code=$rebootExitCode;
    event_logs=$eventSummary;usb_endpoints_opened=$false;payload_loaded=$false;partition_write_commands_sent=$false;
    limitations=@('Polling interval includes PnP/property query time','No device-side trace or USB packets','Cannot prove cause from temporal correlation alone')
} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $destination 'manifest.json') -Encoding utf8
Write-Output ('Captura concluida: '+$destination+' | amostras='+$sampleCount+' | mudancas='+$transitionCount)
