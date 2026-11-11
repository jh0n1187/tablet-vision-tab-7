# Authorized one-shot MSI installation. No bind/attach/reboot or security changes.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunDirectory)
$ErrorActionPreference = 'Stop'
$expectedHash = '1c984914aec944de19b64eff232421439629699f8138e3ddc29301175bc6d938'
$productCode = '{EA1D5623-E6A7-4E4A-9259-E39722050300}'
$run = [IO.Path]::GetFullPath($RunDirectory)
$installationsRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'installations')) + [IO.Path]::DirectorySeparatorChar
if (-not $run.StartsWith($installationsRoot,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $run -PathType Container)) {
    throw 'Run directory must already exist under this project installations folder'
}
$resultFile = Join-Path $run 'install-result.json'
$markerFile = Join-Path $run 'installer-started.json'
if ((Test-Path -LiteralPath $resultFile) -or (Test-Path -LiteralPath $markerFile)) { throw 'Attempt already consumed; no automatic retry' }
$result = [ordered]@{state='PRECHECK';utc_started=[DateTime]::UtcNow.ToString('o');product_code=$productCode;version='5.3.0';package_sha256=$expectedHash;initial_state_clear=$false;owns_installation=$false;msi_started=$false;msi_exit_code=$null;reboot_performed=$false;device_commands=@();error=$null}
try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator token required' }
    if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64') { throw 'Expected native x64 Windows' }
    foreach ($item in @(
        @('version_only.py','LIVE_VERSION_ENABLED'), @('winusb_backend.py','LIVE_USB_ENABLED'),
        @('linux_version_only.py','LIVE_LINUX_VERSION_ENABLED'), @('linux_capture_session.py','LIVE_LINUX_MONITOR_CAPTURE_ENABLED')
    )) {
        $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot ('..\fel-readonly\'+$item[0])) -Raw
        if ($source -notmatch ('(?m)^'+$item[1]+' = False\r?$')) { throw ('Physical gate not blocked: '+$item[1]) }
    }
    $tablet = @(Get-PnpDevice -PresentOnly | Where-Object InstanceId -Match '^USB\\VID_1F3A&PID_(4EE7|EFE8)(&|\\)')
    if ($tablet.Count) { throw 'Disconnect tablet USB before installation; no device operation attempted' }
    $msi = Join-Path $PSScriptRoot 'downloads\usbipd-win_5.3.0_x64.msi'
    if ((Get-Item -LiteralPath $msi).Length -ne 4501504 -or (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'MSI hash/size mismatch' }
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne '30EC478E9FEC6174D949FFF5C00EC028A7D2E8F9') { throw 'Unexpected MSI signature' }
    & (Join-Path $PSScriptRoot 'snapshot-host.ps1') -OutputFile (Join-Path $run 'host-just-before.json') | Out-Null
    $hostState = Get-Content -LiteralPath (Join-Path $run 'host-just-before.json') -Raw | ConvertFrom-Json
    if (@($hostState.services).Count -or @($hostState.vbox_drivers).Count -or @($hostState.firewall_rules).Count -or @($hostState.matching_oem_infs).Count -or $hostState.program_directory_exists) { throw 'Existing or conflicting product resources; stop without upgrade' }
    if (@($hostState.registry).Count -ne 3 -or @($hostState.registry | Where-Object exists).Count) { throw 'Product registry no longer clear' }
    if ($hostState.vbs_status -ne 2 -or 2 -notin @($hostState.security_services_running) -or $hostState.kernel_ci_policy -ne 2) { throw 'Security baseline changed; review before installation' }
    & (Join-Path $PSScriptRoot '..\winusb-efe8\capture-baseline.ps1') -OutputFile (Join-Path $run 'baseline-disconnected-before.json') | Out-Null
    $result.initial_state_clear = $true
    $log = Join-Path $run 'msi-install.log'
    if (Test-Path -LiteralPath $log) { throw 'Installer log already exists' }
    $arguments = '/i "{0}" /qb /norestart REBOOT=ReallySuppress /L*v "{1}"' -f $msi,$log
    $result.arguments = $arguments
    $result.state = 'INSTALLING'
    $result.msi_started = $true
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $markerFile -Encoding utf8
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $arguments -Wait -PassThru -WindowStyle Normal
    $result.msi_exit_code = $process.ExitCode
    $result.reboot_required_by_msi = ($process.ExitCode -eq 3010)
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+$productCode
    $installed = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
    if ($process.ExitCode -in @(0,3010) -and $installed.DisplayVersion -eq '5.3.0') {
        $result.state = 'APPLIED'
        $result.owns_installation = $true
        $result.installed_product = $installed | Select-Object DisplayName,DisplayVersion,InstallLocation,UninstallString
    } else {
        $result.state = 'INSTALLATION_FAILED_OR_INCOMPLETE'
    }
} catch {
    $result.state = $(if ($result.msi_started) { 'INSTALLATION_ERROR' } else { 'PRECHECK_FAILED' })
    $result.error = $_.Exception.Message
} finally {
    foreach ($step in @('host-after','baseline-after')) {
        try {
            if ($step -eq 'host-after') { & (Join-Path $PSScriptRoot 'snapshot-host.ps1') -OutputFile (Join-Path $run 'host-after.json') | Out-Null }
            else { & (Join-Path $PSScriptRoot '..\winusb-efe8\capture-baseline.ps1') -OutputFile (Join-Path $run 'baseline-after.json') | Out-Null }
        } catch { $result[$step+'_snapshot_error'] = $_.Exception.Message }
    }
    $result.utc_finished = [DateTime]::UtcNow.ToString('o')
    $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $resultFile -Encoding utf8
}
