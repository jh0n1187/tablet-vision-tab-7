# Read-only usbipd installation footprint and security state. No device endpoints.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputFile)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputFile) { throw 'Refusing existing evidence file' }
$classPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}'
$classKey = Get-Item -LiteralPath $classPath
$filters = [ordered]@{}
foreach ($name in @('UpperFilters','LowerFilters')) {
    $exists = $classKey.GetValueNames() -contains $name
    $filters[$name] = @{exists=$exists;data=$(if ($exists) { @($classKey.GetValue($name)) } else { @() })}
}
$services = @(Get-CimInstance Win32_Service -Filter "Name='usbipd' OR Name='usbipd-win'" | Select-Object Name,State,StartMode,PathName,StartName)
$drivers = @(Get-CimInstance Win32_SystemDriver -Filter "Name LIKE 'VBox%'" | Select-Object Name,State,StartMode,PathName)
$rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DisplayName -eq 'usbipd' -or $_.Name -eq 'usbipd' } | Sort-Object Name | Select-Object Name,DisplayName,Enabled,Direction,Action,Profile)
$reg = @()
foreach ($key in @('HKLM:\SOFTWARE\usbipd-win','HKLM:\SOFTWARE\WOW6432Node\usbipd-win','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{EA1D5623-E6A7-4E4A-9259-E39722050300}')) {
    $record = [ordered]@{path=$key;exists=(Test-Path -LiteralPath $key)}
    if ($record.exists) {
        $item = Get-ItemProperty -LiteralPath $key
        $record.details = $item | Select-Object Version,DisplayVersion,DisplayName,APPLICATIONFOLDER,InstallLocation
    }
    $reg += $record
}
$deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$windows = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$oem = @(Get-ChildItem -LiteralPath "$env:SystemRoot\INF" -Filter 'oem*.inf' -File | Where-Object {
    Select-String -LiteralPath $_.FullName -Pattern 'VBoxUSB|usbipd-win' -Quiet
} | ForEach-Object { [ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash} })
$data = [ordered]@{utc=[DateTime]::UtcNow.ToString('o');architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();windows_display_version=$windows.DisplayVersion;build=($windows.CurrentBuild+'.'+$windows.UBR);services=$services;vbox_drivers=$drivers;firewall_rules=$rules;registry=$reg;usb_class_filters=$filters;machine_path=[Environment]::GetEnvironmentVariable('Path','Machine');program_directory_exists=(Test-Path -LiteralPath 'C:\Program Files\usbipd-win');matching_oem_infs=$oem;vbs_status=$deviceGuard.VirtualizationBasedSecurityStatus;security_services_running=@($deviceGuard.SecurityServicesRunning);kernel_ci_policy=$deviceGuard.CodeIntegrityPolicyEnforcementStatus;usermode_ci_policy=$deviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus;operations='Read-only host inventory; no installer, driver, firewall, policy or USB change'}
$data | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputFile -Encoding utf8
Write-Output ('Read-only inventory saved: '+$OutputFile)
