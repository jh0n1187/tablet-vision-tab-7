# Explicitly authorized trust + exact 1010 package staging. Never reboots or opens USB.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExpectedUserSid)
$ErrorActionPreference='Stop'
$out=Join-Path $PSScriptRoot 'validation\authorized-install-result.json'
if(Test-Path -LiteralPath $out){throw 'Operation result already exists; no retry'}
$r=[ordered]@{state='STARTED';trust_imported=$false;driver_staged=$false;tablet_rebooted=$false;payload_loaded=$false;protections_changed=$false}
try {
    & (Join-Path $PSScriptRoot 'apply-trust.ps1') -Apply -ExpectedUserSid $ExpectedUserSid -ReceiptPath (Join-Path $PSScriptRoot 'trust-receipts\import-1010-20261110.json') | Out-Null
    $r.trust_imported=$true
    $signtool='C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
    & $signtool verify /pa /v /c (Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.cat') (Join-Path $PSScriptRoot 'package\homelab-fastboot-1010.inf') *> (Join-Path $PSScriptRoot 'validation\trusted-catalog-inf-verification.txt')
    $r['trusted_verification_exit_code']=$LASTEXITCODE
    if($LASTEXITCODE -ne 0){throw 'Trusted catalog/INF verification failed; driver not staged'}
    & (Join-Path $PSScriptRoot 'stage-driver.ps1') -Apply -ExpectedUserSid $ExpectedUserSid -ReceiptPath (Join-Path $PSScriptRoot 'driver-receipts\stage-1010-20261110.json')
    $r.driver_staged=$true
    & (Join-Path $PSScriptRoot 'capture-baseline.ps1') -OutputFile (Join-Path $PSScriptRoot 'baseline\after-authorized-install.json') | Out-Null
    $r.state='COMPLETE'
} catch {
    $r.state='REVIEW_REQUIRED';$r['error']=$_.Exception.Message
} finally {
    $r['utc']=[DateTime]::UtcNow.ToString('o')
    $r | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $out -Encoding utf8
}
