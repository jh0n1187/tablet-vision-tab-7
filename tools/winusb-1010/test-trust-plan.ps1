# Tests only pure planning functions using synthetic store/receipt objects.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'trust-plan-core.ps1')
$rootStore='Cert:\LocalMachine\Root'
$publisherStore='Cert:\LocalMachine\TrustedPublisher'
$thumb=$script:Fastboot1010TrustThumbprint
$sha=$script:Fastboot1010TrustCertificateSha256
$checks=0
function Expect-Rejection([scriptblock]$Action) {
    $rejected=$false
    try { & $Action | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Unsafe operation was not rejected' }
}
$absent=@(@{store=$rootStore;exists=$false;sha256=$null},@{store=$publisherStore;exists=$false;sha256=$null})
if (@(Get-Fastboot1010TrustDelta $absent | Where-Object action -eq 'ProposedAdd').Count -ne 2) { throw 'Missing additions' };$checks++
$oneExisting=@(@{store=$rootStore;exists=$true;sha256=$sha},$absent[1])
if (@(Get-Fastboot1010TrustDelta $oneExisting | Where-Object action -eq 'ProposedAdd').Count -ne 1) { throw 'Existing trust not preserved' };$checks++
$bothExisting=@(@{store=$rootStore;exists=$true;sha256=$sha},@{store=$publisherStore;exists=$true;sha256=$sha})
if (@(Get-Fastboot1010TrustDelta $bothExisting | Where-Object action -eq 'ProposedAdd').Count) { throw 'Not idempotent' };$checks++
Expect-Rejection { Get-Fastboot1010TrustDelta @(@{store=$rootStore;exists=$true;sha256='WRONG'},$absent[1]) };$checks++
Expect-Rejection { Get-Fastboot1010TrustDelta @($absent[0],$absent[0]) };$checks++
Expect-Rejection { Get-Fastboot1010TrustDelta @(@{store='Cert:\CurrentUser\Root';exists=$false},$absent[1]) };$checks++
$receipt=@{schema=1;state='APPLIED';certificate_thumbprint=$thumb;certificate_sha256=$sha;entries=@(@{store=$rootStore;present_before=$false;added_by_this_operation=$true},@{store=$publisherStore;present_before=$true;added_by_this_operation=$false})}
$removals=@(Get-Fastboot1010OwnedTrustRemoval $receipt)
if ($removals.Count -ne 1 -or $removals[0].store -ne $rootStore) { throw 'Rollback touched preexisting trust' };$checks++
$receipt.entries[0].added_by_this_operation=$false
if (@(Get-Fastboot1010OwnedTrustRemoval $receipt).Count) { throw 'Rollback touched unowned trust' };$checks++
$receipt.entries[1].added_by_this_operation=$true
Expect-Rejection { Get-Fastboot1010OwnedTrustRemoval $receipt };$checks++
$receipt.entries[1].store=$publisherStore;$receipt.state='TEMPLATE_NOT_AN_IMPORT_RECEIPT'
Expect-Rejection { Get-Fastboot1010OwnedTrustRemoval $receipt };$checks++
Expect-Rejection { Get-Fastboot1010TrustDelta @(@{store=$rootStore;exists='false';sha256=$sha},$absent[1]) };$checks++
$receipt.state='APPLIED';$receipt.entries[0].added_by_this_operation='true'
Expect-Rejection { Get-Fastboot1010OwnedTrustRemoval $receipt };$checks++
$receipt.entries[1].added_by_this_operation=$false
$receipt.certificate_thumbprint='FOREIGN'
Expect-Rejection { Get-Fastboot1010OwnedTrustRemoval $receipt };$checks++
$receipt.certificate_thumbprint=$thumb;$receipt.entries[0].added_by_this_operation=$false;$receipt.entries[1].store=$rootStore
Expect-Rejection { Get-Fastboot1010OwnedTrustRemoval $receipt };$checks++
Write-Output ($checks.ToString()+' verificacoes sinteticas aprovadas; nenhuma loja de certificados consultada ou alterada.')
