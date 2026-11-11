# Pure planning functions. No certificate-store, driver or device writes.
$script:Fastboot1010TrustThumbprint = 'F1D9D3825930C5768826BC2274E6C1F047356854'
$script:Fastboot1010TrustCertificateSha256 = '017833237D9D0C4A05477F59F3BBCB9749FC0E7BCCA2253BDFD42E383A644FFE'
$script:Fastboot1010TrustStores = @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')

function Get-Fastboot1010TrustDelta {
    param([Parameter(Mandatory)][object[]]$StoreState)
    if ($StoreState.Count -ne 2) { throw 'Expected exactly two machine stores' }
    $seen = @()
    foreach ($entry in $StoreState) {
        if ($entry.exists -isnot [bool]) { throw 'Store existence must be an explicit boolean' }
        if ($entry.store -cnotin $script:Fastboot1010TrustStores -or $seen -ccontains $entry.store) { throw 'Unexpected or duplicate store' }
        $seen += $entry.store
        if ($entry.exists -and $entry.sha256 -cne $script:Fastboot1010TrustCertificateSha256) { throw 'Existing certificate data mismatch' }
        [pscustomobject]@{store=$entry.store;thumbprint=$script:Fastboot1010TrustThumbprint;action=$(if ($entry.exists) {'PreserveExisting'} else {'ProposedAdd'});present_before=[bool]$entry.exists}
    }
}

function Get-Fastboot1010OwnedTrustRemoval {
    param([Parameter(Mandatory)]$Receipt)
    if ($Receipt.schema -ne 1 -or $Receipt.certificate_thumbprint -cne $script:Fastboot1010TrustThumbprint -or $Receipt.certificate_sha256 -cne $script:Fastboot1010TrustCertificateSha256) { throw 'Receipt identity mismatch' }
    if ($Receipt.state -cnotin @('APPLIED','PARTIAL')) { throw 'Only an actual applied/partial receipt may authorize rollback planning' }
    if ($Receipt.entries.Count -ne 2) { throw 'Receipt must contain two stores' }
    $seen = @()
    foreach ($entry in $Receipt.entries) {
        if ($entry.present_before -isnot [bool] -or $entry.added_by_this_operation -isnot [bool]) { throw 'Receipt ownership flags must be explicit booleans' }
        if ($entry.store -cnotin $script:Fastboot1010TrustStores -or $seen -ccontains $entry.store) { throw 'Unexpected or duplicate receipt store' }
        $seen += $entry.store
        if ($entry.present_before -and $entry.added_by_this_operation) { throw 'Cannot claim ownership of preexisting trust' }
        if ($entry.added_by_this_operation -and -not $entry.present_before) {
            [pscustomobject]@{store=$entry.store;thumbprint=$script:Fastboot1010TrustThumbprint;certificate_sha256=$script:Fastboot1010TrustCertificateSha256;action='ProposedRemoveOwnedCertificate'}
        }
    }
}
