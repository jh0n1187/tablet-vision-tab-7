# Pure planning functions. No certificate-store, driver or device writes.
$script:Efe8TrustThumbprint = '9169C63101332FE8064D63B31E70BAAEAA81D813'
$script:Efe8TrustCertificateSha256 = 'A268B2990119F20C46F6095224310744C59F9B0D82CF0BE95D4C86EC51C1F0AD'
$script:Efe8TrustStores = @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')

function Get-Efe8TrustDelta {
    param([Parameter(Mandatory)][object[]]$StoreState)
    if ($StoreState.Count -ne 2) { throw 'Expected exactly two machine stores' }
    $seen = @()
    foreach ($entry in $StoreState) {
        if ($entry.exists -isnot [bool]) { throw 'Store existence must be an explicit boolean' }
        if ($entry.store -cnotin $script:Efe8TrustStores -or $seen -ccontains $entry.store) { throw 'Unexpected or duplicate store' }
        $seen += $entry.store
        if ($entry.exists -and $entry.sha256 -cne $script:Efe8TrustCertificateSha256) { throw 'Existing certificate data mismatch' }
        [pscustomobject]@{store=$entry.store;thumbprint=$script:Efe8TrustThumbprint;action=$(if ($entry.exists) {'PreserveExisting'} else {'ProposedAdd'});present_before=[bool]$entry.exists}
    }
}

function Get-Efe8OwnedTrustRemoval {
    param([Parameter(Mandatory)]$Receipt)
    if ($Receipt.schema -ne 1 -or $Receipt.certificate_thumbprint -cne $script:Efe8TrustThumbprint -or $Receipt.certificate_sha256 -cne $script:Efe8TrustCertificateSha256) { throw 'Receipt identity mismatch' }
    if ($Receipt.state -cnotin @('APPLIED','PARTIAL')) { throw 'Only an actual applied/partial receipt may authorize rollback planning' }
    if ($Receipt.entries.Count -ne 2) { throw 'Receipt must contain two stores' }
    $seen = @()
    foreach ($entry in $Receipt.entries) {
        if ($entry.present_before -isnot [bool] -or $entry.added_by_this_operation -isnot [bool]) { throw 'Receipt ownership flags must be explicit booleans' }
        if ($entry.store -cnotin $script:Efe8TrustStores -or $seen -ccontains $entry.store) { throw 'Unexpected or duplicate receipt store' }
        $seen += $entry.store
        if ($entry.present_before -and $entry.added_by_this_operation) { throw 'Cannot claim ownership of preexisting trust' }
        if ($entry.added_by_this_operation -and -not $entry.present_before) {
            [pscustomobject]@{store=$entry.store;thumbprint=$script:Efe8TrustThumbprint;certificate_sha256=$script:Efe8TrustCertificateSha256;action='ProposedRemoveOwnedCertificate'}
        }
    }
}
