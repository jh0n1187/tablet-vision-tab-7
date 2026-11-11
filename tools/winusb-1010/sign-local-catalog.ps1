# Default: preview only. -Apply requires explicit user approval for temporary My certificate.
# Never imports trust, installs drivers, changes Windows protections or accesses tablet USB.
[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$inf = Join-Path $root 'package\homelab-fastboot-1010.inf'
$cat = Join-Path $root 'package\homelab-fastboot-1010.cat'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$plan = [ordered]@{
    target=$cat
    temporary_store='CurrentUser\My'
    subject='CN=Homelab Fastboot 1010 Local Package'
    key='RSA 3072, SHA256, non-exportable; deleted after signing'
    validity_days=30
    trust_root_import=$false
    trusted_publisher_import=$false
    test_signing_or_protection_changes=$false
    driver_installation=$false
    tablet_reboot=$false
    output_trusted_for_installation=$false
}
if (-not $Apply) { $plan | ConvertTo-Json; return }
if ((Get-FileHash -LiteralPath $inf -Algorithm SHA256).Hash -ne '989F050A19ACF2DB917F228BA4761150D01F298D222CC11F3CE82C9F3FE05A13') { throw 'INF differs from reviewed version' }
if (-not (Test-Path -LiteralPath $cat)) { throw 'Catalog missing' }
if ((Get-AuthenticodeSignature -LiteralPath $cat).Status -ne 'NotSigned') { throw 'Catalog must be unsigned before this one-time operation' }
$signtoolSignature = Get-AuthenticodeSignature -LiteralPath $signtool
if ($signtoolSignature.Status -ne 'Valid' -or $signtoolSignature.SignerCertificate.Subject -notlike '*Microsoft Corporation*') { throw 'SignTool not validated' }
$out = Join-Path $root 'signing'
if (Test-Path -LiteralPath $out) { throw 'Signing output already exists; do not overwrite evidence' }
$null = New-Item -ItemType Directory -Path $out
Copy-Item -LiteralPath $cat -Destination (Join-Path $out 'homelab-fastboot-1010.unsigned.cat')
$beforeThumbprints = @(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint)
$beforeThumbprints | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $out 'my-before.json') -Encoding utf8
$thumb = $null
$keyName = $null
$result = [ordered]@{plan=$plan;original_catalog_sha256=(Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash;certificate_created=$false;certificate_and_key_removed=$false;crypto_signature_verified=$false;trusted_for_installation=$false}
try {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject $plan.subject -CertStoreLocation Cert:\CurrentUser\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -Provider 'Microsoft Software Key Storage Provider' -NotAfter (Get-Date).AddDays(30)
    $thumb = $certificate.Thumbprint
    $result.certificate_created = $true
    if ($thumb -notmatch '^[0-9A-F]{40}$' -or $beforeThumbprints -contains $thumb) { throw 'New certificate identity not unique; stop' }
    $result['certificate_subject'] = $certificate.Subject
    $result['certificate_thumbprint'] = $thumb
    $result['certificate_not_after_utc'] = $certificate.NotAfter.ToUniversalTime().ToString('o')
    $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    try {
        if ($privateKey -isnot [System.Security.Cryptography.RSACng] -or $privateKey.Key.IsMachineKey) { throw 'Expected user CNG key not found' }
        $keyName = $privateKey.Key.KeyName
    } finally { $privateKey.Dispose() }
    Export-Certificate -Cert $certificate -FilePath (Join-Path $out 'homelab-fastboot-1010-public.cer') -Type CERT | Out-Null
    & $signtool sign /fd SHA256 /s My /sha1 $thumb /v $cat 2>&1 | Tee-Object -FilePath (Join-Path $out 'sign-output.txt')
    if ($LASTEXITCODE -ne 0) { throw 'SignTool signing failed' }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -AssemblyName System.Security } else { Add-Type -AssemblyName System.Security.Cryptography.Pkcs }
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode([IO.File]::ReadAllBytes($cat))
    # Cryptographic signature only, explicitly not Windows trust validation.
    $cms.CheckSignature($true)
    $result.crypto_signature_verified = $true
    $result['signed_catalog_sha256'] = (Get-FileHash -LiteralPath $cat -Algorithm SHA256).Hash
    $result['windows_signature_status'] = (Get-AuthenticodeSignature -LiteralPath $cat).Status.ToString()
} finally {
    if ($null -ne $certificate) { $certificate.Dispose() }
    if ($thumb -and $thumb -match '^[0-9A-F]{40}$' -and $beforeThumbprints -notcontains $thumb) {
        $certificatePath = 'Cert:\CurrentUser\My\'+$thumb
        if (Test-Path -LiteralPath $certificatePath) {
            $current = Get-Item -LiteralPath $certificatePath
            if ($current.Subject -ne $plan.subject) { throw 'Certificate identity changed; cleanup stopped' }
            Remove-Item -LiteralPath $certificatePath -DeleteKey
        }
        $keyStillExists = if ($keyName) { [System.Security.Cryptography.CngKey]::Exists($keyName,[System.Security.Cryptography.CngProvider]::new('Microsoft Software Key Storage Provider'),[System.Security.Cryptography.CngKeyOpenOptions]::None) } else { $true }
        $result.certificate_and_key_removed = (-not (Test-Path -LiteralPath $certificatePath)) -and (-not $keyStillExists)
    }
    $afterThumbprints = @(Get-ChildItem Cert:\CurrentUser\My | Select-Object -ExpandProperty Thumbprint)
    $result['my_store_restored'] = ((@($beforeThumbprints | Sort-Object) -join ',') -eq (@($afterThumbprints | Sort-Object) -join ','))
    $result | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $out 'result.json') -Encoding utf8
}
if (-not $result.certificate_and_key_removed -or -not $result.my_store_restored) { throw 'Temporary certificate/key cleanup not confirmed; inspect signing/result.json' }
$result | ConvertTo-Json -Depth 7
