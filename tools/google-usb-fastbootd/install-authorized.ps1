if(-not $env:T307F_SERIAL){throw 'Defina T307F_SERIAL antes de acessar o tablet'}
$ErrorActionPreference = 'Stop'
$taskRoot = 'C:\Users\Jonathan\projetos\tablet-positivo\tools\google-usb-fastbootd'
$target = ('USB\VID_18D1&PID_4EE0\' + $env:T307F_SERIAL)
$dev = Get-PnpDevice -InstanceId $target -PresentOnly
$signature = Get-AuthenticodeSignature "$taskRoot\package\usb_driver\androidwinusba64.cat"
if ($signature.Status -ne 'Valid') { throw 'Catalog signature invalid' }
$output = & pnputil /add-driver "$taskRoot\package\usb_driver\android_winusb.inf" /install 2>&1
$code = $LASTEXITCODE
@{target=$target;exit_code=$code;output=@($output | ForEach-Object {[string]$_});utc=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$taskRoot\install-receipt.json" -Encoding utf8
