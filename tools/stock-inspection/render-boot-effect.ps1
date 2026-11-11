param([string]$Version='proposta-v2')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -Path (Join-Path $PSScriptRoot 'render-boot-effect.cs') -ReferencedAssemblies 'System.Drawing','System.IO.Compression','System.IO.Compression.FileSystem','System.Core'
$project=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$proposal=Join-Path $project "analise-firmware/central-inteligente/$Version"
$reference=Join-Path $project 'analise-firmware/stock-URBR2024101701/erofs-extracted/system/system/media/bootanimation.zip'
[CentralBootEffect]::Render($reference,(Join-Path $proposal 'boot-base.png'),(Join-Path $proposal 'boot-frames'))
Write-Output '167 frames rendered from the reference reveal envelope; no loading dots.'
