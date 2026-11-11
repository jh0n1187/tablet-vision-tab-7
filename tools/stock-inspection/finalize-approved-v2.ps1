$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$project=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$base=Join-Path $project 'analise-firmware/central-inteligente'
$source=Join-Path $base 'proposta-v2'
$approved=Join-Path $base 'aprovado-v2'
if(Test-Path -LiteralPath $approved){throw 'Approved snapshot already exists; do not overwrite it'}
$manifest=Get-Content (Join-Path $source 'manifest.json') -Raw|ConvertFrom-Json
foreach($entry in $manifest.files){
 $path=Join-Path $source $entry.file
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() -ne $entry.sha256){throw ('Proposal changed since review: '+$entry.file)}
}
Copy-Item -LiteralPath $source -Destination $approved -Recurse
$resources=Join-Path $approved 'recursos-nativos'
$boot=Join-Path $resources 'boot-resource'
$stock=Join-Path $project 'analise-firmware/stock-URBR2024101701/boot-resource-complete'
New-Item -ItemType Directory -Path (Join-Path $boot 'bat'),(Join-Path $resources 'system/media'),(Join-Path $resources 'vendor/etc/res/images/charger'),(Join-Path $resources 'vendor/etc/res/values/charger'),(Join-Path $resources 'fundos') -Force|Out-Null

function NativeBmp([string]$png,[string]$template,[string]$destination,[bool]$fit=$false){
 $raw=[IO.File]::ReadAllBytes($template)
 $offset=[BitConverter]::ToUInt32($raw,10);$width=[BitConverter]::ToInt32($raw,18);$height=[BitConverter]::ToInt32($raw,22);$bpp=[BitConverter]::ToUInt16($raw,28)
 if($width -le 0 -or $height -le 0 -or $bpp -notin @(24,32) -or [BitConverter]::ToUInt32($raw,30) -ne 0){throw 'Unsupported BMP template'}
 $image=[Drawing.Bitmap]::FromFile($png);$render=[Drawing.Bitmap]::new($width,$height);$g=[Drawing.Graphics]::FromImage($render)
 try{
  $g.Clear([Drawing.Color]::Black)
  if($fit){
   $scale=[Math]::Min($width/$image.Width,$height/$image.Height);$w=[single]($image.Width*$scale);$h=[single]($image.Height*$scale)
   $g.InterpolationMode='HighQualityBicubic';$g.DrawImage($image,[Drawing.RectangleF]::new(($width-$w)/2,($height-$h)/2,$w,$h))
  }else{
   if($image.Width -ne $width -or $image.Height -ne $height){throw 'BMP geometry mismatch'}
   $g.DrawImageUnscaled($image,0,0)
  }
  $pixelBytes=[int]($bpp/8);$stride=[int]([Math]::Ceiling($width*$pixelBytes/4)*4)
  if($raw.Length -ne $offset+$stride*$height){throw 'Unexpected BMP payload length'}
  # Retain the complete original DIB/header, dimensions and color-space metadata.
  for($y=0;$y -lt $height;$y++){for($x=0;$x -lt $width;$x++){
   $c=$render.GetPixel($x,$y);$p=$offset+($height-1-$y)*$stride+$x*$pixelBytes
   $raw[$p]=$c.B;$raw[$p+1]=$c.G;$raw[$p+2]=$c.R;if($pixelBytes -eq 4){$raw[$p+3]=255}
  }}
  [IO.File]::WriteAllBytes($destination,$raw)
 }finally{$g.Dispose();$render.Dispose();$image.Dispose()}
}
NativeBmp (Join-Path $approved 'bootlogo-candidato.bmp') (Join-Path $stock 'bootlogo.bmp') (Join-Path $boot 'bootlogo.bmp')
NativeBmp (Join-Path $approved 'bootlogo-go-candidato.bmp') (Join-Path $stock 'bootlogo-go.bmp') (Join-Path $boot 'bootlogo-go.bmp')
foreach($i in 0..10){NativeBmp (Join-Path $approved "bootloader-battery/bat$i.png") (Join-Path $stock "bat/bat$i.bmp") (Join-Path $boot "bat/bat$i.bmp")}
NativeBmp (Join-Path $approved 'bateria-baixa-conceito.png') (Join-Path $stock 'bat/low_pwr.bmp') (Join-Path $boot 'bat/low_pwr.bmp') $true
Copy-Item -LiteralPath (Join-Path $approved 'bootanimation-RASCUNHO-NAO-INSTALAR.zip') -Destination (Join-Path $resources 'system/media/bootanimation.zip')
Copy-Item -LiteralPath (Join-Path $approved 'bootanimation-RASCUNHO-NAO-INSTALAR.zip') -Destination (Join-Path $resources 'system/media/bootanimation_dark.zip')
Copy-Item -LiteralPath (Join-Path $approved 'battery_scale-RASCUNHO.png') -Destination (Join-Path $resources 'vendor/etc/res/images/charger/battery_scale.png')
Copy-Item -LiteralPath (Join-Path $approved 'battery-fail.png') -Destination (Join-Path $resources 'vendor/etc/res/images/charger/battery_fail.png')
Copy-Item -LiteralPath (Join-Path $approved 'animation-RASCUNHO.txt') -Destination (Join-Path $resources 'vendor/etc/res/values/charger/animation.txt')
Copy-Item -LiteralPath (Join-Path $approved 'wallpaper.png') -Destination (Join-Path $resources 'fundos/wallpaper.png')
Copy-Item -LiteralPath (Join-Path $approved 'lockscreen-fundo.png') -Destination (Join-Path $resources 'fundos/lockscreen.png')
[ordered]@{visual_approved=$true;user_message='agora sim, vamos com essa versao';client_date='2026-11-09';revision='proposta-v2';snapshot='aprovado-v2';flash_ready=$false;device_write_performed=$false;scope='Approved visual resources; installation still requires technical validation'}|ConvertTo-Json|Set-Content -Encoding utf8 (Join-Path $approved 'APROVACAO-VISUAL.json')
Write-Output ('Approved snapshot and native resources: '+$approved)
