$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$root=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$base=Join-Path $root 'analise-firmware/central-inteligente'
$approved=Join-Path $base 'aprovado-v2'
$templates=Join-Path $base 'aviso-boot/recursos-v3'
$output=Join-Path $base 'carga-fallback/replacement/bat'
if(Test-Path -LiteralPath $output){throw 'Inspect existing preparation before repeating'}
New-Item -ItemType Directory -Path $output -Force | Out-Null
function Convert-NativeBmp([string]$source,[string]$name,[bool]$rotate=$false){
    $raw=[IO.File]::ReadAllBytes((Join-Path $templates ('bat/'+$name)))
    $offset=[BitConverter]::ToUInt32($raw,10);$width=[BitConverter]::ToInt32($raw,18);$height=[BitConverter]::ToInt32($raw,22)
    if([BitConverter]::ToUInt16($raw,28) -ne 24 -or [BitConverter]::ToUInt32($raw,30) -ne 0){throw 'Unsupported native BMP'}
    $stride=[int]([Math]::Ceiling($width*3/4)*4)
    if($raw.Length -ne $offset+$stride*$height){throw 'Unexpected BMP size'}
    $image=[Drawing.Bitmap]::FromFile($source)
    $render=[Drawing.Bitmap]::new($width,$height)
    $g=[Drawing.Graphics]::FromImage($render)
    try{
        if($rotate){$image.RotateFlip([Drawing.RotateFlipType]::Rotate270FlipNone)}
        $g.Clear([Drawing.Color]::Black)
        $scale=[Math]::Min($width/$image.Width,$height/$image.Height)
        $w=[single]($image.Width*$scale);$h=[single]($image.Height*$scale)
        $g.InterpolationMode='HighQualityBicubic'
        if($image.Width -eq $width -and $image.Height -eq $height){$g.DrawImageUnscaled($image,0,0)}else{$g.DrawImage($image,[Drawing.RectangleF]::new(($width-$w)/2,($height-$h)/2,$w,$h))}
        for($y=0;$y -lt $height;$y++){for($x=0;$x -lt $width;$x++){
            $c=$render.GetPixel($x,$y);$p=$offset+($height-1-$y)*$stride+$x*3
            $raw[$p]=$c.B;$raw[$p+1]=$c.G;$raw[$p+2]=$c.R
        }}
        [IO.File]::WriteAllBytes((Join-Path $output $name),$raw)
        # Preview as physically oriented on this portrait-mounted panel.
        if($rotate){$render.RotateFlip([Drawing.RotateFlipType]::Rotate90FlipNone)}
        $render.Save((Join-Path (Split-Path $output) ($name+'.png')),[Drawing.Imaging.ImageFormat]::Png)
    }finally{$g.Dispose();$render.Dispose();$image.Dispose()}
}
Convert-NativeBmp (Join-Path $approved 'charger-frames/frame-0.png') 'battery_charge.bmp' $true
Convert-NativeBmp (Join-Path $approved 'bootloader-battery/bat10.png') 'battery.bmp'
Convert-NativeBmp (Join-Path $approved 'bootloader-battery/bat0.png') 'bempty.bmp'
Convert-NativeBmp (Join-Path $templates 'bootlogo.bmp') 'bootlogo.bmp'
Write-Output 'Four static fallback resources prepared; native BMP headers and sizes preserved.'
