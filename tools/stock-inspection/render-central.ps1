param([string]$Version='proposta-v2')
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$project=(Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$out=Join-Path $project "analise-firmware/central-inteligente/$Version"
New-Item -ItemType Directory -Force -Path $out,(Join-Path $out 'boot-frames'),(Join-Path $out 'charger-frames'),(Join-Path $out 'bootloader-battery')|Out-Null
$cyan=[Drawing.ColorTranslator]::FromHtml('#79DAD4')
$white=[Drawing.ColorTranslator]::FromHtml('#EAF0F1')
$muted=[Drawing.ColorTranslator]::FromHtml('#69757A')
function RoundPath([single]$x,[single]$y,[single]$w,[single]$h,[single]$r){
 $p=[Drawing.Drawing2D.GraphicsPath]::new();$d=$r*2
 $p.AddArc($x,$y,$d,$d,180,90);$p.AddArc(($x+$w-$d),$y,$d,$d,270,90)
 $p.AddArc(($x+$w-$d),($y+$h-$d),$d,$d,0,90);$p.AddArc($x,($y+$h-$d),$d,$d,90,90);$p.CloseFigure();return $p
}
function Label($g,[string]$text,[single]$size,[single]$y,$color,[int]$width=600){
 $f=[Drawing.Font]::new('Segoe UI',$size,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
 $brush=[Drawing.SolidBrush]::new($color);$format=[Drawing.StringFormat]::new();$format.Alignment=[Drawing.StringAlignment]::Center
 try{$g.DrawString($text,$f,$brush,[Drawing.RectangleF]::new(0,$y,$width,($size*1.7)),$format)}finally{$f.Dispose();$brush.Dispose();$format.Dispose()}
}
function Mark($g,[single]$x,[single]$y,[single]$scale,[int]$alpha=255){
 $state=$g.Save();$g.TranslateTransform($x,$y);$g.ScaleTransform($scale,$scale)
 $pen=[Drawing.Pen]::new([Drawing.Color]::FromArgb($alpha,$cyan),3.5);$pen.StartCap='Round';$pen.EndCap='Round';$pen.LineJoin='Round'
 try{
  $g.DrawLines($pen,[Drawing.PointF[]]@([Drawing.PointF]::new(-40,-2),[Drawing.PointF]::new(0,-36),[Drawing.PointF]::new(40,-2)))
  $g.DrawLines($pen,[Drawing.PointF[]]@([Drawing.PointF]::new(-29,-3),[Drawing.PointF]::new(-29,33),[Drawing.PointF]::new(29,33),[Drawing.PointF]::new(29,-3)))
  foreach($dx in @(-8,8)){foreach($dy in @(2,18)){$path=RoundPath ($dx-4) ($dy-4) 8 8 2;$g.DrawPath($pen,$path);$path.Dispose()}}
 }finally{$pen.Dispose();$g.Restore($state)}
}
function Surface([int]$w,[int]$h){
 $b=[Drawing.Bitmap]::new($w,$h,[Drawing.Imaging.PixelFormat]::Format24bppRgb)
 $g=[Drawing.Graphics]::FromImage($b);$g.SmoothingMode='AntiAlias';$g.TextRenderingHint='AntiAliasGridFit';$g.Clear([Drawing.Color]::Black)
 return @($b,$g)
}
function SaveSurface($pair,[string]$path){try{$pair[0].Save($path,[Drawing.Imaging.ImageFormat]::Png)}finally{$pair[1].Dispose();$pair[0].Dispose()}}
function Brand($g,[int]$alpha=255){Mark $g 300 437 1.1 $alpha;Label $g 'CENTRAL INTELIGENTE' 27 520 $white;Label $g 'SUA CASA, EM UM SÓ LUGAR' 12 566 $muted}
$p=Surface 600 1024;Brand $p[1];Label $p[1] 'powered by Android' 12 948 $muted;SaveSurface $p (Join-Path $out 'splash-retrato.png')
$p=Surface 600 1024;Brand $p[1];SaveSurface $p (Join-Path $out 'boot-base.png')
function LevelColor([double]$level){
 $stops=@(@(0.0,232,100,105),@(0.3,230,159,82),@(0.55,215,194,91),@(1.0,104,207,154))
 for($n=1;$n -lt $stops.Count;$n++){
  if($level -le $stops[$n][0]){$a=$stops[$n-1];$b=$stops[$n];$t=($level-$a[0])/($b[0]-$a[0]);return [Drawing.Color]::FromArgb([int]($a[1]+($b[1]-$a[1])*$t),[int]($a[2]+($b[2]-$a[2])*$t),[int]($a[3]+($b[3]-$a[3])*$t))}
 }
 return [Drawing.Color]::FromArgb(104,207,154)
}
function Battery([int]$height,[double]$level,[bool]$failure=$false,[bool]$percent=$true){
 $p=Surface 120 $height;$g=$p[1];$y=[single](($height-128)/2+2)
 $shell=RoundPath 24 $y 72 128 17
 $background=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#080F12'));$g.FillPath($background,$shell);$background.Dispose()
 $pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#9AA9AE'),1.8);$g.DrawPath($pen,$shell);$pen.Dispose();$shell.Dispose()
 $cap=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#74878E'));$path=RoundPath 49 ($y-6) 22 3 1.4;$g.FillPath($cap,$path);$path.Dispose();$cap.Dispose()
 $color=LevelColor $level
 $inside=RoundPath 30 ($y+6) 60 116 12;$saved=$g.Save();$g.SetClip($inside)
 $fillHeight=[single][Math]::Max(4,116*$level)
 $gradient=[Drawing.Drawing2D.LinearGradientBrush]::new([Drawing.RectangleF]::new(30,$y+6,60,116),[Drawing.Color]::FromArgb(220,$color),[Drawing.Color]::FromArgb(155,$color),[single]90)
 $g.FillRectangle($gradient,[single]30,[single]($y+122-$fillHeight),[single]60,$fillHeight)
 $gradient.Dispose();$g.Restore($saved);$inside.Dispose()
 if($percent -and -not $failure){
  # Percentage is drawn at runtime. Use a continuous dark glass window, not an empty cutout.
  $window=RoundPath 31 (($height-28)/2) 58 28 8;$brush=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(218,9,17,20));$g.FillPath($brush,$window);$brush.Dispose();$window.Dispose()
 }
 if($failure){Label $g '!' 25 ([single]($height/2-18)) $color 120}
 return ,$p
}
for($i=0;$i -lt 6;$i++){SaveSurface (Battery 186 ($i/5.0)) (Join-Path $out "charger-frames/frame-$i.png")}
$packed=[Drawing.Bitmap]::new(120,1116,[Drawing.Imaging.PixelFormat]::Format24bppRgb)
try{
 for($frame=0;$frame -lt 6;$frame++){
  $source=[Drawing.Bitmap]::FromFile((Join-Path $out "charger-frames/frame-$frame.png"))
  try{for($y=0;$y -lt 186;$y++){for($x=0;$x -lt 120;$x++){$packed.SetPixel($x,($y*6+$frame),$source.GetPixel($x,$y))}}}finally{$source.Dispose()}
 }
 $packed.Save((Join-Path $out 'battery-scale-packed-rascunho.png'),[Drawing.Imaging.ImageFormat]::Png)
}finally{$packed.Dispose()}
for($i=0;$i -le 10;$i++){SaveSurface (Battery 250 ($i/10.0) $false $false) (Join-Path $out "bootloader-battery/bat$i.png")}
SaveSurface (Battery 186 0 $true) (Join-Path $out 'battery-fail.png')
$p=Surface 600 1024;$small=Battery 186 0.04 $false $false
try{$p[1].DrawImageUnscaled($small[0],240,315)}finally{$small[1].Dispose();$small[0].Dispose()}
Label $p[1] 'BATERIA BAIXA' 24 550 ([Drawing.ColorTranslator]::FromHtml('#E86469'));Label $p[1] 'Conecte o carregador' 18 594 $muted;SaveSurface $p (Join-Path $out 'bateria-baixa-conceito.png')
$p=Surface 512 512;Mark $p[1] 256 256 2.4;SaveSurface $p (Join-Path $out 'icone-app-conceito.png')
$p=Surface 600 1024;$g=$p[1]
$gradient=[Drawing.Drawing2D.LinearGradientBrush]::new([Drawing.Rectangle]::new(0,0,600,1024),[Drawing.ColorTranslator]::FromHtml('#080D10'),[Drawing.ColorTranslator]::FromHtml('#0B181C'),[single]70)
$g.FillRectangle($gradient,0,0,600,1024);$gradient.Dispose()
$pen=[Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#132529'),1)
for($x=-800;$x -lt 1200;$x+=160){$g.DrawLine($pen,$x,1024,($x+800),0)};$pen.Dispose()
Mark $g 300 845 0.55 110;Label $g 'CENTRAL INTELIGENTE' 14 900 ([Drawing.ColorTranslator]::FromHtml('#658184'))
SaveSurface $p (Join-Path $out 'wallpaper.png')
$p=Surface 600 1024;Mark $p[1] 300 875 0.55 120;Label $p[1] 'CENTRAL INTELIGENTE' 14 930 $muted;SaveSurface $p (Join-Path $out 'lockscreen-fundo.png')
# Landscape-oriented BMP files are review candidates, not patched firmware resources.
$bitmap=[Drawing.Bitmap]::FromFile((Join-Path $out 'splash-retrato.png'))
try{
 $bitmap.RotateFlip([Drawing.RotateFlipType]::Rotate270FlipNone)
 foreach($profile in @(@('bootlogo-candidato.bmp',[Drawing.Imaging.PixelFormat]::Format32bppArgb),@('bootlogo-go-candidato.bmp',[Drawing.Imaging.PixelFormat]::Format24bppRgb))){
  $copy=[Drawing.Bitmap]::new(1024,600,$profile[1]);$graphics=[Drawing.Graphics]::FromImage($copy)
  try{$graphics.DrawImageUnscaled($bitmap,0,0);$copy.Save((Join-Path $out $profile[0]),[Drawing.Imaging.ImageFormat]::Bmp)}finally{$graphics.Dispose();$copy.Dispose()}
 }
}finally{$bitmap.Dispose()}
$legacy=Join-Path $out 'splash-painel-1024x600.bmp';if(Test-Path -LiteralPath $legacy){Remove-Item -LiteralPath $legacy}
$p=Surface 600 1024;$image=[Drawing.Bitmap]::FromFile((Join-Path $out 'charger-frames/frame-3.png'))
try{$p[1].DrawImageUnscaled($image,240,419);Label $p[1] '62%' 20 498 $white;SaveSurface $p (Join-Path $out 'carga-preview-percentual-simulado.png')}finally{$image.Dispose()}
$p=Surface 1280 740;$g=$p[1];$g.Clear([Drawing.ColorTranslator]::FromHtml('#11181C'))
Label $g 'CENTRAL INTELIGENTE' 25 28 $white 1280
Label $g 'Revisão 02 · bateria e identidade visual' 15 70 $muted 1280
$cards=@(@('splash-retrato.png','01  SPLASH'),@('bateria-baixa-conceito.png','02  BATERIA BAIXA'),@('carga-preview-percentual-simulado.png','03  CARGA DESLIGADO'),@('wallpaper.png','04  FUNDO PADRÃO'))
for($i=0;$i -lt $cards.Count;$i++){
 $x=40+$i*310;$image=[Drawing.Bitmap]::FromFile((Join-Path $out $cards[$i][0]))
 try{$g.DrawImage($image,[Drawing.Rectangle]::new($x,122,270,461))}finally{$image.Dispose()}
 $font=[Drawing.Font]::new('Segoe UI',14,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel);$brush=[Drawing.SolidBrush]::new($white)
 try{$g.DrawString($cards[$i][1],$font,$brush,[single]$x,[single]609)}finally{$font.Dispose();$brush.Dispose()}
}
Label $g 'Revisão no PC · percentual demonstrativo · nada aplicado à imagem ou ao tablet' 15 685 $muted 1280
SaveSurface $p (Join-Path $out 'PAINEL-DE-PROPOSTAS.png')
Write-Output ('Proposal assets: '+$out)
