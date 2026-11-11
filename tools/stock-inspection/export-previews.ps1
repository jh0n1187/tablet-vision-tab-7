$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$project = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$base = Join-Path $project 'analise-firmware/stock-URBR2024101701'
$output = Join-Path $base 'previews'
New-Item -ItemType Directory -Force -Path $output | Out-Null
foreach ($name in @('bootlogo.bmp', 'bootlogo-go.bmp')) {
    $image = [Drawing.Bitmap]::FromFile((Join-Path $base "boot-resource-complete/$name"))
    try {
        $image.RotateFlip([Drawing.RotateFlipType]::Rotate90FlipNone)
        $image.Save((Join-Path $output $name.Replace('.bmp', '-portrait.png')), [Drawing.Imaging.ImageFormat]::Png)
    } finally { $image.Dispose() }
}
$source = [Drawing.Bitmap]::FromFile((Join-Path $base 'erofs-extracted/vendor/etc/res/images/charger/battery_scale.png'))
try {
    if ($source.Width -ne 120 -or $source.Height -ne 1116) {throw 'Unexpected source dimensions'}
    # AOSP minui multi-frame PNG format interlaces rows; it is not a vertical strip.
    for ($frame = 0; $frame -lt 6; $frame++) {
        $image = [Drawing.Bitmap]::new(120,186)
        try {
            for ($y=0; $y -lt 186; $y++) {
                for ($x=0; $x -lt 120; $x++) {
                    $image.SetPixel($x,$y,$source.GetPixel($x,($y*6+$frame)))
                }
            }
            $image.Save((Join-Path $output "charger-$frame.png"),[Drawing.Imaging.ImageFormat]::Png)
        } finally {$image.Dispose()}
    }
} finally {$source.Dispose()}
foreach ($frame in 0..10) {
    $image=[Drawing.Bitmap]::FromFile((Join-Path $base "boot-resource-complete/bat/bat$frame.bmp"))
    try {$image.Save((Join-Path $output "boot-battery-$frame.png"),[Drawing.Imaging.ImageFormat]::Png)}
    finally {$image.Dispose()}
}
