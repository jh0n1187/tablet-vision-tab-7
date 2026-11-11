param([Parameter(Mandatory=$true)][string]$Video,[Parameter(Mandatory=$true)][string]$Output,[double]$From=-1,[double]$To=0,[double]$Step=0.1)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null=[Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.MediaClip,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.MediaComposition,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.VideoFramePrecision,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Graphics.Imaging.ImageStream,Windows.Graphics.Imaging,ContentType=WindowsRuntime]
function Await-WinRT($Operation,[Type]$ResultType){
    $method=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    $task=$method.MakeGenericMethod($ResultType).Invoke($null,@($Operation))
    $task.GetAwaiter().GetResult()
}
$source=Await-WinRT ([Windows.Storage.StorageFile]::GetFileFromPathAsync($Video)) ([Windows.Storage.StorageFile])
$clip=Await-WinRT ([Windows.Media.Editing.MediaClip]::CreateFromFileAsync($source)) ([Windows.Media.Editing.MediaClip])
$composition=New-Object Windows.Media.Editing.MediaComposition
[System.Collections.Generic.ICollection[Windows.Media.Editing.MediaClip]].GetMethod('Add').Invoke($composition.Clips,@($clip))
New-Item -ItemType Directory -Path $Output -Force | Out-Null
Write-Output ('Duration: '+$clip.OriginalDuration.TotalSeconds)
$times=@(0,0.5,1,2,3,4,5,6,8,10,10.2,10.4,10.6,10.8,11,11.1,11.2,11.3,11.4,11.5,11.6,11.7,11.8,11.9,12,12.2,15,20,25)
if($From -ge 0){if($Step -le 0 -or $To -lt $From){throw 'Invalid frame interval'};$times=@();for($t=$From;$t -le $To+0.0001;$t+=$Step){$times += [Math]::Round($t,3)}}
foreach($seconds in $times){
    if($seconds -ge $clip.OriginalDuration.TotalSeconds){continue}
    $thumbnail=Await-WinRT ($composition.GetThumbnailAsync([TimeSpan]::FromSeconds($seconds),600,1024,[Windows.Media.Editing.VideoFramePrecision]::NearestFrame)) ([Windows.Graphics.Imaging.ImageStream])
    $stream=[System.IO.WindowsRuntimeStreamExtensions]::AsStreamForRead($thumbnail)
    $file=[System.IO.File]::Create((Join-Path $Output ('frame-'+$seconds+'.jpg')))
    try{$stream.CopyTo($file)}finally{$file.Dispose();$stream.Dispose();$thumbnail.Dispose()}
}
