# Reverte o debloat e os ajustes de som. Uso: .\scripts\restore.ps1
Get-Content "$PSScriptRoot\..\backup\debloat_log.txt" | ForEach-Object { ($_ -split ' ')[0] } | Where-Object { $_ } | ForEach-Object { adb shell pm enable $_ }
adb shell settings put system sound_effects_enabled 1
adb shell settings put system haptic_feedback_enabled 1
adb shell settings put system dtmf_tone 1
