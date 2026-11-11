# Desativa (reversivel) os pacotes listados em backup\debloat_log.txt. Uso: .\scripts\debloat.ps1
$pkgs = @(
'com.apkpure.aegon','com.goodev.volume.booster','com.google.android.apps.kids.familylinkhelper','com.google.android.gms.supervision',
'com.google.android.apps.assistant','com.google.android.apps.searchlite','com.google.android.apps.books','com.google.android.apps.photosgo',
'com.google.android.apps.nbu.files','com.google.android.calendar','com.google.android.contacts','com.google.android.deskclock',
'com.google.android.calculator','com.google.android.apps.wellbeing','com.google.android.apps.safetyhub','com.google.android.apps.adm',
'com.google.android.apps.turbo','com.google.android.feedback','com.google.android.gms.location.history','com.google.android.tag',
'com.google.android.marvin.talkback','com.google.android.accessibility.switchaccess','com.google.android.healthconnect.controller',
'com.positivo.fota','com.dajingtech.update','com.softwinner.update','com.softwinner.runin','com.clock.pt1.keeptesting',
'com.softwinner.qrscanner','com.softwinner.camera2','com.softwinner.dragonatt','com.softwinner.timerswitch')
foreach ($p in $pkgs) { adb shell pm disable-user --user 0 $p }
adb shell settings put system sound_effects_enabled 0
adb shell settings put system haptic_feedback_enabled 0
adb shell settings put system dtmf_tone 0
