param(
    [Parameter(Mandatory=$true)][ValidateSet('Export','Restore')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$Bundle,
    [string]$ProjectRoot=(Join-Path $PSScriptRoot '../..')
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Security
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$Bundle=[IO.Path]::GetFullPath($Bundle)

function Ask-BackupPassword([bool]$Confirm){
    $form=[Windows.Forms.Form]::new()
    $form.Text='Central Inteligente — chave do backup privado'
    $form.Width=540;$form.Height=260;$form.StartPosition='CenterScreen';$form.TopMost=$true
    $form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false;$form.MinimizeBox=$false
    $label=[Windows.Forms.Label]::new();$label.Left=18;$label.Top=16;$label.Width=490;$label.Height=45
    $label.Text=if($Confirm){'Defina uma senha para proteger as chaves no HD externo. Guarde-a no seu gerenciador de senhas. Não envie pelo chat.'}else{'Informe a senha do pacote privado para restaurar as chaves neste perfil Windows.'}
    $password=[Windows.Forms.TextBox]::new();$password.Left=18;$password.Top=68;$password.Width=490;$password.UseSystemPasswordChar=$true
    $confirmation=[Windows.Forms.TextBox]::new();$confirmation.Left=18;$confirmation.Top=105;$confirmation.Width=490;$confirmation.UseSystemPasswordChar=$true;$confirmation.Visible=$Confirm
    $ok=[Windows.Forms.Button]::new();$ok.Text='Confirmar';$ok.Left=300;$ok.Top=155;$ok.Width=100
    $cancel=[Windows.Forms.Button]::new();$cancel.Text='Cancelar';$cancel.Left=410;$cancel.Top=155;$cancel.Width=100;$cancel.DialogResult='Cancel'
    $ok.Add_Click({
        if($password.Text.Length -lt 12){[Windows.Forms.MessageBox]::Show('Use pelo menos 12 caracteres.') | Out-Null;return}
        if($Confirm -and $password.Text -cne $confirmation.Text){[Windows.Forms.MessageBox]::Show('As senhas não coincidem.') | Out-Null;return}
        $form.DialogResult='OK';$form.Close()
    }.GetNewClosure())
    $form.Controls.AddRange(@($label,$password,$confirmation,$ok,$cancel));$form.AcceptButton=$ok;$form.CancelButton=$cancel
    try{
        if($form.ShowDialog() -ne 'OK'){throw 'Operação cancelada; nenhuma chave exportada/restaurada.'}
        return ,([Text.Encoding]::UTF8.GetBytes($password.Text))
    }finally{$password.Clear();$confirmation.Clear();$form.Dispose()}
}

$passBytes=Ask-BackupPassword ($Mode -eq 'Export')
$key=$null;$plain=$null;$storePass=$null
try{
    if($Mode -eq 'Export'){
        if(Test-Path -LiteralPath $Bundle){throw 'O pacote já existe; não será sobrescrito.'}
        $private=Join-Path $ProjectRoot 'backup/private-signing'
        $storePass=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes((Join-Path $private 'resource-key-password.dpapi')),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        $payload=[ordered]@{
            format=1
            resource_pkcs12=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $private 'central-resources.p12')))
            resource_password=[Convert]::ToBase64String($storePass)
        }
        $adbPrivate=Join-Path $env:USERPROFILE '.android/adbkey'
        $adbPublic=Join-Path $env:USERPROFILE '.android/adbkey.pub'
        if((Test-Path -LiteralPath $adbPrivate) -and (Test-Path -LiteralPath $adbPublic)){
            $payload.adb_private=[Convert]::ToBase64String([IO.File]::ReadAllBytes($adbPrivate))
            $payload.adb_public=[Convert]::ToBase64String([IO.File]::ReadAllBytes($adbPublic))
        }
        $plain=[Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
        $salt=[Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
        $nonce=[Security.Cryptography.RandomNumberGenerator]::GetBytes(12)
        $key=[Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($passBytes,$salt,600000,[Security.Cryptography.HashAlgorithmName]::SHA256,32)
        $cipher=[byte[]]::new($plain.Length);$tag=[byte[]]::new(16)
        $aes=[Security.Cryptography.AesGcm]::new($key,16)
        try{$aes.Encrypt($nonce,$plain,$cipher,$tag)}finally{$aes.Dispose()}
        # Decrypt in memory and check the complete plaintext before saving.
        $check=[byte[]]::new($plain.Length);$aes=[Security.Cryptography.AesGcm]::new($key,16)
        try{$aes.Decrypt($nonce,$cipher,$tag,$check);if(-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($plain,$check)){throw 'Falha na validação criptográfica'}}finally{$aes.Dispose();[Array]::Clear($check,0,$check.Length)}
        $envelope=[ordered]@{format='CentralPrivateKeys-v1';cipher='AES-256-GCM';kdf='PBKDF2-HMAC-SHA256';iterations=600000;salt=[Convert]::ToBase64String($salt);nonce=[Convert]::ToBase64String($nonce);tag=[Convert]::ToBase64String($tag);ciphertext=[Convert]::ToBase64String($cipher)}
        [IO.Directory]::CreateDirectory((Split-Path $Bundle)) | Out-Null
        [IO.File]::WriteAllText($Bundle,($envelope | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
        Write-Output 'Chaves exportadas e descriptografia de retorno validada. Nenhuma senha em texto foi gravada.'
    }else{
        $envelope=Get-Content -LiteralPath $Bundle -Raw | ConvertFrom-Json
        if($envelope.format -ne 'CentralPrivateKeys-v1' -or $envelope.iterations -ne 600000){throw 'Formato de pacote inesperado'}
        $salt=[Convert]::FromBase64String($envelope.salt);$nonce=[Convert]::FromBase64String($envelope.nonce);$tag=[Convert]::FromBase64String($envelope.tag);$cipher=[Convert]::FromBase64String($envelope.ciphertext)
        $key=[Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($passBytes,$salt,600000,[Security.Cryptography.HashAlgorithmName]::SHA256,32)
        $plain=[byte[]]::new($cipher.Length);$aes=[Security.Cryptography.AesGcm]::new($key,16)
        try{$aes.Decrypt($nonce,$cipher,$tag,$plain)}finally{$aes.Dispose()}
        $payload=[Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
        $private=Join-Path $ProjectRoot 'backup/private-signing'
        [IO.Directory]::CreateDirectory($private) | Out-Null
        $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        & icacls $private /inheritance:r /grant:r ('*'+$sid+':(OI)(CI)F') | Out-Null
        if($LASTEXITCODE -ne 0){throw 'Falha ao restringir acesso ao diretório privado'}
        $p12=Join-Path $private 'central-resources.p12';$p12Bytes=[Convert]::FromBase64String($payload.resource_pkcs12)
        if(Test-Path -LiteralPath $p12){if(-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals([IO.File]::ReadAllBytes($p12),$p12Bytes)){throw 'Já existe outra chave de assinatura; não sobrescrever.'}}
        [IO.File]::WriteAllBytes($p12,$p12Bytes)
        $storePass=[Convert]::FromBase64String($payload.resource_password)
        $protected=[Security.Cryptography.ProtectedData]::Protect($storePass,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $private 'resource-key-password.dpapi'),$protected)
        if($payload.adb_private){
            $adb=Join-Path $private 'adb';[IO.Directory]::CreateDirectory($adb) | Out-Null
            foreach($name in @('adbkey','adbkey.pub')){if(Test-Path -LiteralPath (Join-Path $adb $name)){throw 'Chave ADB de backup já existe; inspecione antes de repetir.'}}
            [IO.File]::WriteAllBytes((Join-Path $adb 'adbkey'),[Convert]::FromBase64String($payload.adb_private))
            [IO.File]::WriteAllBytes((Join-Path $adb 'adbkey.pub'),[Convert]::FromBase64String($payload.adb_public))
        }
        Write-Output 'Assinatura restaurada e protegida neste perfil Windows. Chave ADB preservada separadamente; perfil ADB do PC não alterado.'
    }
}finally{
    foreach($buffer in @($passBytes,$key,$plain,$storePass)){if($null -ne $buffer){[Array]::Clear($buffer,0,$buffer.Length)}}
}
