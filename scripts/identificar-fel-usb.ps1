# Consulta apenas o inventario PnP do Windows. Nao abre endpoints USB.
# Nao usa ADB/xfel, nao instala driver e nao carrega payload.
[CmdletBinding()]
param(
    # Exclusivamente para testes no PC com um inventario sintetico.
    [string]$InventarioSimulado
)
$ErrorActionPreference = 'Stop'

if ($InventarioSimulado) {
    $dispositivos = @(Get-Content -LiteralPath $InventarioSimulado -Raw | ConvertFrom-Json)
} else {
    $dispositivos = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
}

$alvos = @($dispositivos | Where-Object {
    $_.InstanceId -match '^USB\\VID_1F3A&PID_[0-9A-F]{4}(&|\\)'
})

if ($alvos.Count -eq 0) {
    Write-Output 'Nenhum dispositivo USB Allwinner (VID 1F3A) presente no inventario. Isso nao comprova que o tablet esteja desligado.'
    return
}

foreach ($dispositivo in $alvos) {
    $null = $dispositivo.InstanceId -match '^USB\\VID_1F3A&PID_([0-9A-F]{4})'
    $pidDispositivo = $Matches[1].ToUpperInvariant()
    $modo = switch ($pidDispositivo) {
        'EFE8' { 'Candidato a FEL BootROM; falta resposta VERSION para confirmar SoC/protocolo' }
        '4EE7' { 'Compativel com Android/ADB observado no T307F; nao e o FEL BootROM esperado' }
        '1010' { 'Modo diferente do FEL BootROM esperado; parar e sair sem consulta de protocolo' }
        default { 'PID nao previsto; parar e sair sem consulta de protocolo' }
    }
    [PSCustomObject]@{
        VID = '1F3A'
        PID = $pidDispositivo
        Status = $dispositivo.Status
        Nome = $dispositivo.FriendlyName
        Avaliacao = $modo
    }
}

# Interfaces de um dispositivo composto podem gerar varias linhas; nao
# selecionar uma automaticamente nem interpretar linhas como unidades fisicas.
Write-Output 'Somente metadados PnP foram consultados; nenhum endpoint USB foi aberto.'
