# Pacote EFE8 registrado no Windows — 09/11/2026

> Atualização após uma tentativa efex autorizada: `oem61.inf`/`WINUSB` associados ao EFE8 com instalação Windows bem-sucedida, mas FEL transitório (~133/152 ms); Android/ADB e app homelab retornaram. [Resultado](../../analise-firmware/revisao-fel/capturas/efex-driver-20261109T164143Z/RESULTADO.md). A reversão simples de pacote não associado agora deve parar para revisão de desassociação.

O PnPUtil adicionou com sucesso o pacote assinado `homelab-fel-efe8.inf` ao Driver Store, como **`oem61.inf`**, código de saída **0**. O comando aplicado foi `pnputil /add-driver` com o caminho exato do INF, sem `/install`, `/subdirs` ou `/reboot`.

O pacote corresponde exclusivamente a `USB\VID_1F3A&PID_EFE8`. Como EFE8 estava desconectado, o driver está preparado no PC para a próxima enumeração nesse modo; não houve associação ativa, teste FEL ou abertura de endpoints USB. Essa distinção segue a [documentação do PnPUtil](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax).

## Evidências

- [Recibo da aplicação](driver-receipts/stage-20261109T161225Z.json): estado `STAGED`, nome publicado, hash, inventário anterior/posterior e saída do PnPUtil.
- [Comparação dos inventários](validation/driver-install-results.json): apenas `oem61.inf` acrescentado; nenhum OEM anterior alterado ou removido.
- ADB `4EE7` permanece presente e `OK`, `winusb.inf`, `WINUSB`, Microsoft, versão `10.0.26100.9549`; GUID e parâmetros idênticos ao inventário anterior.
- Nó EFE8 histórico permanece desconectado e sem associação. WinUSB.sys e winusb.inf preservados por hash; lojas de certificados preservadas.
- Catálogo/INF confiáveis antes da aplicação; pacote aceito pelo Windows sem contornar políticas.
- Nenhum comando enviado ao tablet, reinício, payload ou acesso ao armazenamento. Nenhuma proteção do Windows alterada.

## Reversão registrada — não executada

A [prévia de reversão](validation/driver-rollback-preview.json) confirmou o comando exato e zero dispositivos associados, sem remover o pacote. O script `rollback-staged-driver.ps1` verifica recibo, nome OEM, SHA-256 e ausência de dispositivos associados; sem `-Apply`, apenas mostra a prévia. A remoção exata equivale a `pnputil /delete-driver oem61.inf`, sem `/force`, `/uninstall` ou `/reboot`.

Para futura reversão autorizada, em PowerShell como administrador:

```powershell
& 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-efe8\rollback-staged-driver.ps1' -ReceiptPath 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-efe8\driver-receipts\stage-20261109T161225Z.json' -Apply
```

Se o pacote já estiver associado a um dispositivo, o script para para revisão da desinstalação dirigida. Não remove o WinUSB da Microsoft nem o certificado de confiança. A reversão dos certificados permanece separada e documentada em [RESULTADO-CONFIANCA.md](RESULTADO-CONFIANCA.md).

## Próxima etapa

Uma nova entrada em FEL e a verificação do EFE8 ativo dependem de autorização própria. O registro do pacote não comprova que o modo permanecerá ativo ou que a extração será possível. Payload continua fora do escopo e desabilitado na ferramenta de leitura.
