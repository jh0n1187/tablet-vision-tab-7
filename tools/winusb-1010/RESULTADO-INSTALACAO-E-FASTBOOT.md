# Driver 1010 instalado — fastboot limitado pelo tablet, Android restaurado

10/11/2026. Autorizados importação do certificado, instalação exclusiva do driver 1010 e uma tentativa de identificação/retorno. Depois, o usuário autorizou avançar com testes e implantação da imagem. **A implantação não foi executada por impedimento técnico de aceitação da firmware; não por falta dessa autorização posterior.**

## Alterações no PC concluídas

- Novo certificado público `F1D9D3825930C5768826BC2274E6C1F047356854` importado somente nas lojas físicas LocalMachine\Root e LocalMachine\TrustedPublisher. Recibo `trust-receipts/import-1010-20261110.json`, estado APPLIED. Chave privada continua ausente.
- SignTool `/pa /c` verificou confiança e participação do INF no catálogo: código 0, um arquivo verificado, zero avisos/erros. Log `validation/trusted-catalog-inf-verification.txt`.
- `homelab-fastboot-1010.inf` registrado como **oem76.inf**, PnPUtil exit 0, sem `/install`, `/subdirs` ou `/reboot`. Na enumeração posterior, o 1010 foi associado automaticamente a oem76.inf/WINUSB, provider Homelab local preparation. Recibo `driver-receipts/stage-1010-20261110.json`.
- Preservados ADB 4EE7, driver EFE8, todos os INFs OEM anteriores e arquivos inbox WinUSB. Só oem76.inf foi acrescentado. Evidências `validation/authorized-install-preservation.json` e `validation/post-fastboot-result.json`.
- A enumeração lógica de CurrentUser\Root/TrustedPublisher também mostra o novo certificado por herança de LocalMachine; não houve importação física em HKCU. Conferido no Registro e registrado em `validation/physical-trust-locations.json`. A [Microsoft documenta essa herança](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/local-machine-and-current-user-certificate-stores).
- Primeira solicitação UAC cancelada antes de criar o helper; a pedido do usuário, reaberta. A segunda elevação concluiu uma única aplicação. Não houve dois instaladores concorrentes.

Nenhuma proteção do Windows foi desativada. O driver foi aceito com as políticas existentes, e a comunicação com o bootloader funcionou; alterar UAC, HVCI, Secure Boot, firewall ou assinatura obrigatória não removeria a restrição que o tablet respondeu.

## Única tentativa executada

Recibo detalhado: `../../analise-firmware/central-inteligente/candidato-v2/fastboot-identificacao-1010-20261110/RESULTADO.json`.

1. Antes: URTSF2025092701, locked/green, ADB 4EE7 OK, central em primeiro plano, LockTask LOCKED e Device Owner confirmados.
2. Emitido **um** `adb reboot bootloader`. O processo no PC atingiu timeout de oito segundos; não foi repetido. O dispositivo efetivamente transitou por 4EE7 → EFE8 → 1010.
3. EFE8 observado somente pelo inventário Windows, sem abrir seus endpoints. Nenhum cliente FEL foi usado.
4. 1010 ficou OK e foi reconhecido pelo fastboot. Foram enviados somente `getvar product`, `getvar unlocked`, `getvar secure` e `getvar version-bootloader`.
5. **As quatro consultas foram recusadas remotamente:** `FAILED (remote: ':secure mode,fastboot limited used')`. Nenhum valor de produto/bloqueio foi retornado. O SDK devolveu exit code 0 apesar do texto FAILED; o relatório classifica a resposta pelo resultado do protocolo, não pelo exit code isolado.
6. Emitido **um** `fastboot reboot`, aceito como `Rebooting OKAY`. Não houve outro reboot, desbloqueio, apagamento, boot/download de imagem, payload ou comando de escrita de partições.
7. Retorno verificado: ADB 1F3A:4EE7 OK, mesma build/propriedades locked/green, processo da central ativo, MainActivity em primeiro plano, `mLockTaskModeState=LOCKED` e Device Owner preservado.

O Android foi restaurado e a tentativa está encerrada. O 1010 permanece apenas como nó histórico associado ao driver, sem estar presente no barramento.

## Consequência para a implantação

O bloqueio observado é do bootloader, que devolveu uma recusa explícita, e não do driver Windows. A informação de locked/green vem das leituras Android; os getvars não confirmaram valores porque foram rejeitados.

As três partições customizadas têm conteúdo e metadados EROFS validados, mas **não correspondem aos descritores AVB assinados pela OEM**. Não há chave privada OEM, desbloqueio suportado efetivamente demonstrado, backup integral validado da firmware atual ou contadores de rollback conhecidos. A base de 2024 é anterior à instalada de 2025.

A autorização de instalar não torna esses arquivos inicializáveis. Gravar candidatos sem uma rota de aceitação e recuperação pode impedir o boot e perder o kiosk/dados. Não foi enviado um flash de teste, não foi usada uma imagem de outro modelo e não se apresentou vbmeta sem assinatura como solução comprovada.

Próximo requisito técnico: rota suportada de desbloqueio/instalação ou pacote modificado autenticado pela fabricante, acompanhados de recuperação e revisão de rollback. A instalação customizada permanece não pronta; repetir consultas ou desativar segurança do Windows não resolve esse requisito.

## Reversão registrada — não aplicada

Agora que houve associação, a reversão do driver deve usar a rota dirigida, não a de pacote nunca associado:

```powershell
& 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-1010\rollback-associated-1010.ps1' -ReceiptPath 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-1010\driver-receipts\stage-1010-20261110.json'
```

Essa chamada é **somente prévia**. Ela exige propriedade do pacote/hash/recibo, Android 4EE7 OK, ausência de 1010 presente e associação exclusivamente ao 1010. A futura aplicação com `-Apply` executaria apenas `pnputil /delete-driver oem76.inf /uninstall`, sem `/force` ou reboot; não toca ADB/EFE8 nem certificados. Prévia real em `validation/associated-rollback-preview.json`.

Depois de remover o pacote, a reversão de confiança continua separada, com `rollback-trust.ps1` e o recibo real de importação. Só as duas entradas adicionadas por essa operação podem ser removidas; o certificado EFE8 e confiança preexistente permanecem. Prévia real em `validation/applied-trust-rollback-preview.json`. Nenhuma reversão foi executada.

O ZIP `homelab-fastboot-1010-preparado.zip` é o snapshot histórico anterior à instalação, não um instalador automático nem a firmware do tablet. Estado operacional atual em `manifest.json` e neste resultado.
