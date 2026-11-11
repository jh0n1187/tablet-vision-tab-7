# usbipd-win: pacote, compatibilidade e reversão preparados

09/11/2026. **Nada instalado ou reiniciado.** Nenhum msiexec, executável extraído, bind, attach, comando ADB, payload ou consulta FEL executado. Somente download, leitura do banco MSI em modo 0, extração do CAB, verificações criptográficas/estáticas e testes do planejador. O NUC não foi acessado nesta etapa.

## Resultado e limite de compatibilidade

O pacote oficial x64 **5.3.0** foi verificado. O MSI e as assinaturas dos componentes passaram nas verificações adequadas descritas abaixo. Este Windows atende aos pré-requisitos publicados, mas **compatibilidade operacional/HVCI ainda não foi comprovada neste PC**. Há um relato aberto no próprio projeto sobre BSOD com VBoxUSBMon 7.2.2 em Windows 11, exatamente a família de driver incluída nesta release. É um relato de usuário, não diagnóstico de falha neste host. O mantenedor respondeu sobre a evolução dos drivers e futura substituição; não há nessa discussão garantia de correção para este pacote. [Issue oficial #1487](https://github.com/dorssel/usbipd-win/issues/1487).

Recomendação: considerar esta entrega uma preparação revisável, **não uma liberação automática para instalação no PC principal**. O risco de driver de kernel não desaparece por usar Docker. Não substituir pelo build de desenvolvimento, instalar certificados ou reduzir proteções para contornar eventual bloqueio.

## Origem e integridade

Na consulta, o endpoint oficial `releases/latest` retornou **v5.3.0**, publicada em **11/10/2025** — não confundir com a data de revisão deste documento. [Release oficial](https://github.com/dorssel/usbipd-win/releases/tag/v5.3.0), [metadados salvos](evidence/official-release.json).

Arquivo baixado diretamente do asset oficial:

```text
usbipd-win_5.3.0_x64.msi
4.501.504 bytes
SHA-256: 1c984914aec944de19b64eff232421439629699f8138e3ddc29301175bc6d938
```

O hash corresponde ao campo `digest` publicado pelo GitHub para esse asset. Authenticode do MSI: **Valid**, signatário Open Source Developer, Frans van Dorsselaer, certificado `30EC478E9FEC6174D949FFF5C00EC028A7D2E8F9`, timestamp Certum. SignTool `/pa /v`: código 0. [Evidência](evidence/msi-authenticode.json), [SignTool](evidence/installer-signtool.txt).

O MSI foi aberto com `MsiOpenDatabaseW` somente leitura e consultas SELECT. Seu CAB incorporado foi extraído com `MsiRecordReadStream`; os 13 nomes foram conferidos contra a tabela File e limitados a nomes simples antes da expansão. Não houve instalação administrativa `/a`, sessão de instalação ou execução de custom actions. [Leitor utilizado](inspect_msi.py), [tabelas MSI](msi/tables.json), [lista do CAB](evidence/cabinet-list.txt).

## Assinaturas dos componentes

Os drivers extraídos do próprio MSI são **Oracle/VirtualBox 7.2.2.170484**. O fonte/licenciamento conferido é o da tag **v5.3.0**, não o master atual que pode conter outra versão. [Proveniência do driver](sources/Drivers/README.md).

| Componente | Resultado |
|---|---|
| usbipd.exe e Usbipd.PowerShell.dll | Authenticode Valid, Frans van Dorsselaer; não executados |
| VBoxUSB.cat | Authenticode Valid; Microsoft Windows Hardware Compatibility Publisher |
| VBoxUSB.sys + VBoxUSB.inf | Hashes conferidos pelo catálogo; SignTool `/kp /c` código 0 e política de driver com alvo `2:10.0.26200` código 0 |
| VBoxUSBMon.sys | Duas assinaturas incorporadas: Oracle e Microsoft; `/pa /all` código 0, ambas válidas; política Windows Driver selecionando índice Microsoft 1 (`/ds 1`) código 0 |

[Assinaturas/hashes](evidence/payload-signatures.json), [catálogo/kernel](evidence/driver-catalog-kernel.txt), [alvo build 26200](evidence/driver-policy-target.txt), [assinaturas do monitor](evidence/monitor-authenticode-all.txt), [política de driver do monitor](evidence/monitor-driver-policy-index1.txt).

**Limitação do teste `/kp` do monitor:** a invocação padrão selecionou a assinatura primária Oracle e falhou por não encadear a uma raiz Microsoft. O arquivo tem uma segunda assinatura Microsoft válida, verificada separadamente. O SDK rejeita combinar `/kp` com `/ds`, `/all` ou `/ms`; essas recusas de opções não são rejeições do driver. O catálogo VBoxUSB não cobre o monitor. Não foi alterado o arquivo para trocar assinaturas, nem afirmado que houve carregamento de kernel bem-sucedido. O resultado isolado da primeira assinatura não deve ser apresentado como prova de incompatibilidade do arquivo inteiro. [Diagnóstico consolidado](evidence/review-summary.json), [documentação SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).

## Este Windows e estado anterior

Windows **11 25H2 x64, 26200.9711**, VBS em execução e `SecurityServicesRunning=[2]` (HVCI). Os requisitos oficiais incluem Windows x64/ARM64 e a documentação Microsoft para WSL exige Windows 11 e kernel WSL ≥ 5.10.60.1; o Docker local usa WSL2 6.18.33.2. Atender a esses mínimos não homologa o cenário EFE8 transitório. [README da release](sources/README.md), [Microsoft WSL USB](https://learn.microsoft.com/en-us/windows/wsl/connect-usb).

Os dois drivers são AMD64/PE32+, alinhamento 4096, NX_COMPAT e sem seções simultaneamente graváveis/executáveis. São indicadores estáticos favoráveis; não substituem validação de HVCI/runtime, HLK ou um ensaio controlado. Nenhum driver foi carregado ou Driver Verifier ativado. [PE](evidence/driver-pe-check.json).

Não há serviço usbipd/usbipd-win, driver VBox*, regra de firewall usbipd, pasta padrão, chave de produto ou INF OEM correspondente no inventário. Não há instalação VirtualBox detectada por esses recursos. Se isso mudar antes de uma instalação futura, interromper e revisar conflito/upgrade, sem remover componentes de outro programa. [Antes](evidence/host-before.json), [depois](evidence/host-after.json).

## Alterações que uma instalação faria

| Alvo | Efeito do pacote revisado |
|---|---|
| Arquivos | Programa por máquina em Program Files/usbipd-win, drivers, módulo PowerShell, dados USB e ferramentas WSL |
| PATH da máquina | Acrescenta a pasta de instalação; não substituir o PATH completo |
| Driver Store | Publica VBoxUSB.inf; o nome `oemNN.inf` só será conhecido depois. O INF casa USB\VID_80EE&PID_CAFE; não casa diretamente o ADB 1F3A:4EE7 |
| VBoxUSBMon | Cria serviço de kernel demand-start; o MSI para/remove eventual instância antiga e a recria, motivo para recusar coexistência não revisada |
| usbipd | Serviço automático, por padrão LocalSystem, argumento `server`, dependente de VBoxUSBMon. A instalação tenta iniciá-lo; isso pode carregar o monitor já durante a instalação |
| Firewall | Regra de entrada **usbipd**, programa usbipd.exe, **TCP 3240**, **todos os perfis**, origem **LocalSubnet** |
| Registro/eventos | HKLM\SOFTWARE\usbipd-win, localização/versão e chaves Devices/Policy; registro MSI e fontes de eventos |
| ACL específica | Custom action nega execução do README de WSL; não altera permissões globais do Windows |

A tabela MSI e o fonte mostram custom actions para staging do driver, criação do monitor, limpeza de drivers antigos/stubs e atualização de dispositivos previamente force-bound. O estado atual não contém esses recursos. Não há modificação UpperFilters/LowerFilters da classe USB no INF/tabelas/fontes de instalação revisados, e o planejamento não propõe editá-los. Isso não torna o monitor de kernel isolado ao EFE8 nem garante ausência de impacto em outros USB. [Fonte Server.wxs](sources/Installer/Server.wxs), [ações em C#](sources/Usbipd/CommandHandlersInstaller.cs), [firewall MSI](evidence/firewall-table.json).

**Preservação do ADB:** não executar bind/attach/force/policy para 4EE7, não remover winusb.inf/WinUSB.sys ou INFs preexistentes, não instalar driver genérico para o tablet. A instalação não compartilha dispositivos por padrão; compartilhamento e attach são etapas distintas. Nenhuma delas está no plano executável desta entrega.

## Plano de instalação futura — somente prévia

[Prévia concreta em JSON](evidence/installation-rollback-preview.json), gerada por [plan.py](plan.py). Não há opção Apply, subprocesso ou API de alteração de sistema no planejador.

1. Rever o relato de BSOD e a compatibilidade operacional ainda pendente. Não tratar origem/assinatura como garantia de estabilidade. Deixar o tablet desconectado para uma eventual instalação, mantendo todos os gates bloqueados.
2. Refazer inventários e comparar o estado atual. Parar se existir usbipd/VirtualBox/recursos compartilhados não previstos. Verificar novamente hash/assinatura do MSI exato e preparar log novo, sem sobrescrever evidências.
3. Somente se a instalação for autorizada separadamente, usar interface interativa do MSI com `/norestart REBOOT=ReallySuppress` e log `/L*v`. Não usar winget silencioso, auto-reboot ou iniciar drivers manualmente. O instalador, por suas ações próprias, tentará iniciar o serviço e carregar a dependência de kernel.
4. Registrar ProductCode `{EA1D5623-E6A7-4E4A-9259-E39722050300}`, versão/hash, código de saída, serviços/driver paths, OEM atribuído, regra de firewall (Name real e propriedades), PATH/registro e diferenças do inventário em recibo **APPLIED**. A prévia atual é `TEMPLATE_NOT_APPLIED`, sem ownership.
5. Código 3010 significa reinício pendente; não reiniciar automaticamente. Código 0 não comprova que driver/serviço funcionaram: algumas ações relatam necessidade de reboot no log ou ignoram falha ao iniciar. Verificar estado sem bind/attach; se precisar reiniciar, manter como etapa separada.
6. Conferir ADB 4EE7 no inventário, INF EFE8, WinUSB, certificados e proteções. Revisar e limitar a regra criada antes de compartilhar dispositivos; o padrão LocalSubnet não é restrito somente ao WSL. Nenhuma regra foi alterada agora.

`/norestart` equivale a `REBOOT=ReallySuppress` para o MSI; essas opções não garantem continuidade contra uma eventual falha de kernel. Não foi criado ponto de restauração ou backup do host nesta etapa. Antes de carregar driver, ter recuperação do PC definida; não usar desativação de HVCI, assinatura ou firewall como mecanismo de teste. [Opções MSI](https://learn.microsoft.com/en-us/windows/win32/msi/standard-installer-command-line-options).

## Plano de reversão

O desinstalador oficial do MSI é a primeira opção, por **ProductCode exato**, com `/x`, `/norestart REBOOT=ReallySuppress` e log novo. O planejador só gera essa reversão quando recebe recibo real APPLIED, versão/hash/ProductCode correspondentes, instalação nova de nossa propriedade, nenhum vínculo USB ativo/persistente e ausência de uso VirtualBox compartilhado.

O MSI executa internamente **`unbind --all`** na desinstalação. Portanto, a reversão não é exclusiva a um eventual futuro dispositivo de teste: é preciso conferir todos os vínculos antes, sem assumir que todos são nossos. Não executar esse comando agora e não gerar comandos globais de detach/unbind como atalho.

A remoção oficial trata arquivos, serviço, regra e driver; custom actions de limpeza são parcialmente best-effort e podem deixar reboot/resíduos pendentes. Depois, comparar com o recibo: ausência dos recursos novos, remoção apenas da entrada PATH própria, serviços/regras/INFs originais preservados, 4EE7 em winusb.inf/WINUSB e gates bloqueados. Se restar regra/INF/serviço, identificar **Name/OEM/path/hash e ownership exatos** e revisar antes de qualquer remoção manual. Não apagar todos os drivers Oracle, `VBox*`, toda a chave da classe USB ou toda lista de filtros.

Não remover certificados, `oem61.inf`/INF EFE8, WinUSB ou o driver Microsoft mausbip preexistente. Se a versão instalada mudou, surgiram outros consumidores ou não há recibo, a reversão automática é recusada. Se Windows não iniciar, a remoção online pode não estar disponível; não há garantia de recuperação apenas por ter o comando `/x` preparado.

## Validação e preservação

**10 testes sintéticos do planejador aprovados:** pacote adulterado, arquitetura, recursos existentes/desconhecidos, recibo-template, ownership incorreto, versão divergente, vínculos ativos/desconhecidos, compartilhamento e política de reinício. [Testes](evidence/plan-tests.txt).

[Preservação antes/depois: PASS](evidence/preservation.json). ADB 4EE7 presente/OK, **winusb.inf/WINUSB**; dispositivos, GUIDs, INFs OEM, WinUSB, certificados, filtros de classe, firewall, PATH, serviços/registro e VBS/HVCI/políticas iguais. Não foi testada resposta pelo protocolo ADB, pois nenhum comando ao tablet foi enviado. Os quatro gates permanecem bloqueados.

[Manifesto local de hashes](manifest.json). Nenhum instalador, binário extraído ou custom action foi executado. A preparação está pronta para revisão; a instalação continua não realizada e a estabilidade operacional permanece pendente.
