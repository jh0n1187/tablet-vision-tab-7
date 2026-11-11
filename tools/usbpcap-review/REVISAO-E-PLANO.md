# USBPcap: instalador, compatibilidade e reversão preparados

09/11/2026. **Nenhum instalador/USBPcapCMD executado, driver instalado, serviço criado ou reinício realizado.** Somente download, extração seletiva, leitura, verificações de assinatura e testes de planejamento no PC. ADB 4EE7 preservado; consulta física e backend geral permanecem bloqueados.

## Resultado da avaliação

**O pacote é oficial e as verificações de assinatura passaram, inclusive a política de driver para o build 26200. A compatibilidade operacional neste Windows 11 com HVCI ativo não está comprovada.** Há relato aberto no projeto de BSOD usando USBPcap 1.5.4.0 no Windows 11 25H2 build 26200.8037. É um relato de usuário, não diagnóstico confirmado para este PC, mas é material para a decisão. Recomendo validar primeiro em um host Windows de teste, em vez de tratar esta preparação como liberação automática para instalar no host principal. [Issue upstream #146](https://github.com/desowin/usbpcap/issues/146).

## Origem e assinaturas

A página oficial e o endpoint latest do projeto apontam para **1.5.4.0**, publicada em 22/05/2020. A declaração formal cobre Windows 7/8/10, x86/x64, sem homologação explícita para Windows 11 25H2. [Site oficial](https://desowin.org/usbpcap/), [release oficial](https://github.com/desowin/usbpcap/releases/tag/1.5.4.0).

| Arquivo | Verificação |
|---|---|
| `downloads/USBPcapSetup-1.5.4.0.exe` | 195.040 bytes; Authenticode `Valid`; SignTool `/pa` código 0, zero erros/avisos |
| `Release/Windows10/x64/USBPcap.sys` do anexo oficial | Authenticode `Valid`; assinatura com timestamp |
| `usbpcapamd64.cat` | Assinado por **Microsoft Windows Hardware Compatibility Publisher**, válido |
| SYS + INF no catálogo | SignTool `/kp /c` código 0; ambos os hashes conferidos |
| SYS + INF, alvo `2:10.0.26200` | Política Windows Driver com `/o`, código 0; zero erros/avisos |
| `USBPcapCMD_x64.exe` | Authenticode e SignTool `/pa` válidos; binário não executado |

SHA-256 completo do instalador:

```text
87A7EDF9BBBCF07B5F4373D9A192A6770D2FF3ADD7AA1E276E82E38582CCB622
```

O signatário do EXE é Tomasz Moń, certificado `904287C47876C84601A322DE45BEEFB4BB87EBA8`. O certificado venceu em 2021, mas a assinatura possui timestamp de 22/05/2020 e passou na verificação atual; vencimento do certificado não foi confundido com falha da assinatura.

Também foi baixado o anexo oficial `usbpcap-src-incl-pdb-1.5.4.0.7z`, SHA-256 `3A66CF03425F5860FF8ACD64D11CC0BB50669C7F449754F47788011259A5B15E`. O instalador contido nele é byte a byte idêntico ao EXE baixado separadamente. Foram extraídos apenas os arquivos selecionados, sem executar o instalador. O pacote Windows10/x64 e o script NSIS revisados vieram desse anexo; **o payload do EXE NSIS não foi extraído diretamente**. [Metadados oficiais](evidence/official-release.json), [comparação](evidence/archive-installer-match.json), [assinaturas](evidence/package-authenticode.json).

Uma invocação inicial de SignTool combinando `/kp` e `/o` foi recusada por incompatibilidade de opções, sem avaliar o driver. Foi preservada como diagnóstico e substituída por verificações separadas válidas: `/kp` e política Windows Driver com `/o`. [Kernel](evidence/kernel-signature.txt), [alvo OS](evidence/driver-policy-target-os.txt).

## Compatibilidade com este PC

- **Windows 11 25H2, x64, build 26200.9711**. O texto legado ProductName no Registro ainda diz Windows 10 Pro; versão/build identificam a família Windows 11. [Referência Microsoft](https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information).
- VBS em execução e `SecurityServicesRunning=[2]`: integridade de memória/HVCI ativa. Políticas de integridade de kernel e modo usuário em estado 2. Nenhuma foi alterada. [Estado observado](evidence/windows-state.json), [mapeamento Microsoft](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).
- O script NSIS seleciona Windows10/x64 para sistemas x64 `AtLeastWin10`; a seleção correspondente no Windows 11 é uma inferência do fonte, não um teste de execução do instalador.
- PE do SYS: AMD64, alinhamento 4096, NX_COMPAT e nenhuma seção simultaneamente gravável/executável. O fonte tem opt-in de pool NX para builds modernos. São evidências estáticas favoráveis, não comprovação de HVCI/funcionamento. [PE](evidence/driver-pe-check.json), [requisitos Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard).
- Não houve carregamento, Driver Verifier, teste de stress ou HLK. O relato de BSOD permanece aberto; a busca upstream não produziu declaração de compatibilidade HVCI específica para esta configuração. Não recomendar desabilitar HVCI, App Control, Secure Boot ou validação de assinatura para contornar eventual bloqueio.

## O que uma futura instalação alteraria

| Alvo | Alteração do pacote revisado |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Control\Class\{36FC9E60-C465-11CF-8056-444553540000}\UpperFilters` | Acrescentar a string `USBPcap` como REG_MULTI_SZ, preservando valores existentes |
| Serviço `USBPcap` | Driver de kernel, StartType 3, ErrorControl 2, `System32\drivers\USBPcap.sys` |
| Diretório de instalação, normalmente `C:\Program Files\USBPcap` | INF/SYS/CAT, CLI x64 e desinstalador |
| Registro de desinstalação HKLM | Entrada `...\CurrentVersion\Uninstall\USBPcap`, versão/publisher/caminho de remoção |
| Restauração do Sistema | O instalador tenta criar um ponto; falha não impede necessariamente a instalação |

O INF é um **filtro da classe USB global**, não uma associação restrita a EFE8. O driver ADB `winusb.inf`, seu GUID e `oem61.inf` não são alvos do pacote, mas o novo filtro pode interpor-se na pilha compartilhada. Portanto preservar esses INFs não é garantia de que o filtro não afetará o ADB ou outros dispositivos USB.

Estado atual registrado: `UpperFilters` da classe USB ausente, sem serviço USBPcap, SYS em System32, entrada de desinstalação ou pasta de instalação. [Estado antes/depois](evidence/usbpcap-state-before.json).

Fontes locais exatos: [INF](sources/usbpcap/Release/Windows10/x64/USBPcap.inf), [NSIS](sources/usbpcap/nsis/USBPcap.nsi). O INF usa append (`0x00010008`), não substituição da lista. [Semântica AddReg, Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addreg-directive).

## Plano de instalação — não aplicado

1. Preferir host de teste. Se futuramente for escolhido este host, preparar recuperação do Windows e um backup válido antes de acrescentar um filtro global, considerando o relato de BSOD na mesma família de build.
2. Atualizar o inventário imediatamente antes e parar se USBPcap já existir. Registrar presença/tipo/lista de UpperFilters, serviço/arquivos, INFs publicados, assinaturas e propriedades ADB/EFE8. Não assumir propriedade de instalação preexistente.
3. Revalidar o EXE pelo SHA-256 e assinatura. Execução futura **interativa**, com UAC; não usar `/S`, porque as escolhas padrão incluem funções adicionais e dificultam controlar prompts.
4. Manter driver e CLI, **desmarcar “Detect USB 3.0”**. Essa opção chama `USBPcapCMD.exe -I` para inicialização de hardware IDs não padronizados; não é necessária como experimento automático e amplia o escopo de configuração.
5. O instalador chama `InstallHinfSection DefaultInstall 132`: pode perguntar sobre reinício quando necessário. Responder **não reiniciar** até haver autorização específica. O modo 132 pergunta, não é a variante de reinício automático. [Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-installhinfsectionw).
6. Não lançar USBPcapCMD interativo após instalar: se o filtro ainda não estiver ativo, ele pode oferecer reiniciar **todos os dispositivos USB**. Não aceitar. Não usar `-I`, scan/restart global ou reiniciar o tablet para forçar ativação.
7. Registrar recibo real de instalação: pacote/hash, caminho real, versão e assinatura do desinstalador, diff de filtros, serviço e eventuais INFs novos. Comparar ADB e proteções. Ativação/carga e reinício do PC ficam como etapa separada; não iniciar VERSION ou captura por implicação.
8. Se houver bloqueio Code Integrity, coletar o erro e parar; não reduzir as proteções. A recomendação oficial de reiniciar o PC após instalar deve ser revisada e autorizada separadamente. [USBPcap oficial](https://desowin.org/usbpcap/).

## Reversão preparada — não aplicada

O caminho preferencial é o desinstalador oficial da instalação efetivamente criada, depois de conferir seu caminho, versão, assinatura e recibo. Ele ainda não existe no sistema, portanto seu hash não pode ser registrado como se já estivesse instalado.

O fonte chama `DefaultUninstall 132`, remove somente a string USBPcap da lista de filtros (`0x00018002`), solicita remoção do serviço e arquivos próprios e apaga a entrada de desinstalação. Pode ficar pendente até reinício; não forçar exclusão de serviço/SYS carregado. Não apagar `WinUSB.sys`, `winusb.inf`, `oem61.inf`, certificados EFE8 ou a chave inteira da classe USB.

Preservar quaisquer filtros preexistentes ou adicionados por outro programa. Se originalmente UpperFilters era ausente e após remoção oficial restar apenas um valor vazio, revisar a restauração exata da ausência com recibo e estado atual; não substituir a lista pelo snapshot antigo. Se não existir recibo real ou USBPcap já existia, não presumir que a instalação pertence a esta operação.

Se o Windows não iniciar após uma futura instalação, o desinstalador online pode não estar disponível. Antes de instalar, deve haver um caminho de recuperação validado: ponto/backup restaurável ou reversão offline dirigida da entrada USBPcap no ControlSet correto. Não foi criado comando genérico de edição offline, não foi montada hive e não se presume volume/ControlSet. Não desativar controles de segurança como mecanismo de recuperação.

Depois da reversão e do reinício eventualmente autorizado, conferir ausência do filtro/serviço, preservação dos demais filtros, ADB 4EE7 `winusb.inf`/GUID/serviço e app normal, e gates físicos bloqueados.

## Artefatos e validação

[Prévia concreta](evidence/installation-rollback-preview.json) e [gerador somente de leitura](review_plan.py), sem caminho Apply/instalação/Registro. O recibo é marcado `TEMPLATE_NOT_AN_INSTALL_RECEIPT` e não autoriza remoção.

**10 testes sintéticos aprovados**: append, pré-existência, ownership contraditório, template inválido, preservação de outros filtros, remoção já feita, valor vazio/ausente e tipos inválidos. [Testes](evidence/plan-tests.txt).

[Preservação antes/depois](evidence/preservation.json): ADB 4EE7 presente e OK pelo Windows, `winusb.inf`, propriedades/GUID, EFE8, WinUSB, INFs OEM, certificados, classe USB, serviços/arquivos USBPcap e estado das proteções iguais. Nenhum comando ADB foi necessário. Consulta física e backend geral continuam bloqueados.
