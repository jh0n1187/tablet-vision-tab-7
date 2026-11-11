# WinUSB exclusivo para 1F3A:EFE8 — preparação para revisão

> Atualização após uma tentativa efex autorizada: `oem61.inf`/`WINUSB` associados ao EFE8 com instalação Windows bem-sucedida, mas FEL transitório (~133/152 ms); Android/ADB e app homelab retornaram. [Resultado](../../analise-firmware/revisao-fel/capturas/efex-driver-20261109T164143Z/RESULTADO.md). A reversão simples de pacote não associado agora deve parar para revisão de desassociação.

> Estado posterior: pacote EFE8 registrado como `oem61.inf`; associação ativa pendente de futura enumeração FEL. ADB 4EE7 preservado, nenhum reboot/payload. Veja [resultado e reversão do driver](RESULTADO-DRIVER.md).

> Estado atual: confiança importada nas duas lojas LocalMachine autorizadas; catálogo/INF verificados, assinatura `Valid`. ADB 4EE7 preservado; nenhum driver instalado ou reboot. Veja [resultado, evidências e reversão](RESULTADO-CONFIANCA.md). As referências abaixo à confiança pendente descrevem etapas anteriores.

> Próxima etapa preparada, não aplicada: [importação de confiança e reversão](PLANO-CONFIANCA-E-REVERSAO.md). Somente duas adições propostas em LocalMachine Root/TrustedPublisher; o script de prévia não importa nem remove certificados. A confiança teria escopo da máquina para esse signatário, não fica restrita a EFE8.

Data: 09/11/2026. **Não instalado. Catálogo validado e assinado localmente; confiança Windows não importada.** Veja [catálogo e resultado da assinatura](CATALOGO-E-ASSINATURA.md). O certificado temporário e a chave privada foram removidos. As notas abaixo sobre falta de ferramentas descrevem a etapa inicial; depois elas foram extraídas de um pacote oficial para uma pasta local, sem instalação global.

O INF preparado corresponde somente ao hardware ID `USB\VID_1F3A&PID_EFE8`, em Windows 10/11 x64. O objetivo é usar o WinUSB da Microsoft já presente no PC, sem driver de kernel novo, filtros USB, libusbK ou substituição do ADB.

## Estado observado e preservado

| Item | Estado atual |
|---|---|
| Android/ADB `1F3A:4EE7` | Presente, OK, `winusb.inf`, serviço `WINUSB`, provedor Microsoft, versão `10.0.26100.9549` |
| GUID atual do ADB | `DeviceInterfaceGUID` = `{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}` |
| FEL `1F3A:EFE8` | Nó histórico desconectado, sem INF/serviço associado |
| GUIDs atuais do EFE8 | Valores singular/plural ausentes em Device Parameters |
| `WinUSB.sys` existente | Assinatura Microsoft válida; hash salvo no inventário |

O EFE8 observado tem classe USB `FF/FF/FF` e não anuncia o identificador `USB\MS_COMP_WINUSB` que permite associação automática ao driver genérico. O ADB usa outra interface, `FF/42/01`, já configurada. Os IDs vieram do inventário Windows, sem leitura direta do tablet.

`baseline/review-before.json` guarda propriedades PnP, valores de interface, hashes dos arquivos WinUSB, hashes dos INFs OEM publicados e thumbprints dos certificados públicos das quatro lojas de confiança consultadas. Contém IDs de instância locais; não inclui certificados privados ou chaves. O inventário é evidência, não um script de restauração integral do Registro.

## Alterações propostas para uma instalação futura

| Local | Alteração prevista |
|---|---|
| Driver Store do Windows | Adicionar um pacote de associação `homelab-fel-efe8.inf` com catálogo assinado; o Windows atribuirá um nome `oemNN.inf` a registrar |
| Nó(s) USB com hardware ID exato `1F3A:EFE8` | Associar ao serviço Microsoft `WINUSB`, herdando `winusb.inf` |
| Estado da interface de EFE8 | Acrescentar `{431CD5B9-DF93-4B87-B9EB-DA404040F0C4}` a `DeviceInterfaceGUIDs`, como REG_MULTI_SZ com APPEND |
| Arquivos locais de evidência | Guardar nome OEM atribuído, hashes do pacote efetivo, inventário posterior e resultado de verificação |

O INF contém uma única linha de modelo, nenhum wildcard, correspondência por classe genérica ou PID ADB. APPEND preserva GUIDs que já existam. Não há coinstaller, classe nova, filtro, executável auxiliar ou seção de instalação genérica. O binário de kernel é o WinUSB fornecido pelo Windows. [Estrutura de INF WinUSB, Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation), [semântica APPEND](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addreg-directive).

A correspondência por VID/PID alcança **qualquer dispositivo que anuncie esse mesmo par**, não apenas o número de série deste tablet. Antes de instalar/aplicar/reverter, manter outros equipamentos Allwinner EFE8 desconectados. Nenhuma operação deve selecionar o primeiro dispositivo sem conferir sua identidade.

O `4EE7` não consta no INF. Não se propõe alterar seu INF, serviço, GUID, registros, driver ou configuração ADB. Também não se propõe apagar `winusb.inf`, substituir `WinUSB.sys`, excluir o serviço global `WINUSB` ou alterar Secure Boot, HVCI, teste de assinatura, antivírus ou políticas de confiança.

## O que foi preparado

- `package/homelab-fel-efe8.inf`: associação exata, versão local `1.0.0.0`, data INF `11/09/2026` no formato MM/DD/YYYY.
- `verify_package.py`: auditoria estática e leitura pelo parser INF nativo do Windows; não vincula funções de instalação.
- `capture-baseline.ps1`: consultas de leitura e gravação de evidência somente nesta pasta de projeto.
- `validation/results.json`: verificações e limitações.
- `baseline/`: estado anterior/posterior e comparação de preservação.

Não foi criado script de instalação automática. Nenhum comando `pnputil /add-driver`, `/install`, `/delete-driver`, `/remove-device` ou `/scan-devices` foi executado. PnPUtil foi usado somente para enumeração.

## Assinatura e condição de parada

O `WinUSB.sys` da Microsoft tem assinatura válida, mas o **INF personalizado precisa de seu próprio catálogo assinado**, aceito pela política atual do Windows. O catálogo `homelab-fel-efe8.cat` existe, gerado por Inf2Cat sem erros/avisos; InfVerif também aprovou o INF. As ferramentas foram extraídas localmente do WDK NuGet oficial, sem instalação global. O catálogo foi assinado com certificado temporário após autorização, mas sua raiz não é confiável no Windows. O certificado e a chave privada foram removidos; o certificado público foi preservado em arquivo. A assinatura criptográfica não substitui a confiança exigida na instalação. [Requisitos de pacote WinUSB](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation).

MakeCat não foi usado como substituto de Inf2Cat: a documentação orienta não usá-lo para criar catálogos de arquivos instalados por INF. [Orientação Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/using-makecat-to-create-a-catalog-file).

Foi gerado somente o certificado/chave temporários autorizados em `CurrentUser\My`, removidos após a assinatura. Nenhuma autoridade ou confiança foi importada. Zadig/libwdi não foram baixados nem executados; suas operações de preparação podem envolver criação de catálogo e instalação de certificado na máquina, não apenas extração de arquivos. Isso exigiria revisão explícita dos efeitos e reversão adicional. [Declaração do projeto libwdi](https://github.com/pbatard/libwdi/wiki/Certification-Practice-Statement).

**Parar antes da instalação enquanto faltar assinatura/confiança aceita.** A proposta não inclui contornar essa exigência. Uma alternativa documentada pela Microsoft é associar o WinUSB já existente via Gerenciador de Dispositivos e configurar o GUID da instância; isso evita o INF personalizado, mas é outra forma de alterar a associação, não foi executada/testada e precisa de revisão própria para o EFE8 transitório.

## Plano futuro de aplicação — não executar agora

1. Concluir assinatura/confiança aceita para o catálogo já gerado e validado, ou revisar separadamente a alternativa de associação nativa. Não gerar confiança local ou desativar proteções implicitamente. A autorização solicitada para assinatura temporária não inclui instalar confiança ou driver.
2. Revalidar o estado ADB contra `baseline/review-before.json` e confirmar que só este tablet poderá aparecer como EFE8. Guardar cópia final assinada, hashes e signatário.
3. Com aprovação específica e privilégios administrativos mínimos, registrar apenas o INF exato no Driver Store. O equivalente de revisão é `pnputil /add-driver "<caminho-exato-do-INF-assinado>"`, **sem** `/install`, `/subdirs` ou `/reboot`. Só depois conferir o nome publicado e seus hardware IDs. [PnPUtil oficial](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax).
4. Não reiniciar o tablet nessa etapa. A associação ao EFE8 na próxima enumeração e uma nova tentativa efex exigem autorização própria. A instalação no host não garante que o modo permanecerá ativo.
5. Depois da associação autorizada, confirmar código de problema, serviço WINUSB e interface EFE8. Conferir separadamente que ADB `4EE7` continua com seu estado original. Não usar o driver como autorização para payload ou leitura de eMMC; o backend de transferência continua desabilitado.

## Plano de reversão

O estado anterior de EFE8 é **sem driver associado**; portanto, reverter não significa instalar outro driver nele.

1. Parar qualquer sessão de identificação; manter Android/ADB funcionando quando possível. Não enviar reset, payload ou comandos de flash para reverter um driver do PC.
2. Identificar o nome publicado `oemNN.inf` registrado na aplicação. Confirmar original `homelab-fel-efe8.inf`, provedor local, versão, hash e único hardware ID EFE8. Nunca escolher um OEM por suposição ou usar wildcard.
3. Se apenas registrado e não utilizado, remover esse pacote exato com `pnputil /delete-driver "<OEM-confirmado>.inf"`. Se já associado, a variante de revisão é `pnputil /delete-driver "<OEM-confirmado>.inf" /uninstall`. Não usar `/force` ou `/reboot`; se houver exigência de reinício ou outro dispositivo afetado, parar. Esses comandos são documentação e **não foram executados**.
4. Inspecionar apenas os nós EFE8 envolvidos. Se o GUID local permanecer após a desinstalação, remover somente `{431CD5B9-DF93-4B87-B9EB-DA404040F0C4}` da lista. Preservar os demais GUIDs e a configuração anterior; se o valor antes não existia e ficar vazio, remover apenas esse valor. Não apagar a chave Enum, restaurar a árvore inteira, mudar permissões de Registro ou tocar nos nós 4EE7. Se o sistema impedir o ajuste, parar para revisão em vez de tomar posse das chaves.
5. Como esta proposta não adiciona certificados, não há certificado a remover. Se outra rota for escolhida, a reversão deve ser ampliada antes de aplicá-la, usando thumbprints específicos e o inventário anterior — nunca removendo raízes Microsoft ou certificados por nome genérico.
6. Comparar ADB, hashes WinUSB e inventários. ADB precisa continuar `winusb.inf`/WINUSB/Microsoft, com seu GUID original. O EFE8 deve deixar de apontar para o pacote local. A verificação funcional do EFE8 pode precisar de outra enumeração autorizada; não provocar reboot silenciosamente.

A instalação e a reversão reais ainda não foram ensaiadas; são procedimentos condicionais para revisão, não uma garantia de ausência absoluta de efeitos do instalador Windows.

## Repetir somente verificações

```powershell
python tools/winusb-efe8/verify_package.py --native
```

O verificador abre e lê o INF com SetupAPI. Não chama funções de instalação nem tenta abrir o tablet. A auditoria rejeitou oito alterações perigosas simuladas, incluindo PID ADB, correspondência USB genérica, wildcard, coinstaller, filtro, registro global e arquitetura adicional.
