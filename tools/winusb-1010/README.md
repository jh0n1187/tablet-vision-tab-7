# WinUSB exclusivo para Allwinner 1F3A:1010 — preparado, não instalado

> **Estado posterior:** confiança importada e driver instalado como oem76.inf após autorização. A única tentativa fastboot comunicou, mas os quatro getvars foram recusados por secure mode; retorno ao Android e kiosk confirmado. [Resultado atual e reversão dirigida](RESULTADO-INSTALACAO-E-FASTBOOT.md). A preparação descrita abaixo e o ZIP preservam o estado anterior à aplicação.

Preparação concluída em 10/11/2026 para o PID `1010` observado na tentativa de bootloader. O dispositivo estava com ProblemCode 28 e sem INF associado. Não houve instalação, importação de confiança, reboot, ADB/fastboot/FEL ou carga de payload nesta preparação.

## Escopo do pacote

| Item | Definição |
| --- | --- |
| Correspondência de hardware | **Somente `USB\VID_1F3A&PID_1010`** |
| INF | `package/homelab-fastboot-1010.inf` |
| Catálogo | `package/homelab-fastboot-1010.cat`, SHA-256 assinado localmente |
| Arquitetura | Windows x64; validação Inf2Cat específica `10_25H2_X64` |
| Classe de instalação | USBDevice, `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}` |
| Serviço/binário | WinUSB do Windows via Include/Needs; nenhum `.sys` adicional |
| Interface registrada | `{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}`, esperada pelo fastboot Windows |
| Nome proposto no Gerenciador | Allwinner Fastboot 1F3A 1010 - WinUSB |

Sem correspondência genérica, wildcard, 4EE7, EFE8, filtros USB, coinstaladores ou alteração global de classe USB. O GUID de interface Android é compartilhado pelo ecossistema, mas não amplia os hardware IDs que este INF pode associar.

O GUID foi conferido no [fastboot AOSP](https://raw.githubusercontent.com/aosp-mirror/platform_system_core/main/fastboot/usb_windows.cpp), no [cabeçalho Android USB API](https://raw.githubusercontent.com/aosp-mirror/platform_development/main/host/windows/usb/api/adb_api.h) e como bytes GUID dentro do `fastboot.exe` existente no SDK deste PC. [Instalação WinUSB por INF da Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/winusb-installation). Isso confirma a interface esperada pelo cliente, não o protocolo/descritores do tablet: o teste real após associação permanece pendente.

## Assinatura concluída

- Certificado: `CN=Homelab Fastboot 1010 Local Package`.
- Thumbprint: `F1D9D3825930C5768826BC2274E6C1F047356854`, diferente do certificado EFE8 existente.
- Certificado público: `signing/homelab-fastboot-1010-public.cer`.
- RSA 3072/SHA-256, EKU Code Signing; válido até **10/12/2026, 00:47:14 em Cuiabá**, sem timestamp externo.
- Criado temporariamente em CurrentUser\My. Certificado pessoal e chave CNG privada não exportável removidos; loja My restaurada. Nenhum PFX/chave privada exportado ou incluído no pacote.
- CMS criptograficamente válido, conteúdo do catálogo idêntico ao catálogo gerado por Inf2Cat antes da assinatura. Resultado definitivo em `signing/verification-summary.json`.
- **Confiança Windows ainda não aplicada**. SignTool `/pa /c` retornou raiz não confiável, conforme esperado. Não é assinatura WHQL/attestation da Microsoft e não se apresenta como tal.

A primeira execução usou Windows PowerShell 5.1: a assinatura passou, mas o carregamento do assembly de verificação Pkcs falhou. O bloco finally removeu certificado/chave e restaurou My. Não foi recriada a chave nem reassinado o catálogo; a verificação foi concluída no PowerShell 7 já existente. `signing/result.json` preserva o registro da primeira execução e `signing/verification-summary.json` registra a verificação concluída. O script de assinatura foi ajustado para carregar o assembly correspondente à edição PowerShell.

## Validações realizadas

- Parser INF nativo do Windows: uma linha de modelo, sem funções de instalação chamadas.
- Política exata do INF e **9 mutações perigosas rejeitadas**, incluindo 4EE7, EFE8, wildcard, filtro, registro global e coinstalador.
- InfVerif `/w`: exit 0; Inf2Cat para Windows 11 25H2 x64: exit 0, zero erros/avisos; nova verificação `/nocat` após assinatura: exit 0.
- Assinatura CMS e conteúdo do catálogo preservado; GUID conferido no SDK local.
- **14 testes sintéticos** de planejamento/reversão de confiança, incluindo rejeição de remoção de certificado preexistente/estrangeiro e recibo não aplicado.
- Inventários antes/depois iguais: PnP/associação dos três PIDs, arquivos inbox WinUSB, lista/hashes dos INFs OEM, Root/TrustedPublisher de usuário/máquina e CurrentUser\My.
- INF, CAT e certificado público do pacote EFE8 preservados por comparação com seu manifesto anterior. Nenhuma chave de confiança EFE8 removida/reutilizada.

Ferramentas WDK reutilizadas da extração portátil anteriormente verificada do pacote Microsoft.Windows.WDK.x64 10.0.26100.6584, sem reinstalar WDK. Evidências de origem em `../winusb-efe8/tooling/`; SignTool do Windows SDK já existente. Recibos desta preparação em `baseline/` e `validation/`.

## O que mudaria em uma aplicação futura — não executado

1. Adicionar **somente o novo certificado público** em LocalMachine\Root e LocalMachine\TrustedPublisher, com recibo do estado anterior de cada loja. Nenhuma substituição/remoção do certificado EFE8.
2. Registrar **somente este INF** no Driver Store com `pnputil /add-driver "<caminho exato>\homelab-fastboot-1010.inf"`, sem `/subdirs`, `/install` ou `/reboot`. O Windows atribuirá um `oemNN.inf`; esse nome ainda não existe para este pacote e não pode ser antecipado.
3. Na próxima enumeração do `1F3A:1010`, o PnP poderá associar o WinUSB e registrar o GUID Android **no nó 1010**. Só então validar associação/descritores e testar `fastboot devices`/consultas de identificação autorizadas.

A confiança de assinatura em Root/TrustedPublisher é de máquina e **não é criptograficamente limitada ao VID/PID**, embora o INF seja. A chave privada foi destruída, mas não se deve descrever a importação de confiança como uma restrição por PID. Não se propõe desativar Secure Boot, HVCI, integridade de código, assinatura obrigatória, antivírus ou firewall; se a política bloquear o pacote, parar para análise.

Somente instalar esse driver não demonstra desbloqueio nem aceitação AVB. Firmware modificada permanece sem autenticação OEM e ainda não está pronta para flash.

## Reversão

**Estado atual:** não há driver/confiança 1010 instalados para desfazer. A reversão do certificado temporário de assinatura já foi concluída.

Depois de eventual aplicação, em ordem:

1. Retornar ao Android e confirmar ADB 4EE7/kiosk. Identificar pelo recibo o `oemNN.inf` acrescentado, conferir hash do INF e que seus usuários sejam exclusivamente 1010. Nunca remover `winusb.inf`, WinUSB.sys, oem61.inf/EFE8 ou o INF do ADB.
2. `rollback-staged-driver.ps1 -ReceiptPath <recibo real>` mostra a prévia. Com autorização futura, `-Apply` remove apenas o pacote próprio **sem associação**, sem `/force`, `/uninstall` ou reboot. Se já houver associação, o script para: revisar primeiro a desassociação dirigida exclusivamente ao 1010, com o tablet fora desse modo, e não fazer exclusão forçada. Não há recibo de staging agora e nenhum foi fabricado.
3. `rollback-trust.ps1 -ReceiptPath <recibo real da importação>` mostra a prévia; com autorização futura, `-Apply` remove somente as entradas do novo thumbprint que o recibo prove terem sido acrescentadas por essa operação. Certificados preexistentes são preservados. Um template não é aceito como recibo aplicado.
4. Comparar novamente ADB/EFE8, arquivos WinUSB, INFs OEM e certificados. Caso a instalação solicite reboot, não reiniciar automaticamente.

`preview-trust.ps1` só lê e mostra alterações propostas; não tem caminho de importação. Nenhum script de instalação automática está incluído nesta preparação. Os scripts de reversão são opcionais e recusam operações sem propriedade comprovada por recibo.
