# usbipd-win instalado e verificado

**09/11/2026, 20:40, America/Cuiaba.** Instalação autorizada pelo usuário, após confirmação de que o tablet foi desconectado. **Sem reboot, bind/attach, comando ADB, consulta FEL ou payload. NUC não utilizado.** Os quatro gates físicos continuam `False`.

## Resultado

- **usbipd-win 5.3.0**, MSI oficial x64 de SHA-256 `1c984914aec944de19b64eff232421439629699f8138e3ddc29301175bc6d938`.
- MSI terminou com **código 0**, produto registrado e sem reinício solicitado pelo MSI. Foram usados `/qb /norestart REBOOT=ReallySuppress` e log detalhado; nenhuma proteção foi desativada.
- Serviço **usbipd** ativo, automático, LocalSystem; executável `C:\Program Files\usbipd-win\usbipd.exe`, versão 5.3.0.1158.
- Driver de kernel **VBoxUSBMon** ativo, demand-start; hash instalado igual ao pacote revisado.
- Driver VBoxUSB publicado no Driver Store como **oem74.inf**, conteúdo idêntico ao INF oficial revisado.
- Regra de firewall criada pelo MSI: **usbipd**, entrada TCP 3240, programa usbipd.exe, todos os perfis, origem LocalSubnet. A configuração padrão não foi ampliada nem ajustada manualmente. Antes de compartilhar um dispositivo, revisar escopo para o uso local/WSL.
- Chaves Devices/Policy sem entradas: nenhum vínculo persistente ou política de auto-bind registrado. Nenhum comando bind/attach foi enviado.

O carregamento inicial do monitor com HVCI ativo foi observado neste host. Isso resolve a dúvida de admissão inicial do driver **nesta instalação**, mas não comprova estabilidade sob tráfego/uso prolongado nem resolve o [relato de BSOD registrado na revisão](REVISAO-INSTALACAO-E-REVERSAO.md). Nenhuma captura ou teste físico USB foi executado.

## Preservação confirmada

Comparação com o inventário feito **já com o tablet desconectado**, imediatamente antes do MSI:

- Metadados dos dispositivos, drivers/serviços/GUIDs preexistentes iguais. O ADB 4EE7 continua configurado como **winusb.inf / WINUSB**; o tablet permaneceu desconectado, portanto não foi testada comunicação ADB.
- WinUSB, todos os INFs OEM anteriores (incluindo o EFE8), certificados Root/TrustedPublisher e filtros UpperFilters/LowerFilters da classe USB preservados.
- VBS e HVCI em execução, políticas de integridade de kernel/usuário iguais às anteriores.
- PATH preserva todas as entradas e acrescenta somente a pasta usbipd-win. Somente o novo oem74.inf foi observado na diferença de INFs.

[Comparação completa: PASS](installations/20261109T223115Z-3595e2b9/preservation-after-install.json).

## Auditoria e reversão

[Recibo real APPLIED e recursos de nossa propriedade](installations/20261109T223115Z-3595e2b9/installation-receipt.json), [resultado do instalador](installations/20261109T223115Z-3595e2b9/install-result.json), [log MSI](installations/20261109T223115Z-3595e2b9/msi-install.log), [regra de firewall exata](installations/20261109T223115Z-3595e2b9/firewall-receipt.json), [estado de compartilhamento](installations/20261109T223115Z-3595e2b9/sharing-state-registry.json).

[Reversão específica preparada, não executada](installations/20261109T223115Z-3595e2b9/rollback-preview.json): desinstalação oficial pelo ProductCode `{EA1D5623-E6A7-4E4A-9259-E39722050300}`, com reinício suprimido e log novo. Exige nova conferência de versão/ownership/vínculos/uso VirtualBox antes de executar; o MSI pode realizar `unbind --all` internamente. Nenhum driver, serviço ou regra preexistente será removido por comandos genéricos.

A primeira solicitação de elevação do helper não iniciou instalação; o Windows a encerrou como cancelada. Após o usuário pedir novo disparo, a elevação foi feita diretamente pelo MSI, sem instalação duplicada. O histórico da primeira solicitação foi preservado no diretório de auditoria.

## Próximo limite

Instalar o serviço não autoriza compartilhar o tablet. O próximo ensaio deverá continuar com dispositivo de teste separado e revisão específica de WSL/Docker, coletor e escopo de firewall. O kit atual ainda recusa WSL como host nativo; nenhum bloqueio foi removido para contornar essa política.
