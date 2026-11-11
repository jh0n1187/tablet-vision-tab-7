# Confiança EFE8 importada — 09/11/2026

> Estado posterior: pacote EFE8 registrado como `oem61.inf`; associação ativa pendente de futura enumeração FEL. ADB 4EE7 preservado, nenhum reboot/payload. Veja [resultado e reversão do driver](RESULTADO-DRIVER.md).

Importação autorizada concluída às 12:04:52 (Cuiabá), somente em `LocalMachine\Root` e `LocalMachine\TrustedPublisher`, pelo UAC do Windows. Certificado `9169C63101332FE8064D63B31E70BAAEAA81D813`, sem chave privada. A confiança abrange assinaturas desse certificado na máquina; não é limitada ao hardware EFE8. Expira em 09/12/2026 às 11:46:55, sem timestamp externo.

## Validação

- Recibo em estado `APPLIED`: [importação](trust-receipts/import-20261109T160448Z.json), com propriedade das duas entradas adicionadas e SHA-256 do DER conferido.
- `signtool verify /pa /v /c CAT INF`: código 0, zero erros e avisos; `Get-AuthenticodeSignature`: `Valid`. [Saída](validation/trust-import-verification.txt).
- Inventários antes/depois: dispositivos, associação ADB 4EE7, associação EFE8, arquivos WinUSB e INFs OEM idênticos. [Comparação](validation/trust-import-results.json).
- CurrentUser\My preservado. As lojas lógicas CurrentUser Root/TrustedPublisher exibem a confiança herdada de LocalMachine; não houve importação direta em CurrentUser, e as entradas correspondentes em HKCU estão ausentes.
- Nenhum driver instalado, nenhuma proteção alterada, nenhum comando enviado ao tablet e nenhum reinício.
- A aprovação Authenticode comprova a confiança do catálogo/INF; a instalação PnP e o funcionamento com EFE8 ainda não foram testados.

## Reversão registrada, não executada

A [prévia da reversão](validation/trust-rollback-preview.json) selecionou somente as duas entradas efetivamente adicionadas. O script valida recibo, thumbprint e DER; o padrão é somente prévia. Para futura reversão autorizada, executar em PowerShell como administrador:

```powershell
& 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-efe8\rollback-trust.ps1' -ReceiptPath 'C:\Users\Jonathan\projetos\tablet-positivo\tools\winusb-efe8\trust-receipts\import-20261109T160448Z.json' -Apply
```

A reversão remove apenas esse certificado das duas lojas da máquina. Não altera drivers ou o tablet. Não foi necessário desativar controles do Windows.
