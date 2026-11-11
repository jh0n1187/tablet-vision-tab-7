# Prévia da confiança EFE8 e sua reversão

> Estado atual: confiança importada nas duas lojas LocalMachine autorizadas; catálogo/INF verificados, assinatura `Valid`. ADB 4EE7 preservado; nenhum driver instalado ou reboot. Veja [resultado, evidências e reversão](RESULTADO-CONFIANCA.md). As referências abaixo à confiança pendente descrevem etapas anteriores.

Data: 09/11/2026. **Preparação somente: nenhum certificado importado/removido, driver instalado ou tablet reiniciado nesta etapa.** O usuário pediu para revisar as alterações antes de executá-las.

## Certificado exato

| Propriedade | Valor conferido |
|---|---|
| Arquivo público | `signing/homelab-fel-efe8-public.cer` |
| Assunto / emissor | `CN=Homelab EFE8 Local Package` — autoassinado |
| Thumbprint | `9169C63101332FE8064D63B31E70BAAEAA81D813` |
| SHA-256 do DER | `A268B2990119F20C46F6095224310744C59F9B0D82CF0BE95D4C86EC51C1F0AD` |
| Uso estendido | Somente assinatura de código, OID `1.3.6.1.5.5.7.3.3` |
| Chave privada no arquivo | Não |
| Expiração | 09/12/2026 às 11:46:55, Cuiabá |
| Certificado/chave temporários de assinatura | Removidos na etapa anterior, conforme evidência |

O script de prévia também confere hashes fixos do INF e catálogo assinado. Se arquivos, validade ou EKU divergirem, ele para. Não tenta recriar certificado, chave ou assinatura.

## Alteração proposta

| Loja de certificados | Antes | Depois de uma futura importação autorizada |
|---|---|---|
| `Cert:\LocalMachine\Root` | Certificado acima ausente | Uma entrada pública desse mesmo certificado |
| `Cert:\LocalMachine\TrustedPublisher` | Certificado acima ausente | Uma entrada pública desse mesmo certificado |

São **duas entradas do mesmo certificado**, sem chave privada. O escopo LocalMachine foi escolhido para a validação PnP de drivers, que usa as lojas da máquina. A execução exigiria privilégios administrativos para essas duas alterações; não será solicitada elevação nesta preparação. [TrustedPublisher e PnP, Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-publishers-certificate-store), [Root, Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/trusted-root-certification-authorities-certificate-store).

**A confiança é da máquina para assinaturas desse certificado, não uma regra restrita ao VID/PID EFE8 nem somente a este INF.** O certificado não contém uma restrição criptográfica por dispositivo. O INF é que limita a associação do driver a `USB\VID_1F3A&PID_EFE8`. A chave ter sido destruída reduz a possibilidade de reutilizá-la, mas não torna a confiança uma permissão vinculada ao dispositivo.

Nenhuma entrada nas lojas CurrentUser/My é necessária. Não há geração de chave, importação de PFX, instalação de autoridade adicional, alteração de Secure Boot, HVCI, WDAC, modo de teste, verificação de assinatura, antivírus ou política de execução.

Importar confiança não é instalar o driver: não registra o INF no Driver Store, não associa o EFE8 ao WinUSB e não resolve por si só a permanência de aproximadamente 140 ms no modo. Políticas adicionais podem continuar impedindo o pacote; se ocorrer, a regra é parar para revisão, não relaxar proteções.

## O que foi entregue e executado agora

- `preview-trust.ps1`: somente leitura e geração de prévia. **Não possui caminho que importe/remova certificados**, nem parâmetro de aplicação.
- `trust-plan-core.ps1`: funções puras de seleção das mudanças e de reversão, sem operações no sistema.
- `test-trust-plan.ps1`: testes com lojas/recibos sintéticos, sem consulta ou alteração de certificados reais.
- `validation/trust-preview.json`: certificado conferido, duas adições propostas, comandos futuros como texto e modelo de recibo.
- Inventários `baseline/trust-preparation-before.json` e `baseline/trust-preparation-after.json`, para comprovar preservação.

Rodar novamente a prévia, sem aplicar nada:

```powershell
.\tools\winusb-efe8\preview-trust.ps1
```

Ela lê o certificado público em memória; isso não o importa em nenhuma loja. Os dois comandos `Import-Certificate` que aparecem no JSON são **strings para revisão**, não chamadas executadas. O modelo de recibo está marcado como template e não autoriza uma reversão.

## Ordem para uma eventual aplicação — não executada

1. Obter autorização explícita para as duas lojas LocalMachine e guardar a prévia revisada. Instalar driver ou reiniciar o tablet ficam fora dessa autorização.
2. Refazer o inventário imediatamente antes da alteração. Conferir a integridade do CER, INF e CAT e a validade do certificado. Guardar cópia pública do CER e o inventário; não exportar chaves.
3. Criar um recibo novo com identificador da operação, thumbprint, hash DER e os estados `present_before` das duas lojas. Uma entrada preexistente idêntica será preservada; conteúdo divergente com a mesma identificação causa parada.
4. Importar somente nas lojas em que o certificado está ausente, uma por vez, usando o caminho explícito do CER e da loja. A identidade dos comandos já está na prévia. Registrar imediatamente cada importação bem-sucedida como `added_by_this_operation=true`.
5. Se a segunda importação falhar, parar e usar o recibo parcial para reverter somente a primeira alteração confirmada. Não repetir a sequência inteira automaticamente.
6. Conferir presença/hash do certificado nas lojas previstas e validação Windows do catálogo/INF, sem instalar driver. Se o Windows continuar rejeitando o catálogo, registrar o motivo e parar.
7. Comparar ADB `4EE7`, arquivos WinUSB, INFs OEM, registros de interface e lojas fora do escopo contra o inventário. As únicas diferenças esperadas nas lojas são as entradas ausentes anteriormente e adicionadas por esta operação.

O recibo deve ser persistido antes da primeira alteração e atualizado após cada sucesso. Uma falha/crash entre a importação e a atualização do recibo pode deixar estado ambíguo: nesse caso, não tratar a entrada como comprovadamente própria nem apagá-la automaticamente; revisar o estado e os registros antes da reversão.

## Reversão prevista

1. Usar apenas o recibo real dessa operação, com estado `APPLIED` ou `PARTIAL`. O template de prévia é recusado pelas funções de reversão.
2. A seleção exige thumbprint e SHA-256 DER exatos e aceita somente as duas lojas LocalMachine indicadas. Lojas duplicadas/inesperadas, propriedade de estado ausente ou flags que não sejam booleanas são recusadas.
3. Remover apenas uma entrada que **não existia antes** e foi registrada como **adicionada por esta operação**. Se a entrada já existia antes, ela fica preservada. Se sua presença for ambígua, parar para revisão.
4. Antes de remover, reler a entrada exata por thumbprint e comparar o DER. Conteúdo inesperado causa parada. Se a entrada própria já estiver ausente, registrar ausência e não tocar em outras.
5. Para entradas confirmadas como próprias, os alvos possíveis são exclusivamente:

```text
Cert:\LocalMachine\TrustedPublisher\9169C63101332FE8064D63B31E70BAAEAA81D813
Cert:\LocalMachine\Root\9169C63101332FE8064D63B31E70BAAEAA81D813
```

6. A remoção futura seria pelo caminho literal e **sem `-DeleteKey`**, porque essas entradas contêm somente certificado público e a chave já foi destruída. Não usar wildcard, exclusão por Subject, limpeza de lojas, remoção de raízes Microsoft ou qualquer ação em CurrentUser/My.
7. Conferir as lojas contra o inventário/recibo, registrar o resultado e validar a preservação do ADB. Não reinstalar/apagar `winusb.inf`, não excluir o serviço global WINUSB e não mudar configurações do tablet.

Essa reversão cobre **a confiança do certificado somente**. Se o driver vier a ser instalado em outra etapa, remover confiança não desinstala o pacote e não deve ser vendido como rollback completo do driver. A reversão de associação/INF deve seguir o plano separado, com seu nome OEM exato. Nenhum desses procedimentos foi aplicado ou testado alterando o sistema nesta preparação.

## Preservação ADB 4EE7

Estado exigido para seguir: `winusb.inf`, serviço `WINUSB`, provedor Microsoft, versão atual inventariada, GUID ADB `{F72FE0D4-CBCB-407D-8814-9ED673D0DD6B}` preservado. O nó EFE8 continua sem associação instalada. Não haverá chamadas de ADB, abertura USB ou reboot nos scripts de prévia/confiança.

O teste funcional ADB/kiosk após um eventual procedimento pode ser feito em etapa autorizada própria. Nesta preparação, a preservação é verificada pelos metadados e arquivos do Windows, sem enviar comandos ao tablet.
