# FEL readonly — preparação offline para o T307F

> Análise de captura independente: [plano USBPcap e analisador offline](../../analise-firmware/revisao-fel/CAPTURA-USB-INDEPENDENTE.md). `inspect_usbpcap.py` lê somente arquivos; 15 testes aprovados. Nenhum driver de captura instalado ou sessão iniciada; consulta física bloqueada.

> Diagnóstico ACK zero corrigido no PC: [resultado e testes](../../analise-firmware/revisao-fel/ACK-ZERO-DIAGNOSTICO-E-CORRECAO-PC.md). Canary/guarda e trace nativo opt-in para VERSION; ACK zero continua rejeitado. 46 testes aprovados, 7 omitidos. Nenhuma nova execução física.

> Perfil VERSION corrigido após uma tentativa: OUT 02/IN 81 conforme descritores ETW. A tentativa original parou antes do pedido VERSION; correção validada por 18 testes no PC e ainda não executada no tablet. Gates físicos continuam bloqueados. Veja o índice da investigação para recibos.

> VERSION isolada preparada: [ETW detalhado, ferramenta e validação](../../analise-firmware/revisao-fel/ETW-DETALHADO-E-VERSION.md). 16 testes aprovados; consulta e observador sem payload/reboot, acesso físico bloqueado.

**Protótipo testado no PC. Não carregar nenhum dos binários no tablet.**

> Continuação atual: [BROM, I-cache e SRAM](../../analise-firmware/revisao-fel/REVISAO-BROM-ICACHE-SRAM.md). Executados 120 cenários com os binários ARM no emulador e seis cenários de registradores da rotina I-cache. Não há modelo da BROM, caches físicos ou acesso ao tablet. As proteções do Windows permanecem intactas.

> Rodada mais recente: [validações adicionais no PC](../../analise-firmware/revisao-fel/VALIDACOES-ADICIONAIS-PC.md). São 51 testes Python e 391 verificações C aprovados; a classe com sete casos de ABI nativa foi bloqueada pelo Controle de Aplicativos do Windows (4551) e não executada. O backend físico continua desabilitado.

> Atualização: o transporte FEL e o backend WinUSB restrito foram implementados e testados com substitutos no PC. A abertura física permanece bloqueada por `LIVE_USB_ENABLED = False`. Consulte [USB, identificadores e SRAM](../../analise-firmware/revisao-fel/RESULTADO-USB-E-SRAM.md).

Esta versão separa aquisição de firmware de root/desbloqueio. Não implementa gravação de setores, erase, troca de área da eMMC, RPMB, eFuse, PMIC, DDR, reparo de EXT_CSD ou instalação de Magisk. O arquivo `felro.py` não tem backend USB físico: sua CLI apenas inspeciona uma imagem regular **local**. Importar o módulo, consultar ajuda e executar os testes não abrem o tablet.

O payload tem caminho real de controle SMHC derivado do fonte revisado, mas essa compatibilidade física **não foi validada** no T307F. A entrada FEL, as regiões de memória, a configuração elétrica e o estado da BROM continuam sendo condições de parada. Não existe autorização de execução nesta entrega.

## Conteúdo

- `felro.py`: protocolo, validação de respostas, envelope de RAM, GPT primária/secundária e aquisição com transporte injetado.
- `usb_transport.py`: enquadramento AWUC/FEL, consulta de versão e ponte restrita para o payload, com limite de endereços e conferência do código copiado.
- `winusb_backend.py`: ligação WinUSB de caminho explícito, sem enumeração; abertura real desabilitada. Nos testes, somente API substituta.
- `payload/`: núcleo C e candidato de controlador ARM, entrada assembly e linker script.
- `tests/test_felro.py`: transporte simulado, GPT sintética e arquivos temporários no PC.
- `tests/payload_test.c`: núcleo C com operações de cartão simuladas, executado como processo Linux no WSL.
- `tests/hardware_test.c`: núcleo e driver C com registradores simulados, também executado apenas no WSL.
- `build_and_test.py`: compilação, verificações do ELF e testes locais; não chama ADB ou xfel.
- `brom_sram_audit.py`: consistência das faixas e referências, sem medir disponibilidade física.
- `arm_offline_validation.py`: execução ARM somente no emulador Linux isolado, com MMIO não mapeado.
- `prepare_offline_deps.py`: baixa wheel fixo do emulador, confere SHA-256 e extrai apenas em `build/offline-deps/`.
- `build/results.json`: resultados, ferramentas, hashes dos fontes e binários.
- `build/reproducibility.json`: comparação de duas compilações no mesmo ambiente.

## Como repetir somente no PC

Dependências da rodada inicial: Python 3.14.7, LLVM/Clang 19.0.1 do Android NDK 28.2.13676358 e Ubuntu já instalado no WSL. O caminho do LLVM pode ser alterado conforme a instalação.

Para a emulação opcional, foi acrescentado Unicorn 2.1.4 Linux em pasta local de análise, sem instalação global. Execute `prepare_offline_deps.py` e acrescente `--offline-arm` ao build para repetir essa parte. A dependência não integra o payload e não altera as proteções do Windows.

```powershell
python tools/fel-readonly/build_and_test.py --llvm-bin 'C:\Users\Jonathan\AppData\Local\Android\Sdk\ndk\28.2.13676358\toolchains\llvm\prebuilt\windows-x86_64\bin'
```

Para repetir apenas os testes Python:

```powershell
python -m unittest discover -s tools/fel-readonly/tests -p 'test_*.py' -v
```

A CLI de `felro.py` aceita exclusivamente um caminho de imagem local para inspeção de GPT. Não há opções `--device`, `flash`, `unlock` ou conexão USB. Não usar um dump parcial de `super` como se fosse disco GPT completo.

## Restrições implementadas

### Payload

- Aceita apenas INFO e READ com protocolo próprio, CRC, sequência não nula e campos reservados zerados. Os códigos são próprios deste protótipo e não compatíveis com o script original.
- Rejeita operações inválidas antes da inicialização do hardware.
- Não contém os ramos de gravação, seleção Boot1/Boot2, RPMB ou correção de EXT_CSD do original.
- O gateway de comandos MMC admite somente 0, 1, 2, 3, 7, 8, 13 e 17, com argumentos restritos. Não admite CMD6, CMD24, CMD25, erase ou comandos de fabricante.
- Usa caminho conservador de 1 bit e aproximadamente 400 kHz, sem promoção de frequência. Não modifica a largura do cartão; se ela não for compatível, a leitura deve falhar, sem tentar ajustá-la.
- Consulta EXT_CSD para identificar capacidade e área atual. Ler esse registro não significa programá-lo. Área diferente da de usuário ou largura diferente de zero bloqueiam a extração.
- Trata erros de resposta, CRC, timeout, FIFO e limites como falha. Não ignora END_ERR. Não escreve watchdog, RTC ou PMIC.
- A configuração volátil de pinmux, clocks e controlador ainda existe no candidato: ela requer confirmação específica de hardware antes de uso.

### Programa do PC

- Exige um único transporte e hash do payload; vincula cada sessão à capacidade/CID/configuração informados.
- Verifica versão, CRC do cabeçalho e dos dados, sequência, LBA, contagem, tamanho, área, estado e identidade. Não reutiliza resposta com sequência antiga.
- Envelope de upload permite somente código identificado até `0x28000` e requisição de 32 bytes em `0x2ff00`; execução é limitada à entrada `0x20000`. Trata-se de um validador puro para o futuro adaptador, **não** uma proteção já aplicada a um USB real.
- Valida MBR protetor, assinatura e CRCs da GPT, localização/tamanho reais do array, LBAs de 64 bits, nomes/GUIDs duplicados, sobreposição e limites. Compara GPT primária e secundária.
- A aquisição de partição reconsulta a GPT e usa lista explícita de partições de firmware. Não oferece aquisição arbitrária por CLI nem inclui `userdata`, FRP, `private`, `metadata` ou Secure Storage nessa lista.
- Faz duas requisições independentes por bloco e compara os bytes. Guarda hashes e diário; falhas deixam `.partial`, sem publicar imagem final. Recusa sobrescrita e retomada automática.
- Publica o nome final com hard link exclusivo no PC. A cópia `.partial` completa é preservada como evidência e aponta para o mesmo arquivo; isso requer suporte do sistema de arquivos local. Não equivale a duas cópias de backup.

## Binários gerados e bloqueio padrão

| Binário | Tamanho | Comportamento |
|---|---:|---|
| `build/locked.bin` | 852 bytes | Requisição válida retorna `RO_LOCKED` antes de inicializar hardware; controlador removido pela coleta de seções não usadas |
| `build/candidate-NOT-FOR-DEVICE.bin` | 3820 bytes | Candidato experimental com caminho do controlador, gerado somente para revisão e desassemblagem |

O macro `RO_BOARD_APPROVED` foi definido **somente para gerar o candidato de análise**; seu nome não constitui aprovação do hardware. O binário bloqueado também não deve ser carregado: até sua entrada usa endereços de RAM e pilha ainda não confirmados no tablet.

Mapa proposto para análise, não validado fisicamente:

| Uso | Intervalo |
|---|---|
| Código | `0x20000` até no máximo `0x28000`, fim exclusivo |
| Requisição | `0x2ff00` até `0x2ff20` |
| Resposta | `0x2ff40` até `0x2ff90` |
| Dados | `0x30000` até `0x40000` |
| Pilha reservada na revisão | `0x57000` até `0x58000` |

Linker verifica entrada, limite do código e ausência de BSS global. Entrada preserva r4–r11, LR e SP conforme a convenção de chamada adotada; mantém alinhamento de 8 bytes e retorna à BROM. Compatibilidade efetiva com o contexto da BROM permanece não testada.

## Resultados e alcance

Rodada atual: **51 testes Python, 323 verificações do núcleo C, 64 do modelo do controlador e 4 do bloqueio padrão; zero falhas/erros nos casos executados**. Uma classe com sete casos da ABI nativa foi ignorada por bloqueio do Windows (4551). Os testes Python executados incluem transporte FEL e WinUSB substituto, com subcasos de falha. Nenhuma API USB nativa foi executada.

O C foi executado nativamente em x86_64 no PC, com HAL ou registradores simulados. Os binários ARM também passaram por 120 cenários de emulação AArch32 no PC; a rotina de I-cache de referência passou por seis cenários de registradores. Nenhum ARM físico ou tablet foi acessado. O emulador não modela caches físicos, TrustZone, BROM ou configuração elétrica e não demonstra a disponibilidade real da SRAM.

As verificações do build incluem ELF ARM little-endian, entrada `0x20000`, símbolos externos ausentes, código dentro da janela e rejeição de instruções VFP/NEON. O limite conservador de pilha calculado pela soma dos frames estáticos do candidato mais a entrada é 944 bytes; o grafo revisado não tem recursão. Isso valida consistência do layout proposto, não disponibilidade física dessas regiões.

## O que falta antes do FEL

1. Confirmar ocupação/proteção da SRAM e pilha no contexto real. O mapa do fabricante respalda os intervalos propostos, mas não comprova sua disponibilidade; pinmux e configuração elétrica continuam pendentes.
2. Verificar o modo USB real da unidade. Nas fontes, o A523 é `0x1890` (bruto `0x00189000`); `0x1859` pertence a outra família. O relato `1f3a:1010` não demonstra FEL BootROM `1f3a:efe8`.
3. Revisar a ABI e o comportamento do backend WinUSB nativo. O transporte já está implementado, mas testado com substitutos; não há enumeração nem abertura real habilitadas.
4. Validar temporização, cache/barreiras, comportamento FIFO, estado de largura/área do cartão e retorno à BROM. Se o cartão exigir CMD6 ou outra configuração além do admitido, parar e revisar o projeto; não habilitar comandos como tentativa.
5. Preparar identificação passiva, seleção única do dispositivo, procedimento de saída do FEL e janela de indisponibilidade. Somente depois, com autorização específica, considerar consulta de versão; carregar o leitor é uma etapa posterior.

Nenhum teste de restauração foi feito e não há garantia de recuperação se o primeiro payload falhar. A Etapa A do plano está concluída **quanto ao protótipo offline e testes descritos**, mas seu aceite integral continua bloqueado pelos itens de hardware/transporte acima, incluindo coerência de I-cache indicada nas fontes A523. Não avançar para execução com base apenas nos testes locais.

## Origem e licença

Configuração de SMHC baseada em A523-root, commit `6bd71e4c6181f3c6556e671794448efaa5e8a5f3`, preservando a licença MIT em `LICENSE`. O xfel `445e8aefe6914c85817cc9bd1d201629364b0ec6` foi referência de revisão, não é executado nem incluído como backend. As cópias originais e seus manifests estão em `analise-firmware/revisao-fel/`.
