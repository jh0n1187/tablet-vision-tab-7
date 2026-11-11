# Central Inteligente — Positivo Vision Tab 7 T307F

Customização aplicada e validada em uma unidade T307F com Allwinner A523 e Wi-Fi AIC8800, usando a própria firmware Android 14 de 2025 adquirida do aparelho.

**Estado final:** Central Inteligente T307F v3, recursos revisão 4. Modo escuro padrão, paleta da Central, Roboto original, 49 pacotes removidos e sons stock. A etapa inicial de carga é preta; depois aparecem splash Central e animação com percentual real. A imagem preta foi gravada e conferida, e o Android iniciou; a observação física da carga após essa última alteração ainda está pendente.

[Baixar imagem e conferir hashes](https://github.com/jh0n1187/tablet-vision-tab-7/releases/tag/central-v3-recursos-r4) · [Estado final](docs/ESTADO-FINAL.md) · [Aprendizados](docs/APRENDIZADOS.md) · [Recuperação](docs/RECUPERACAO.md)

## Imagem final

`T307F-Central-Inteligente-v3-particoes.zip` tem 1.156.783.101 bytes e SHA256:

```text
ee8ab269738765f5dab7e7a113a6698b920b0088d7cd12fe8ee7c80cd10f6cf1
```

É um conjunto de **13 partições nativas**, específico da base `T307TSF.BR.OPEN.2025092701` / A523-AIC8800. Não é OTA/TWRP nem contêiner PhoenixSuit. O ZIP inclui referências OEM de boot/recovery/módulos, sem instrução para regravá-las por padrão. Não há instalador universal ou garantia de compatibilidade com outra revisão do T307F.

O bootloader continua desbloqueado. O aviso gráfico foi substituído pelo splash na FAT de recursos; a pausa fixa de aproximadamente 5 segundos permanece. Código U-Boot/TOC, verificações e caminhos de recuperação não foram alterados.

## Conteúdo do repositório

- `tools/stock-inspection/`: aquisição DSU, inspeção, construção de recursos, AVB, escritores restritos e conferência de hashes.
- `tools/fel-readonly/` e demais ferramentas USB: código da investigação histórica; não constituem recuperação FEL validada.
- `scripts/`: ferramentas anteriores de diagnóstico, debloat e restauração. Conferir o alvo e o escopo antes de usar; os fluxos históricos não substituem o processo final documentado.
- `assets/central/`: recursos visuais aprovados, incluindo quadros de boot/carga e fundos.
- `docs/`: conclusões verificadas, limites, organização de backup e metadados da Release.

Os scripts foram feitos durante a investigação desta unidade. Vários dependem de backups, manifestos, SDK/NDK e artefatos **locais** que não estão no Git. Alguns são históricos e bloqueiam repetição por recibo ou hash de baseline. Não executar instaladores em sequência para tentar reproduzir o histórico.

Para os scripts ADB/fastboot que exigem alvo explícito:

```powershell
$env:T307F_SERIAL = '<serial mostrado por adb devices>'
```

Sem essa variável, o identificador de segurança é deliberadamente inválido. Não há seleção automática de outro aparelho. Os arquivos grandes ficam na Release conforme a [orientação do GitHub para binários](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).

## Backup e privacidade

O backup bruto original de 2025, DSU autenticada para este PC, logs, dados individuais e chaves privadas ficam fora do Git/Release. Na máquina de origem, `PARA-BACKUP/` reúne a customizada, 29 arquivos originais e a DSU, com manifesto e hashes. Essa pasta precisa ser copiada para outro disco para se tornar um backup independente.

A [organização completa do backup privado](docs/BACKUP-PRIVADO.md) reúne também fontes locais, artefatos de construção, pacotes USB e chaves criptografadas em uma única pasta, com conteúdo deduplicado, mapa de restauração e bundle offline do Git.

App da Central e kiosk são instalados/configurados separadamente pelo instalador do aplicativo. Não estão embutidos nesta imagem.
