# Central Inteligente T307F v3 — imagem final

Imagem instalada e conferida na unidade de origem. Base Android 14 de setembro de 2025, A523/AIC8800.

- 49 pacotes de bloat removidos; drivers, áudio, WebView, serviços essenciais e controles térmicos/carga preservados.
- Identidade Central Inteligente: fundos/animações aprovados, paleta do layout da central, Roboto e modo escuro padrão.
- Sons da stock 2024: todos os 31 OGGs conferidos. Overlay de fundo Toy Story substituído sem alterar os valores compilados de hardware.
- Nome do dispositivo padrão Central Inteligente; compilação Central Inteligente T307F v3. Fingerprint, modelo e SPL originais preservados.
- Sete partições modificadas com SHA256 integral conferido por DSU; dois boots normais e persistência do tema validados.

## Conteúdo e uso

Este ZIP contém partições nativas, NÃO um instalador OTA/TWRP nem imagem PhoenixSuit. É específico da base/hardware verificados; não presumir compatibilidade com outras revisões T307F.

`images/` inclui as seis partições OS/AVB modificadas e seis referências OEM preservadas de boot/recovery/módulos. As referências permitem verificar a cadeia AVB offline, mas não foram regravadas nesta instalação. `resources/bootloader_a.img` é apenas FAT de imagens de splash/carga; não é o U-Boot executável.

A instalação testada utiliza fastbootd para OS/AVB e DSU autenticada com endereço GPT e hashes verificados para a FAT, que fastbootd não abre. Use os scripts controlados e os recibos do projeto; nunca gravar esta FAT como TOC/U-Boot. Não há comando de erase, troca de slot ou factory reset nesta instalação.

Os backups OEM de recuperação ficam separados em `backup/firmware-2025-dsu-20261111T012532Z/`, com manifesto e dupla leitura. Eles não fazem parte deste ZIP e devem ser preservados. A restauração foi ensaiada de forma idempotente pelo bootloader, fastbootd e escritor FAT; não foi realizado um teste destrutivo integral nem clonagem de userdata/FBE/RPMB.

Revisão 2 dos recursos: os pixels de `orange_warning.bmp` foram substituídos pelo splash Central Inteligente. O estado ORANGE/desbloqueado e a pausa de cerca de 5 segundos continuam; a mudança é visual e também se aplica ao caminho de carga desligada. Código U-Boot/TOC, verificações e recursos de erro vermelho/amarelo não foram alterados. A FAT inteira foi lida de volta com SHA256 idêntico, prefixo GPT/U-Boot e FAT inativa ficaram idênticos, e o Android v3 reiniciou. O usuário confirmou o splash no reinício e enviou vídeo da carga desligada; o aviso em inglês não apareceu. Não bloquear o bootloader com esta ROM sem comprovar suporte à chave e recuperação. Referência: https://source.android.com/docs/security/features/verifiedboot/boot-flow

App da central e kiosk não são incluídos nem configurados por este pacote: pertencem ao instalador do aplicativo.

Chaves privadas e dados pessoais não foram incluídos.

## Recursos revisão 3 — quadros auxiliares de carga

O vídeo revelou um ícone branco antigo por cerca de 0,4 segundo antes do splash. `bat/battery_charge.bmp` agora reutiliza o primeiro quadro da carga aprovada, com rotação nativa correta. Também foram atualizados os recursos estáticos battery.bmp, bempty.bmp e o logo A31 antigo de bat/bootlogo.bmp. Os demais 28 arquivos da FAT, incluindo animações, avisos de temperatura e Verified Boot, ficaram intactos. A FAT foi gravada com hash integral conferido, sem alterar GPT/U-Boot/FAT inativa, e Android normal reiniciou. O usuário confirmou a sequência da revisão 3: bateria inicial, splash Central e carga com percentual real.

## Recursos revisão 4 — etapa inicial preta

A pedido do usuário, somente os pixels de `bat/battery_charge.bmp` foram zerados para preto, preservando todo o cabeçalho BMP e a estrutura FAT. A sequência agora deve ser preto, splash Central e animação Android com percentual real. Nenhum outro recurso, código ou tempo de boot mudou. Gravação integral conferida por SHA256, GPT/U-Boot e FAT inativa idênticos, novo boot Android normal validado. A observação física da carga após esta revisão ainda está pendente.
