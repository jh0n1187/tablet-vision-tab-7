# Estado final confirmado

Base OEM: Android 14, `T307TSF.BR.OPEN.2025092701`, patch 2025-08-05, A523/AIC8800. Compilação apresentada: `Central Inteligente T307F v3`; fingerprint, modelo e SPL originais preservados. Slot A; bootloader desbloqueado/orange; build user, ro.debuggable=0, ADB autenticado e SELinux/dm-verity Enforcing. DSU autenticada instalada e desativada.

## Alterações

- 49 pacotes de bloat removidos; GMS/WebView, conectividade, áudio, controles térmicos/carga e recuperação preservados.
- Paleta do layout da Central: fundo `#0b1620`, cartões `#102233`/`#14293c`, texto `#e6edf3`, secundário `#8b9bab`, azul `#60a5fa`, lilás `#a78bfa` e ciano `#24DAFF`.
- Roboto e fallback originais; modo escuro padrão por `config_defaultNightMode=2`; cores fixas, sem paleta antiga derivada do papel de parede.
- Quatro RROs apenas de recursos. Overlay Disney substituído preservando os valores de hardware compilados, alterando o nome de pacote e três fundos. APKs de plataforma não foram reempacotados.
- Todos os 31 OGGs conferidos contra a referência stock. Quatro sons personalizados substituídos; caches de toques também migrados.
- Nomes padrão do dispositivo e compilação Central Inteligente; fundos, boot e carga com recursos aprovados.

## Revisões da FAT

1. Splash e quadros de bateria aprovados.
2. `orange_warning.bmp` recebe os pixels do splash Central; avisos vermelho/amarelo e código U-Boot intactos. Usuário confirmou o resultado no reinício e em vídeo da carga desligada.
3. Corrigidos os quatro recursos estáticos de carga que restaram antigos, incluindo o ícone branco com raio e um logo A31 de reserva. Usuário confirmou a sequência bateria inicial → splash → carga com percentual real.
4. A pedido do usuário, apenas `bat/battery_charge.bmp` ficou preto, mantendo seu cabeçalho e os outros 31 arquivos. Sequência esperada: preto → splash → animação com percentual real. A observação física desta última revisão ainda está pendente.

FAT atual revisão 4: SHA256 `284fc6f6c87b292d671367ae1af98683b95b1b4e6e872e490651b2916f5c15d9`.

## Evidências e limites

As seis partições OS/AVB e a FAT inicial foram integralmente lidas por DSU e seus SHA256 coincidiram com os arquivos preparados. Cada revisão posterior da FAT passou por nova leitura/hash integral; prefixo GPT/U-Boot de 36 MiB e FAT inativa ficaram idênticos antes/depois. Foram conferidos todos os arquivos da FAT, não apenas seu hash externo. Treze payloads da Release passaram pela leitura/hash de retorno do ZIP.

Android iniciou repetidas vezes e manteve o perfil; Wi-Fi reconectou e rotas de alto-falante/microfone foram observadas. Não houve teste físico de gravação de áudio. Captura ADB preta sob kiosk não foi tratada como falha de tela: o usuário confirmou interface normal.

AVB usa chave própria, flags 0 e dm-verity mantido. Suporte de bootloader bloqueado à chave própria não foi comprovado. A chave AVB privada temporária foi removida após assinatura. Não houve wipe adicional nesta instalação, troca de slot ou flash de kernel/recovery/TOC/U-Boot/RPMB/eFuses.

Metadados públicos e SHA256 do pacote estão em [release/](release/). Backups privados e recibos operacionais completos permanecem na máquina de origem.
