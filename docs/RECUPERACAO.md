# Backup e recuperação: o que foi validado

O backup original de 2025 contém 29 arquivos, aproximadamente 5,38 GB: prefixo de 36 MiB com GPT/early boot, último MiB, boot/init_boot/vendor_boot/AVB dos dois slots, recursos FAT, env, super completa e partições auxiliares. Não inclui clone portátil de userdata/FBE/RPMB. Contém dados específicos da unidade e fica privado.

Cada captura estável passou por duas leituras coincidentes e SHA256 local. GPT primária e secundária foram conferidas, assim como metadados LP e cadeia AVB das partições extraídas.

| Caminho | Ensaio físico realizado | Limite |
| --- | --- | --- |
| U-Boot fastboot | Regravação idêntica de vbmeta_b inativa e hash por DSU | Depende do early boot funcionar |
| Fastbootd | Entrada pelo bootloader sem Android; regravação idêntica de system_dlkm_a e hash em novo DSU | Não é restauração destrutiva integral |
| DSU autenticada | Regravação idêntica de FAT B; atualizações FAT A com readback e rollback preparado | Exige boot chain e DSU disponíveis |
| Android normal | Retorno da DSU e boots das imagens customizadas com dados preservados | Não prova recuperação de early boot danificado |

FEL não foi validado: a interface observada devolveu ACK zero inválido. Testes/emulação de adaptadores em RAM não viraram recovery funcional. Não há dongle CM2 disponível. Portanto possuir os bytes do backup não garante restaurar um U-Boot/TOC danificado. Nenhum patch de executável, relock, RPMB ou eFuse foi feito.

## Pasta local para copiar

`tools/stock-inspection/organize_backup.py` organiza `PARA-BACKUP/` com validação integral antes de criar arquivos:

1. `01-CUSTOMIZADA`: ZIP final, FAT atual separada, metadados e hashes.
2. `02-ORIGINAL-2025`: 29 arquivos originais e manifesto.
3. `03-DSU-AUTENTICADA`: GSI temporária autenticada e recibos dos ensaios.

Arquivos grandes usam hardlinks no mesmo volume para economizar espaço. Copiar normalmente a pasta para outro disco produz a cópia independente; conferir os hashes na cópia. Não editar esses links locais. A pasta organizada no mesmo disco ainda não é um segundo backup.

Nunca gravar a GSI DSU em partição física. Não executar o ZIP de partições como OTA/PhoenixSuit. A restauração exige conferir unidade, revisão de hardware, serial explícito, slot, GPT, capacidade e hashes; não apagar userdata ou trocar slot como tentativa genérica.

## Ferramentas históricas

Os scripts possuem gates, baselines e recibos específicos. Uma execução concluída geralmente bloqueia repetição. Dependências SDK/NDK, Docker/WSL e artefatos locais não vêm no Git. Compilar ou executar testes offline dos leitores não autoriza automaticamente acesso ao dispositivo ou gravação. As referências históricas em `analise-firmware/` são arquivos locais e não acompanham o repositório público.
