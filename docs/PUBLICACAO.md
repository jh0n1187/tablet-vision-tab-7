# Organização e publicação

O Git contém fontes próprios, código de inspeção com seus avisos de licença preservados, documentação consolidada, 190 PNGs aprovados e metadados da imagem final. Dependências baixadas, pacotes de driver, builds, dumps, logs, capturas USB e arquivos específicos do PC não são versionados.

A imagem customizada fica anexada à [Release central-v3-recursos-r4](https://github.com/jh0n1187/tablet-vision-tab-7/releases/tag/central-v3-recursos-r4), junto dos metadados e SHA256. Ela foi construída sem userdata, credenciais, chaves privadas, GPT, TOC/U-Boot, RPMB ou partições individuais de armazenamento seguro. As referências OEM de boot/recovery/módulos são as da base verificada, sem alterações no código.

A Release foi confirmada pública. Os cinco anexos tiveram seus tamanhos e os digests SHA256 retornados pelo GitHub comparados com os arquivos locais; todos coincidiram. Recibo: [release/GITHUB-VERIFIED.json](release/GITHUB-VERIFIED.json). A publicação não muda o limite documentado de recuperação nem substitui o backup privado.

O backup bruto original de 2025 contém partições únicas desta unidade e fica privado. A DSU autenticada contém a chave pública ADB do PC que a preparou e também fica no backup privado. Não distribuir esses arquivos junto da imagem customizada.

Na máquina de origem, `PARA-BACKUP/` reúne 41 arquivos, 7.680.490.612 bytes lógicos, com todos os hashes conferidos. A organização usa links no mesmo volume para evitar duplicação; copiar para outro disco é necessário para ter uma cópia independente. Leia o guia nessa pasta antes de mover ou editar os arquivos.
