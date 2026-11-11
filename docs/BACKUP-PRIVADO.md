# Uma única pasta para o backup externo

Copie somente **PARA-BACKUP inteira** para um HD externo ou armazenamento privado. O conjunto reúne as imagens finais, backup original, DSU, insumos locais de construção e metadados. **As chaves privadas foram omitidas por escolha do usuário; não é necessária senha para copiar este conjunto.** Os arquivos de trabalho podem continuar em `backup/` e `analise-firmware/`; não é necessário copiar essas pastas separadamente depois da consolidação completa.

| Pasta/arquivo | Conteúdo |
| --- | --- |
| `01-CUSTOMIZADA` | ZIP final revisão 4, FAT separada e hashes |
| `02-ORIGINAL-2025` | Backup OEM adquirido e verificado |
| `03-DSU-AUTENTICADA` | GSI temporária autenticada e recibos |
| `04-CHAVES` (opcional) | Omitida nesta cópia; pode ser criada por exportação criptografada futura |
| `05-REPRODUCAO` | Fontes Git em bundle, restaurador e objetos privados deduplicados |
| `MANIFESTO-COMPLETO.json` | Mapa de conteúdos, caminhos de restauração e SHA256 |

O conjunto é privado e não deve ser publicado. Não há senha ou chave privada em texto no Git. Não basta copiar apenas o antigo manifesto de 41 arquivos: a consolidação acrescenta os insumos de reprodução e o manifesto completo. As imagens já assinadas podem ser reaplicadas sem a chave privada. Novas assinaturas exigem chave nova ou a chave mantida no PC original; para outro PC, a DSU antiga pode precisar ser reconstruída para autorizar a nova chave pública ADB.

## Verificar a cópia no HD

Com Python 3 instalado, execute o restaurador que acompanha a pasta, apontando para a cópia externa:

```powershell
python E:\PARA-BACKUP\05-REPRODUCAO\restaurar.py --backup E:\PARA-BACKUP
```

Esse comando somente confere todos os conteúdos e hashes. Não grava no tablet. A pasta no disco original usa links para grandes imagens imutáveis, poupando espaço; só a cópia para outro disco é um backup independente. Os arquivos pequenos mutáveis foram congelados como cópias separadas. Não editar imagens através dos links locais.

## Restaurar em outro computador

Instale Git e Python 3. Clone o repositório ou deixe o restaurador clonar o bundle offline em uma pasta nova:

```powershell
python E:\PARA-BACKUP\05-REPRODUCAO\restaurar.py --backup E:\PARA-BACKUP --destination C:\projetos\tablet-positivo --execute
```

O restaurador confere todo o backup antes de escrever, preserva arquivos existentes diferentes e ajusta os dois arquivos de localização do backup à pasta nova. Não executa ADB/fastboot. Os caminhos e arquivos de origem são restaurados a partir do mapa, sem exigir nomes legíveis nos objetos deduplicados.

Somente se tiver feito uma exportação OPCIONAL das chaves, é possível restaurar a mesma identidade de assinatura no novo perfil Windows usando **PowerShell 7** e senha na janela local. Essa etapa não se aplica ao backup atual sem chaves:

```powershell
C:\projetos\tablet-positivo\tools\stock-inspection\portable_private_keys.ps1 -Mode Restore -Bundle E:\PARA-BACKUP\04-CHAVES\central-private-keys.encrypted.json -ProjectRoot C:\projetos\tablet-positivo
```

O PKCS12 mantém a chave original; sua senha volta a ser protegida pelo DPAPI do novo perfil. A chave ADB é restaurada separadamente em `backup/private-signing/adb`, sem substituir a configuração ADB do PC. Se for necessário usar a DSU antiga, que autoriza a chave original, configure o servidor ADB para carregar essa chave via `ADB_VENDOR_KEYS`. Outra opção é reconstruir a DSU com a chave pública do PC novo. Não copiar a chave privada para o Git.

## Ferramentas reinstaláveis e limites

O backup preserva os insumos específicos e as receitas, mas não clona Windows, SDK/JDK, WSL ou Docker. O fluxo original usou Android SDK build-tools 36.0.0, android.jar 34/36, Android Studio JBR, NDK 28.2.13676358, WSL Ubuntu, Python, OpenSSL e o builder EROFS 1.7.1. O tar fonte EROFS necessário ao Dockerfile acompanha os objetos privados. Os pacotes USB usados também estão no mapa; conferir assinatura/validade antes de reinstalar, sem desativar controles do Windows.

A configuração CSS da Central foi copiada para `aprovado-v2/estilo-referencia.css`; a construção do tema não depende mais de outro projeto no computador original.

As imagens finais assinadas estão preservadas. A chave AVB privada temporária foi descartada depois da assinatura original, por projeto; reconstruir conteúdo exige gerar nova cadeia AVB compatível com o bootloader desbloqueado. O conjunto não promete reprodução byte a byte de nova assinatura nem instalação universal. Scripts históricos têm baselines/recibos e não devem ser executados em sequência para repetir o histórico.
