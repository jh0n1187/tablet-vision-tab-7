# Catálogo gerado e proposta de assinatura

> Estado atual: confiança importada nas duas lojas LocalMachine autorizadas; catálogo/INF verificados, assinatura `Valid`. ADB 4EE7 preservado; nenhum driver instalado ou reboot. Veja [resultado, evidências e reversão](RESULTADO-CONFIANCA.md). As referências abaixo à confiança pendente descrevem etapas anteriores.

Data: 09/11/2026. **Catálogo assinado localmente após aprovação expressa. Certificado temporário e chave privada removidos; confiança Windows não importada.** Nenhum driver foi instalado e o tablet não foi reiniciado nesta etapa.

## Resultado da assinatura autorizada

O SignTool assinou um único catálogo com SHA-256, sem erros/avisos. A verificação criptográfica CMS foi aprovada; o conteúdo do catálogo antes/depois é idêntico e o SignTool confirmou a participação do INF no catálogo. A validação padrão Windows retornou código 1 por raiz não confiável, como esperado sem importar confiança. Isso não deve ser interpretado como aprovação para instalação.

- Certificado público: `signing/homelab-fel-efe8-public.cer`.
- Thumbprint: `9169C63101332FE8064D63B31E70BAAEAA81D813`.
- Assunto: `CN=Homelab EFE8 Local Package`.
- Validade até **09/12/2026 às 11:46:55 em Cuiabá**; não há carimbo de tempo externo na assinatura.
- SHA-256 do catálogo assinado: `5c6fd1fbc5d52072fc3951434fd7836bb0969208d7e8f656a5b7860301f08c30`.
- Loja `CurrentUser\My` restaurada ao estado anterior e ausência da chave CNG confirmada.

Foram comparados os inventários imediatamente anterior/posterior: ADB `4EE7`, associação EFE8, arquivos WinUSB, INFs OEM e lojas Root/TrustedPublisher ficaram iguais. Não houve exportação de chave privada ou PFX; apenas o certificado público permanece em arquivo. Evidências em `signing/result.json`, `signing/verification-summary.json` e `signing/windows-trust-verification.txt`.

## Catálogo e origem das ferramentas

`package/homelab-fel-efe8.cat` foi gerado pelo Inf2Cat, não por MakeCat, e depois assinado conforme o resultado acima. A cópia original sem assinatura está em `signing/homelab-fel-efe8.unsigned.cat`, SHA-256 `760e00e1884de01cf55e955fd062bb12974dfe93dc4028f503f11769d5543427`.

O INF permanece com SHA-256 `5c3e0918dba26f4814723a87992f295210ca261be1c7d3961dd09df096bc987b` e uma única correspondência `USB\VID_1F3A&PID_EFE8`. Não foi acrescentado PID ADB ou wildcard.

Resultados:

- InfVerif `/w`: `INF is VALID`.
- Inf2Cat, perfil `10_GE_X64`: zero erros e avisos, catálogo gerado.
- Nova verificação Inf2Cat `/nocat`: aprovada.
- Parser nativo e oito testes de rejeição da etapa anterior: aprovados novamente.

As ferramentas foram extraídas localmente do pacote oficial `Microsoft.Windows.WDK.x64` versão `10.0.26100.6584`, obtido por HTTPS no NuGet. Foram extraídos somente Inf2Cat/dependências e InfVerif/dependências necessários, sem executar instalador ou registrar WDK. A assinatura de autor Microsoft e a contrassinatura do repositório NuGet foram verificadas pelo NuGet CLI portátil Microsoft, com resultado de sucesso. O arquivo `.nupkg` tem SHA-256 `c393d03dfb640b5c92f546b32f6770ef68cd3aaf691956e7d66d8e2c28a1b55e`. [Distribuição oficial](https://www.nuget.org/packages/Microsoft.Windows.WDK.x64/10.0.26100.6584), [Inf2Cat](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/inf2cat).

O certificado embutido de build interno do Inf2Cat não encadeia a uma raiz confiável neste PC. Não foi importada essa raiz nem alterada política para executá-lo; a origem do pacote foi verificada pela assinatura externa Microsoft/NuGet. A ferramenta rodou sob as políticas existentes. O InfVerif apresentou Authenticode válido da Microsoft.

O host `dotnet` existente não tem SDK; sua tentativa de verificação não funcionou. Nenhum SDK foi instalado. Para essa tentativa, a geração automática de certificado ASP.NET e alterações de PATH foram desativadas somente no ambiente do processo. A verificação bem-sucedida foi feita depois pelo `nuget.exe` portátil de origem Microsoft, com assinatura Authenticode válida, sem instalá-lo globalmente.

## Operação de certificado aprovada e executada

Não foi encontrado certificado de assinatura de código com chave privada nas lojas pessoais consultadas. Após apresentar a proposta, o usuário autorizou explicitamente criar um certificado temporário, assinar apenas o catálogo e destruir a chave ao final. O código está em `sign-local-catalog.ps1`; sem `-Apply`, ele apenas mostra a proposta. A execução autorizada com `-Apply` foi concluída.

| Local | Alteração autorizada e executada |
|---|---|
| `CurrentUser\My` | Adicionar temporariamente um certificado `CN=Homelab EFE8 Local Package`, RSA 3072/SHA-256, EKU de assinatura de código, válido por 30 dias |
| Armazenamento criptográfico do usuário | Criar uma chave CNG não exportável para esse certificado e removê-la após a assinatura |
| Arquivo `.cat` do projeto | Aplicar assinatura SHA-256, preservando cópia do catálogo sem assinatura |
| Pasta `signing/` do projeto | Guardar certificado **público** `.cer`, thumbprint, validade e registros de assinatura/limpeza |
| `Root` e `TrustedPublisher`, usuário/máquina | Nenhuma importação ou remoção nesta proposta |
| Proteções Windows, Driver Store, ADB e tablet | Nenhuma alteração |

O nome EFE8 no certificado é descritivo: certificados de assinatura não se restringem criptograficamente a um VID/PID. O script usa sua chave somente para esse catálogo, não a exporta e remove o certificado/chave ao final. Não será criado PFX com chave privada na pasta do projeto. [Criação de certificado de teste, Microsoft](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate).

O script recusa INF diferente do hash revisado, catálogo já assinado, SignTool sem assinatura Microsoft válida ou saída de assinatura preexistente. Ele seleciona o novo certificado por thumbprint exato; não usa outro certificado do usuário. A limpeza é limitada a esse thumbprint e verifica também a existência da chave CNG correspondente.

## Assinatura matemática não é confiança para instalação

A verificação criptográfica do CMS foi feita separadamente da confiança Windows e foi aprovada. **Sem importar confiança ou obter uma assinatura de publicação aceita, o catálogo continua não confiável para instalação.** Ele não é apresentado como driver Microsoft/WHQL.

Uma eventual rota de confiança local pode exigir adicionar o certificado público específico a lojas de confiança/publishers. Essa mudança tem efeito no PC além da pasta do projeto e precisa de avaliação/aprovação próprias; não está incluída na autorização solicitada para assinatura temporária. Mesmo com importação, políticas como WDAC podem impedir a instalação. Não se propõe desativar WDAC, Secure Boot, HVCI, antivírus ou verificação de assinatura, nem habilitar modo de teste.

Para publicação normal, seria necessário um processo de assinatura de driver aceito pela Microsoft. Não foi criada conta de publicação nem usado certificado de terceiros.

## Preservação confirmada até este ponto

`baseline/signing-before.json` e `baseline/catalog-after.json` foram comparados. Permaneceram iguais: associações PnP EFE8/4EE7, GUIDs inventariados, arquivos WinUSB, INFs OEM publicados e as quatro lojas de certificados Root/TrustedPublisher. A confirmação está em `baseline/catalog-preservation-check.json`.

Foi criado e removido somente o certificado temporário autorizado e sua chave privada. Nenhuma confiança foi importada, nenhum driver instalado e nenhum comando foi enviado ao tablet. O backend USB físico continua desabilitado. Importar confiança ou instalar o pacote não faz parte dessa autorização; qualquer etapa desse tipo exige revisão própria.

## Relação com remover Positivo e Toy Story

O driver prepara a comunicação de diagnóstico/leitura; não muda o Android, não remove aplicativos e não troca imagens de boot. A limpeza de aplicativos e o kiosk já foram feitos anteriormente.

A animação Android Toy Story já foi localizada no backup como ZIP de quadros PNG. Isso permite planejar uma animação visualmente mais limpa, mas a instalação de uma substituição ainda depende de acesso de escrita compatível com Verified Boot/AVB, permissões e montagem somente leitura do sistema. O bootloader desta unidade está bloqueado; não há garantia de que aceitará uma imagem alterada sem desbloqueio, possível limpeza de dados ou outras mudanças ainda não aprovadas.

O logo inicial, a animação Android e a imagem de carga/desligamento podem ter origens diferentes. Ainda não foi demonstrado onde todos os recursos da Positivo/Toy Story ficam nesta imagem nem quais são verificados/assinados. Extrair o firmware e localizar/verificar cada recurso continuam sendo pré-requisitos. Alterar a animação é principalmente uma mudança visual; não garante boot mais rápido ou Android mais novo.

Uma alternativa de menor impacto é aplicar identidade visual clean no app kiosk, que não remove o splash que aparece antes dele. Não foi feita nenhuma alteração de visual ou app nesta etapa de preparação de driver.
