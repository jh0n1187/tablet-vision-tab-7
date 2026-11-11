# Aprendizados confirmados

## Hardware e base de firmware

O nome T307F não garante hardware idêntico. A imagem stock de 2024 disponível usava configuração diferente da unidade de 2025, que possui Wi-Fi AIC8800. A customização final foi construída sobre a firmware adquirida desta unidade; não transplantar vendor/DTB/drivers de outra revisão.

A stock 2024 incompatível não é a base final. Os 31 sons já aprovados foram preservados como fontes locais pequenas, independentes da extração antiga. Imagens/extrações antigas não são necessárias para restaurar a base 2025 adquirida. Alguns scripts históricos ainda citam caminhos 2024 e não são o fluxo vigente.

## Backup e recuperação

DSU userdebug autenticada permitiu extrair firmware com UID0 mantendo SELinux Enforcing e ro.adb.secure=1. Ambas as propriedades em system e system_ext precisam ser conferidas: uma delas pode sobrescrever a outra. A GSI autoriza a chave pública do PC que a preparou; para outro PC é preciso tratar a autorização ou reconstruí-la, sem publicar chave ADB privada.

Backup confiável exigiu duas leituras coincidentes, re-hash local, GPT primária/secundária válidas e validação de geometria/metadados LP e cadeia AVB. `dd` por exec-out exige stderr separado do payload, para não anexar texto ao arquivo binário.

A DSU de uso único retorna ao Android normal ao reiniciar. `gsi_tool status=running` pode aparecer antes de `ro.gsid.image_running`; UI parada no logo não prova ausência de adbd/root. O retorno deve ser confirmado por ADB/build/boot_completed, sem depender da animação.

## Splash, aviso e carga

`bootloader_a` é uma FAT16 de recursos, não o executável U-Boot. O U-Boot real fica antes da primeira partição, dentro de contêiner seguro. Confundir os dois amplia drasticamente o risco.

O aviso ORANGE era `orange_warning.bmp` na FAT. Substituir seus pixels preservou o código, estado desbloqueado, verificações e meios de recuperação. A espera de aproximadamente 5 segundos está compilada no U-Boot 2025; `bootdelay` não controla esse laço. O modo de carga só é verificado depois da espera, por isso o aviso também aparecia carregando desligado. Não há prova de recuperação independente para autorizar um patch do executável.

A carga passa por recursos distintos: `bat/battery_charge.bmp` estático, splash e animação Android com percentual real. Trocar apenas bat0–bat10 e a animação vendor deixou um quadro branco antigo por ~0,4 segundo. Vídeo amostrado a cada 40ms identificou o arquivo. Foram revisados também battery.bmp, bempty.bmp e bat/bootlogo.bmp, onde havia um logo Allwinner A31 antigo.

O painel é montado em retrato sobre framebuffer nativo 1024×600. O quadro inicial aprovado exigia rotação de 270°. A preferência final foi preto nesse estágio, evitando mostrar bateria vazia antes de conhecer o nível real. Cabeçalhos completos BMP, dimensões, formatos, tamanhos e cadeias FAT foram preservados; todos os arquivos foram reextraídos e comparados.

## Tema e AVB

Tema não se limita ao wallpaper: RROs vendor, paleta dinâmica do SystemUI, nomes padrão, seleções/caches de som e recursos de carga também influem. Um RRO somente de recursos pode substituir a identidade visual sem reempacotar APKs de plataforma. Valores compilados de hardware do overlay original precisam permanecer idênticos.

O modo escuro efetivo neste BSP segue o recurso padrão, mesmo quando ui_night_mode não fica gravado na base de dados. Conferir `cmd uimode night` e persistência após reboot. Roboto nativo corresponde ao uso de system-ui no layout; não era necessário importar fontes do Windows.

Antes de instalar o conteúdo customizado, a aceitação da nova cadeia AVB foi testada com metadados novos apontando ainda para conteúdo stock conhecido. Flags permaneceram 0; árvores dm-verity foram reconstruídas; descritores e chaves encadeadas foram conferidos. Não reverter rollback indices nem relockar sem confiança comprovada na chave e recuperação.
