"""Create the reviewable offline cleanup report from actual receipts."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[2]
folder = root / 'analise-firmware/central-inteligente/limpeza'
plan = json.loads((folder / 'plano-limpeza.json').read_text(encoding='utf-8'))
result = json.loads((folder / 'resultado-copia.json').read_text())
audit = json.loads((folder / 'auditoria-background.json').read_text(encoding='utf-8'))
if result['retained_apks_hash_checked'] != plan['retained_apk_files']:
    raise ValueError('Retained application validation incomplete')
signals = {r['package']: r['startup_signals'] for r in audit['apps']}
oem_count = sum(r['category'] == 'OEM/fábrica' for r in plan['removed'])
lines = [
    '# Limpeza da base stock — Central Inteligente', '',
    '09/11/2026. Perfil para o app da central e assistente próprio, com cliente no app e backend no servidor. Nenhum comando enviado ao tablet.', '',
    '## Resultado concreto', '',
    f"- Inventário: {plan['source_apk_files']} APKs / {plan['source_packages']} pacotes.",
    f"- Cópia filtrada dos aplicativos criada em `aplicativos-retidos/`: {plan['removed_packages']} pacotes excluídos, dos quais {oem_count} são OEM/fábrica.",
    f"- {result['retained_apks_hash_checked']} APKs restantes comparados por SHA-256 com os originais, sem diferença.",
    f"- Conteúdo omitido, incluindo arquivos auxiliares das pastas: {plan['removed_bytes_with_sidecars']:,} bytes ({plan['removed_bytes_with_sidecars']/1024**3:.2f} GiB). Isso não representa RAM liberada nem espaço adicional garantido em userdata.",
    f"- {audit['removed_apps_with_startup_signals']} pacotes removidos declaram ações de boot, desbloqueio, troca de pacote ou mudança de rede. Manifestos em `manifestos/`.", '',
    '**A imagem .img original não foi alterada. Ainda não foi reconstruída uma imagem EROFS/AVB limpa.** A entrega desta etapa é a seleção de exclusões e uma cópia somente das árvores dos aplicativos retidos, não o sistema completo ou firmware instalável.', '',
    '## O que permanece', '',
    'WebView, Chrome, Trichrome, serviços de rede/Wi-Fi/Bluetooth, teclado, microfone/áudio, TTS como fallback, serviços Google e Play Store para compatibilidade/manutenção, configurações, SystemUI, permissões/certificados, providers de mídia/contatos/agenda e provisionamento Device Owner. Não foram removidos HALs, drivers, bibliotecas de áudio/câmera ou componentes APEX.', '',
    'Os overlays de recursos e componentes Softwinner de integração/configuração/screenshot não foram excluídos somente pelo nome. Em especial, AwManager/SettingsSetup são mantidos até validação de suas dependências; não representam os testes e atualizadores selecionados para remoção.', '',
    'Google Assistente/Google Go independentes não são necessários ao assistente próprio informado pelo usuário. O APK do backup da central declara INTERNET, WAKE_LOCK e RECORD_AUDIO; foram encontrados termos WebSocket no DEX, mas não referências diretas às classes Android SpeechRecognizer/TextToSpeech. Essa inspeção estática não prova a ausência de dependências na implementação web ou numa versão mais recente do cliente.', '',
    'O APK `br.homelab.central` do backup foi preservado à parte em `cliente-central-preservado/`, sem alteração de pacote ou assinatura. Ele não está incluído na stock e não foi instalado nem automaticamente configurado como Device Owner nesta etapa.', '',
    '## Fluidez, CPU, RAM e bateria', '',
    'O foco é evitar que diagnósticos/testes, atualizadores OEM e apps de uso geral voltem a registrar tarefas e receber eventos numa instalação limpa. A presença de receivers/serviços no manifesto não prova que estejam rodando nem mede seu consumo. Parte desses pacotes já estava desativada pela limpeza anterior do tablet, portanto o ganho adicional sobre o estado atual pode ser menor que a diferença em relação à stock de fábrica.', '',
    'Não houve benchmark ou medição de RAM, CPU, corrente, fluidez ou autonomia nesta etapa. Não foram alterados Doze, restrições globais de segundo plano, políticas térmicas, limites de carga ou as permissões de microfone do app. Captura contínua, wakelocks, renderização WebView e transporte de áudio do cliente devem ser medidos no cenário real, preservando a escuta de voz.', '',
    'Critérios para validação posterior: tempo até o painel utilizável, frames lentos ao navegar, PSS do app/WebView, CPU em repouso e durante voz, wakelocks/tráfego de áudio e tendência de bateria sob o mesmo brilho/Wi-Fi/carregador. Não confundir redução de APKs com ganho automático nessas métricas.', '',
    '## Mudanças funcionais relevantes', '',
    '- A cópia não inclui os três atualizadores OEM (Positivo FOTA, Wi-Fi e Local Update), já desativados no backup. Atualizações futuras de firmware precisarão de fluxo controlado; o mecanismo não foi alterado no tablet atual.',
    '- Saem apps independentes como câmera, QR scanner, Meet, Gmail, Maps, YouTube/YouTube Music, livros, jogos e testes. Navegação e conteúdo de mídia por WebView não foram removidos.',
    '- APKPure não aparece nesta stock; não foi criado um registro fictício de remoção dele. Ele consta apenas no backup do aparelho.', '',
    '## Pendências antes de gerar/gravar firmware', '',
    'A extração inicial em NTFS não é fonte confiável de ownership Linux, permissões, capabilities e SELinux para remontagem. As imagens EROFS originais são a autoridade desses metadados. Uma cópia completa da árvore esbarrou em permissões do compartilhamento; optou-se por preservar os originais e entregar a árvore de apps validada. A reconstrução deve recuperar/verificar esses metadados antes de emitir um novo .img.', '',
    'As assinaturas AVB da stock passaram anteriormente, mas serão invalidadas por alterações nas partições. Continuam pendentes a rota de instalação/recuperação, confiança da chave, antirollback e compatibilidade da build antiga com esta unidade. Nenhuma imagem alterada foi apresentada como pronta para flash.', '',
    'Duas cópias completas temporárias ficaram incompletas. A exclusão delas foi rejeitada pela revisão automática com a mensagem “blocked by policy”. Permanecem marcadas como incompletas, separadas de `aplicativos-retidos/`; não devem ser usadas em builds.', '',
    '## Pacotes excluídos da cópia de apps', '',
    '| Pacote | Motivo | APK MiB | Ações declaradas |',
    '|---|---|---:|---|',
]
for row in plan['removed']:
    lines.append(f"| `{row['package']}` | {row['reason']} | {row['bytes']/1024**2:.1f} | {', '.join(signals[row['package']]) or '—'} |")
lines += ['', 'Recibos: `plano-limpeza.json`, `resultado-copia.json`, `inventario-apks.csv` e `auditoria-background.json`. A auditoria é estática; o contador de serviços declarados não deve ser interpretado como serviços ativos.', '']
(folder / 'RESULTADO.md').write_text('\n'.join(lines), encoding='utf-8')
for name in ('copia-incompleta-1', 'copia-trabalho'):
    path = folder / name
    if path.is_dir():
        (path / 'INCOMPLETA-NAO-USAR.txt').write_text('Cópia incompleta. Não é fonte de build. Use o plano de limpeza e aplicativos-retidos; metadados originais devem vir das imagens EROFS.\n', encoding='utf-8')
print(json.dumps({'report': str(folder / 'RESULTADO.md'), 'removed_packages': plan['removed_packages'],
                  'oem_factory_packages': oem_count, 'retained_sha256_checks': result['retained_apks_hash_checked'],
                  'source_img_modified': False, 'device_accessed': False}, ensure_ascii=False))
