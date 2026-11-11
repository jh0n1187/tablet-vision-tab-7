"""Build a local visual review and asset-only drafts. Never patches firmware."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

root = Path(__file__).resolve().parents[2]
stock = root / 'analise-firmware/stock-URBR2024101701'
proposal = root / 'analise-firmware/central-inteligente/proposta-v2'


def uri(path):
    return 'data:image/png;base64,' + base64.b64encode(Path(path).read_bytes()).decode()


def zipped_images(path):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP CRC failure')
        return ['data:image/png;base64,' + base64.b64encode(archive.read(n)).decode()
                for n in sorted(archive.namelist()) if n.startswith('part0/') and n.endswith('.png')]


def sequence(directory, pattern, count):
    return [uri(directory / pattern.format(i)) for i in range(count)]


frames = sorted((proposal / 'boot-frames').glob('*.png'))
assert len(frames) == 167
with zipfile.ZipFile(proposal / 'bootanimation-RASCUNHO-NAO-INSTALAR.zip', 'w', compression=zipfile.ZIP_STORED) as archive:
    archive.writestr('desc.txt', '600 1024 14\np 0 0 part0\n')
    for frame in frames:
        assert struct.unpack('>II', frame.read_bytes()[16:24]) == (600, 1024)
        archive.write(frame, 'part0/' + frame.name)

raw = (proposal / 'battery-scale-packed-rascunho.png').read_bytes()
assert struct.unpack('>II', raw[16:24]) == (120, 1116)
text = b'Frames\x006'
chunk = struct.pack('>I', len(text)) + b'tEXt' + text + struct.pack('>I', zlib.crc32(b'tEXt' + text))
(proposal / 'battery_scale-RASCUNHO.png').write_bytes(raw[:33] + chunk + raw[33:])
configuration = (stock / 'erofs-extracted/vendor/etc/res/values/charger/animation.txt').read_text()
configuration = configuration.replace('percent_display: c c 255 0 0 255', 'percent_display: c c 234 240 241 255')
(proposal / 'animation-RASCUNHO.txt').write_text(configuration, encoding='utf-8')

stock_preview = stock / 'previews'
assets = {
    'boot': dict(title='Animação de inicialização', delay=1000 / 14,
                 original=zipped_images(stock / 'erofs-extracted/system/system/media/bootanimation.zip'),
                 proposed=[uri(p) for p in frames],
                 note='167 quadros, 14 fps. A proposta usa a evolução de revelação e brilho medida na original, aplicada somente à nova marca. Sem pontinhos de loading; a marca estabiliza ao final. A parada depende do serviço Android.'),
    'splash': dict(title='Splash inicial', delay=1000,
                   original=[uri(stock_preview / 'bootlogo-portrait.png')], proposed=[uri(proposal / 'splash-retrato.png')],
                   note='Proposta com identidade Central Inteligente. Há candidatos BMP 1024×600 em 32 e 24 bits, conforme os dois recursos da stock. Nenhum foi inserido na imagem.'),
    'charger': dict(title='Carga com o tablet desligado', delay=750, battery=True,
                    original=sequence(stock_preview, 'charger-{}.png', 6), proposed=sequence(proposal / 'charger-frames', 'frame-{}.png', 6),
                    note='Seis quadros de 120×186, 750 ms. Percentual simulado em área reservada; o arquivo gráfico não contém um percentual fixo. Esta prévia não emula o daemon, repetição inicial ou apagamento da tela.'),
    'boot_battery': dict(title='Bateria no bootloader', delay=750,
                         original=sequence(stock_preview, 'boot-battery-{}.png', 11), proposed=sequence(proposal / 'bootloader-battery', 'bat{}.png', 11),
                         note='11 níveis, 120×250: vermelho, âmbar e verde conforme a carga. Preenchimento contínuo, sem espaço reservado a percentual. A duração real no bootloader continua não determinada; a entrega é uma proposta PNG.'),
    'wallpaper': dict(title='Papel de parede padrão', delay=1000, fit=True,
                      original=[uri(stock_preview / 'wallpaper-vendor-original.png')], proposed=[uri(proposal / 'wallpaper.png')],
                      note='O padrão da stock vem de um overlay vendor. Para uso no tablet, definir o fundo pela API Android evita modificar APK e partição assinados. Nada foi definido no aparelho.'),
    'lock': dict(title='Fundo para tela de bloqueio', delay=1000, fit=True,
                 original=[uri(stock_preview / 'wallpaper-vendor-original.png')], proposed=[uri(proposal / 'lockscreen-fundo.png')],
                 note='O lado stock mostra o recurso de fundo disponível, não uma captura do bloqueio atual. A proposta deixa espaço livre para relógio e avisos reais do Android.'),
    'low': dict(title='Aviso de bateria baixa', delay=1000, fit=True,
                original=[uri(stock_preview / 'low-power-original.png')], proposed=[uri(proposal / 'bateria-baixa-conceito.png')],
                note='Conceito visual, não arquivo pronto para gravar. O recurso low_pwr original é 480×800; uma substituição futura precisa preservar o perfil usado pelo bootloader e os avisos de temperatura.'),
    'icon': dict(title='Ícone do app · opcional', delay=1000,
                 original=[], proposed=[uri(proposal / 'icone-app-conceito.png')],
                 note='Conceito para coerência visual. Não foi alterado o app kiosk, sua assinatura, Device Owner ou interface. A aplicação exigiria o projeto e a assinatura legítima do app.'),
}
html = '''<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';script-src 'unsafe-inline';img-src data:">
<title>Central Inteligente · revisão 02</title><style>
*{box-sizing:border-box}body{margin:0;background:#10171b;color:#eaf0f1;font:15px system-ui,sans-serif}main{max-width:1120px;margin:32px auto;padding:0 24px}
header{display:flex;justify-content:space-between;align-items:center;gap:15px}h1{font-size:27px;font-weight:500;letter-spacing:.04em;margin:0}p{color:#a2b2b8;line-height:1.6}small{color:#9cadb3}
.pill{font-size:11px;letter-spacing:.08em;color:#79dad4;background:#142a2c;border:1px solid #265456;border-radius:30px;padding:8px 13px;white-space:nowrap}
nav{display:flex;gap:8px;flex-wrap:wrap;margin:25px 0}button,select{font:inherit;border-radius:7px;padding:9px 12px;border:1px solid #33434b;color:#eaf0f1;background:#1a262c;cursor:pointer}button[aria-pressed=true]{color:#79dad4;border-color:#79dad4}
.views{display:grid;grid-template-columns:1fr 1fr;gap:26px}.card{background:#142025;border:1px solid #25373f;border-radius:12px;padding:15px;display:flex;align-items:center;flex-direction:column}
.card h2{font-size:14px;font-weight:400;letter-spacing:.05em;color:#a8bac1}.screen{max-height:57vh;max-width:100%;width:auto;aspect-ratio:600/1024;background:#000;border:1px solid #25343a;border-radius:7px}
.controls{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:18px}input{accent-color:#79dad4}#seek{flex:1;min-width:180px}output{font-variant-numeric:tabular-nums;color:#94a9b2}.notes{padding:14px 0;min-height:64px}
details{border-top:1px solid #2c3f48;margin-top:20px;padding-top:17px;color:#a2b2b8}li{margin:10px 0;line-height:1.5}a{color:#79dad4}.references{display:flex;gap:20px;flex-wrap:wrap;margin-top:20px}
@media(max-width:650px){main{padding:0 14px}header{display:block}.pill{display:inline-block;margin-top:12px}.views{gap:10px}.card{padding:6px}.screen{width:100%;max-height:none}.card h2{font-size:11px}}
</style><main><header><h1>CENTRAL INTELIGENTE</h1><span class="pill">REVISÃO 02 · NÃO APLICADA</span></header>
<p>Uma identidade para o painel da casa: fundo escuro, luz ciano discreta e poucos elementos. Compare os recursos da stock com a proposta.</p><nav id="tabs"></nav>
<div class="views"><div class="card"><h2>ORIGINAL DA STOCK</h2><canvas class="screen" id="before" width="600" height="1024"></canvas></div><div class="card"><h2>PROPOSTA · CENTRAL INTELIGENTE</h2><canvas class="screen" id="after" width="600" height="1024"></canvas></div></div>
<div class="controls"><button id="play">Pausar</button><button id="restart">Reiniciar prévia</button><input id="seek" aria-label="Quadro da proposta" type="range" min="0" value="0"><output id="count"></output></div>
<p id="note" class="notes"></p><small id="status">Carregando recursos locais…</small>
<details><summary>O que foi conferido e o que permanece pendente</summary><ul>
<li>Assinaturas AVB RSA-2048 e hashes/hashtrees da stock verificados no PC. As chaves das duas partições encadeadas correspondem aos descritores do topo.</li>
<li>A build stock é anterior à instalada. Bootloader registrado como bloqueado e verificação ativa. Confiança da chave no hardware, antirollback, revisão do painel/touch e aceitação de uma imagem alterada ainda não estão comprovados.</li>
<li>O arquivo é uma prévia de recursos, sem acesso ao tablet. Não modifica ROM, APK, driver, permissões, carga, limites térmicos ou política de energia.</li>
<li>Avisos de boot verificado, falha, manutenção e temperatura devem continuar claros. Recovery/desligamento não foram completamente auditados nos ramdisks; não há novo vídeo de desligamento separado nas três partições extraídas.</li>
</ul></details><div class="references"><a target="_blank" rel="noreferrer" href="https://www.home-assistant.io/blog/2024/03/04/dashboard-chapter-1/">Home Assistant · organização</a><a target="_blank" rel="noreferrer" href="https://support.google.com/googlehome/answer/9136992?hl=en-CA">Nest Hub · modo ambiente</a><a target="_blank" rel="noreferrer" href="https://support.apple.com/en-au/guide/iphone/iph878d77632/ios">StandBy · leitura e carga</a></div>
</main><script>
const assets=__ASSETS__;const before=document.getElementById('before'),after=document.getElementById('after'),seek=document.getElementById('seek'),play=document.getElementById('play');
let key='boot',loaded={original:[],proposed:[]},generation=0,start=performance.now(),elapsed=0,playing=true,ready=false;
function clear(canvas){const ctx=canvas.getContext('2d');ctx.fillStyle='#000';ctx.fillRect(0,0,600,1024);return ctx}
function paint(canvas,images,index,old){const ctx=clear(canvas),image=images[index];if(!image){ctx.fillStyle='#6c818b';ctx.textAlign='center';ctx.font='17px system-ui';ctx.fillText('Não se aplica nesta comparação',300,512);return}const spec=assets[key];let w=image.naturalWidth,h=image.naturalHeight;if(spec.fit){const scale=Math.min(600/w,1024/h);w*=scale;h*=scale}ctx.drawImage(image,(600-w)/2,(1024-h)/2,w,h);if(spec.battery){ctx.fillStyle=old?'#ff0000':'#eaf0f1';ctx.font='20px system-ui';ctx.textAlign='center';ctx.textBaseline='middle';ctx.fillText('62%',300,512)}}
function render(){if(!ready)return;const spec=assets[key];const t=playing?performance.now()-start:elapsed;const tick=Math.floor(t/spec.delay);const a=tick%loaded.original.length,b=tick%loaded.proposed.length;paint(before,loaded.original,a,true);paint(after,loaded.proposed,b,false);seek.value=b;document.getElementById('count').textContent=`Quadro ${b+1}/${loaded.proposed.length}`}
async function select(next){key=next;ready=false;const gen=++generation;document.querySelectorAll('nav button').forEach(button=>button.setAttribute('aria-pressed',button.dataset.key===key));document.getElementById('note').textContent=assets[key].note;document.getElementById('status').textContent='Carregando recursos locais…';const decode=url=>new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve(image);image.onerror=reject;image.src=url});const spec=assets[next];const values=await Promise.all([Promise.all(spec.original.map(decode)),Promise.all(spec.proposed.map(decode))]);if(gen!==generation)return;loaded={original:values[0],proposed:values[1]};seek.max=loaded.proposed.length-1;elapsed=0;start=performance.now();ready=true;document.getElementById('status').textContent=spec.battery?'Percentual demonstrativo. Não é leitura da bateria do tablet.':'Recursos carregados. Nada aplicado à imagem ou ao tablet.';render()}
for(const [name,spec] of Object.entries(assets)){const button=document.createElement('button');button.dataset.key=name;button.textContent=spec.title;button.onclick=()=>select(name).catch(fail);document.getElementById('tabs').append(button)}
function fail(){ready=false;document.getElementById('status').textContent='Falha na prévia: um recurso não pôde ser decodificado.'}
play.onclick=()=>{if(playing)elapsed=performance.now()-start;else start=performance.now()-elapsed;playing=!playing;play.textContent=playing?'Pausar':'Reproduzir';render()};document.getElementById('restart').onclick=()=>{elapsed=0;start=performance.now();render()};seek.oninput=()=>{elapsed=Number(seek.value)*assets[key].delay;start=performance.now()-elapsed;render()};
function loop(){render();requestAnimationFrame(loop)}select('boot').catch(fail);loop();
</script></html>'''.replace('__ASSETS__', json.dumps(assets, separators=(',', ':')))
(proposal / 'REVISAO-VISUAL.html').write_text(html, encoding='utf-8')
manifest = []
for path in sorted(proposal.rglob('*')):
    if path.is_file() and path.name != 'manifest.json':
        manifest.append({'file': str(path.relative_to(proposal)), 'bytes': path.stat().st_size,
                         'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
(proposal / 'manifest.json').write_text(json.dumps({'applied': False, 'files': manifest}, indent=2), encoding='utf-8')
print(json.dumps({'gallery': str(proposal / 'REVISAO-VISUAL.html'), 'assets': len(manifest), 'applied': False}))
