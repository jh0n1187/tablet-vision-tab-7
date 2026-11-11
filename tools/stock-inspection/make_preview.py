"""Make a self-contained offline viewer of extracted, unmodified visual assets."""
import base64
import hashlib
import json
from pathlib import Path
import struct
import zipfile

root = Path(__file__).resolve().parents[2] / 'analise-firmware/stock-URBR2024101701'
preview = root / 'previews'


def png(data):
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Expected PNG')
    return 'data:image/png;base64,' + base64.b64encode(data).decode('ascii')


with zipfile.ZipFile(root / 'erofs-extracted/system/system/media/bootanimation.zip') as archive:
    if archive.testzip() is not None or archive.read('desc.txt').decode().splitlines() != ['600 1024 14', 'p 0 0 part0']:
        raise ValueError('Unexpected or damaged animation')
    names = sorted(n for n in archive.namelist() if n.startswith('part0/') and n.endswith('.png'))
    frames = [archive.read(name) for name in names]
    if len(frames) != 167 or any(struct.unpack('>II', data[16:24]) != (600, 1024) for data in frames):
        raise ValueError('Unexpected frame count/geometry')

assets = {
    'boot': {'label': 'Inicialização · POSITIVO VISION TAB 7', 'delay': 1000 / 14,
             'note': '167 quadros originais, 600 × 1024, 14 fps. Reprodução em loop conforme desc.txt.',
             'images': [png(data) for data in frames]},
    'charger': {'label': 'Carga com Android desligado · vendor', 'delay': 750,
                'note': '6 quadros originais, 120 × 186, 750 ms. Prévia em sequência: a seleção por nível, repetição inicial e apagamento dependem do carregador. A fonte de percentual não é reproduzida.',
                'images': [png((preview / f'charger-{i}.png').read_bytes()) for i in range(6)]},
    'boot_battery': {'label': 'Bateria · recursos do bootloader', 'delay': 750,
                     'note': '11 imagens bat0–bat10, 120 × 250. Sequência ilustrativa: a ordem operacional e a duração no bootloader ainda não foram confirmadas.',
                     'images': [png((preview / f'boot-battery-{i}.png').read_bytes()) for i in range(11)]},
    'splash': {'label': 'Splash inicial · POSITIVO', 'delay': 1000,
               'note': 'bootlogo.bmp original, convertido para PNG e girado para apresentação em retrato. A imagem stock não foi alterada.',
               'images': [png((preview / 'bootlogo-portrait.png').read_bytes())]},
}

page = '''<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'unsafe-inline';style-src 'unsafe-inline';img-src data:">
<title>T307F · recursos da imagem stock</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#111315;color:#e4e7eb;font:16px system-ui,sans-serif}
main{max-width:1000px;margin:28px auto;padding:0 22px}h1{font-size:25px;margin-bottom:8px}
p{line-height:1.5;color:#b7c0c9}section{display:grid;grid-template-columns:minmax(240px,400px) 1fr;gap:28px;align-items:start}
canvas{width:100%;height:auto;background:#000;border:1px solid #333;border-radius:14px}
select,button{padding:12px;border:1px solid #4a525b;border-radius:8px;color:#fff;background:#23272c;font:inherit}
select{width:100%;margin-bottom:16px}button{cursor:pointer}input{width:100%;margin:20px 0}
small{color:#a3adb7}output{display:block;margin-top:10px;font-variant-numeric:tabular-nums}
@media(max-width:660px){section{display:flex;flex-direction:column-reverse}canvas{max-width:360px;align-self:center}}
</style><main><h1>Recursos originais · Positivo T307F</h1>
<p>Build URBR2024101701 · Android 14 · Visualização local dos arquivos extraídos. Não é emulação do tablet nem teste de instalação.</p>
<section><canvas id="screen" width="600" height="1024" aria-label="Quadro original da animação"></canvas>
<div><select id="mode" aria-label="Recurso visual"></select><p id="note"></p>
<button id="play">Pausar</button><input id="frame" aria-label="Quadro" type="range" min="0" value="0"><output id="counter"></output>
<p><small>Os recursos de carga podem aparecer em etapas diferentes. Esta prévia não comprova qual conjunto a unidade Toy Story utiliza hoje.</small></p>
</div></section></main><script>
const assets=__ASSETS__;
const mode=document.getElementById('mode'),slider=document.getElementById('frame'),button=document.getElementById('play');
const canvas=document.getElementById('screen'),ctx=canvas.getContext('2d');
let images=[],index=0,playing=true,timer=null,generation=0;
for(const [key,value] of Object.entries(assets)){const option=document.createElement('option');option.value=key;option.textContent=value.label;mode.append(option)}
function paint(){ctx.fillStyle='#000';ctx.fillRect(0,0,600,1024);const image=images[index];if(image)ctx.drawImage(image,(600-image.naturalWidth)/2,(1024-image.naturalHeight)/2);slider.value=index;document.getElementById('counter').textContent=`Quadro ${index+1} / ${images.length}`}
function tick(){clearTimeout(timer);if(playing&&images.length>1)timer=setTimeout(()=>{index=(index+1)%images.length;paint();tick()},assets[mode.value].delay)}
async function change(){const own=++generation;clearTimeout(timer);const config=assets[mode.value];document.getElementById('note').textContent=config.note;const loaded=await Promise.all(config.images.map(url=>new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve(image);image.onerror=reject;image.src=url})));if(own!==generation)return;images=loaded;index=0;slider.max=images.length-1;paint();tick()}
mode.onchange=change;slider.oninput=()=>{index=Number(slider.value);paint();tick()};button.onclick=()=>{playing=!playing;button.textContent=playing?'Pausar':'Reproduzir';tick()};
change().catch(()=>document.getElementById('note').textContent='Falha ao decodificar um recurso. Consulte os arquivos originais.');
</script></html>'''.replace('__ASSETS__', json.dumps(assets, separators=(',', ':')))
target = root / 'PREVIA-ANIMACOES.html'
target.write_text(page, encoding='utf-8')
report = {'viewer': str(target), 'bytes': target.stat().st_size,
          'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
          'assets': {key: {'frames': len(value['images']), 'delay_ms': value['delay'], 'note': value['note']}
                     for key, value in assets.items()}}
(root / 'preview-manifest.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps(report, indent=2))
