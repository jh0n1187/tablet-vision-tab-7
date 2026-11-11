"""Bounded HEAD probes only, with normal TLS validation and no redirect following."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import ssl
import urllib.request
import urllib.error

URLS=(
 'https://android.atualizador.positivoinformatica.com.br/fota/query/json',
 'https://fota5p.adups.com/otainter-5.0/fota5/detectSchedule.do',
 'https://fota5p.adups.cn/otainter-5.0/fota5/detectSchedule.do',
)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
def probe(url):
 host=urllib.request.urlparse(url).hostname if hasattr(urllib.request,'urlparse') else __import__('urllib.parse',fromlist=['urlparse']).urlparse(url).hostname
 rec={'url':url,'method':'HEAD','identifiers_sent':False,'tls_verification':True}
 try:
  rec['addresses']=sorted(set(a[4][0] for a in socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)))
  client=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
  try:response=client.open(urllib.request.Request(url,method='HEAD'),timeout=12)
  except urllib.error.HTTPError as e:response=e
  with response:rec.update(status=response.code,content_type=response.headers.get('Content-Type'))
 except Exception as e:rec.update(error_type=type(e).__name__,error=str(e))
 return rec
if __name__=='__main__':
 records=list(ThreadPoolExecutor(max_workers=3).map(probe,URLS))
 out=Path('analise-firmware/ota/endpoint-probes.json')
 if out.exists():raise FileExistsError(out)
 out.write_text(json.dumps(records,indent=2),encoding='utf8')
 print(json.dumps(records,indent=2))
