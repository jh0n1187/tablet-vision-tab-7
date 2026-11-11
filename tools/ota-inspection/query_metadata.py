"""PC-only OTA metadata queries. Fixed endpoints/builds; no install/download/report APIs."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import ssl
import base64
from datetime import datetime,timezone
import subprocess
import socket
import ipaddress
import sys
import urllib.request
import urllib.parse
import urllib.error

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'analise-firmware/ota'
POS='https://android.atualizador.positivoinformatica.com.br/fota/query/json'
ADUPS='https://fota5p.adups.com/otainter-5.0/fota5/'
ALLOWED={POS,ADUPS+'detectSchedule.do',ADUPS+'fullDetectSchedule.do'}
ALLOWED|={u.replace('fota5p.adups.com','fota5p.adups.cn') for u in tuple(ALLOWED) if u.startswith(ADUPS)}
BUILDS={'current':('URTSF2025092701','1758947246'),'stock':('URBR2024101701','1729159949')}

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def adups_encode(text,key=None,padding=None):
 # EncryptUtil.j: random repeating XOR with rotated key in the envelope.
 key=key if key is not None else bytes(secrets.randbelow(255) for _ in range(secrets.randbelow(12)+3))
 padding=padding if padding is not None else secrets.randbelow(15)
 assert 3<=len(key)<=14 and 0<=padding<=14
 junk=(b'\x08'+b'\0'*(padding-1)) if padding else b''
 rotated=bytes(((x>>5)|(x<<3))&255 for x in key)
 raw=text.encode('utf8')
 return (bytes([(padding<<4)|len(key)])+junk+rotated+bytes(v^key[i%len(key)] for i,v in enumerate(raw))).hex().upper()

def adups_decode(encoded):
 data=bytes.fromhex(encoded);padding=data[0]>>4;size=data[0]&15
 start=1+padding
 key=bytes(((v<<5)|(v>>3))&255 for v in data[start:start+size])
 return bytes(v^key[i%size] for i,v in enumerate(data[start+size:])).decode('utf8')

def adups_fields(which):
 build,timestamp=BUILDS[which]
 # Unique device IDs/session/consent state intentionally omitted, not fabricated.
 return dict(device_type='pad',platform='AW_14.0',project='dajingtech$AW$14.0_T307F_pt-BR_other',
             version=timestamp,swFingerprint=f'Positivo/T307F/T307F:14/UP1A.231105.001.A1/{build}:user/release-keys',
             sdk_level='34',sdk_release='14',resolution='600#1024',appVersion='5.30.0.235750.006_2023-06-13 17:37',
             appCode='216',local='pt-BR')

def build_request(provider,which):
 if which not in BUILDS:raise ValueError('Build outside fixed allowlist')
 if provider=='positivo':
  params=dict(dm='T307F',bv=BUILDS[which][0],cv=50005,qa=0,qm='m',up=True,la='pt',br=2,is_=0)
  params['is']=params.pop('is_')
  return POS,json.dumps(params,separators=(',',':')).encode(),'application/json; charset=utf-8',params
 if provider in ('adups-full','adups-delta'):
  params=adups_fields(which)
  plaintext=''.join('&'+k+'='+v for k,v in params.items())
  envelope=adups_encode(plaintext)
  body=urllib.parse.urlencode(dict(key=envelope,shaKey=hashlib.sha256(envelope.encode()).hexdigest())).encode()
  endpoint='fullDetectSchedule.do' if provider=='adups-full' else 'detectSchedule.do'
  return ADUPS+endpoint,body,'application/x-www-form-urlencoded',params
 raise ValueError('Unknown provider')

def redact(value):
 if isinstance(value,dict):return {k:('[REDACTED]' if k in ('ss','sn','ma','imei','imei1','imei2','esn','mac','androidId','mid','fcmId','tk') else redact(v)) for k,v in value.items()}
 if isinstance(value,list):return [redact(v) for v in value]
 return value

def query(provider,which,overrides=None,suffix='',use_cn=False):
 url,body,content_type,params=build_request(provider,which)
 if use_cn:
  if not provider.startswith('adups-'):raise ValueError('CN host only valid for Adups query')
  url=url.replace('fota5p.adups.com','fota5p.adups.cn')
 if overrides:
  if provider=='positivo' and set(overrides)<={'ss','br','sn'}:
   params.update(overrides);body=json.dumps(params,separators=(',',':')).encode()
  elif provider in ('adups-full','adups-delta') and set(overrides)<={'imei1','esn','mid','isNewMid','devicesinfoExt','fotaSign','connect_type'}:
   params.update(overrides)
   envelope=adups_encode(''.join('&'+k+'='+v for k,v in params.items()))
   body=urllib.parse.urlencode(dict(key=envelope,shaKey=hashlib.sha256(envelope.encode()).hexdigest())).encode()
  else:raise ValueError('Unsupported override')
 if url not in ALLOWED:raise ValueError('Endpoint outside metadata allowlist')
 prefix=OUT/f'query-{provider}-{which}{suffix}'
 if prefix.with_suffix('.json').exists():raise FileExistsError(prefix)
 record=dict(provider=provider,profile=which,url=url,request_method='POST',
             request_parameters=redact(params),unique_device_identifiers_sent=bool(set(params)&{'sn','imei1','esn'}),
             omitted_fields=[k for k in ('sn','ma','imei','androidId','mid','fcmId','ss','tk') if k not in params],
             tls_verification=True,redirects_followed=False,response_body_limit=2097152)
 if use_cn:record['dns_source']='HTTPS dns.google / process-local resolution override; TLS hostname verification retained'
 opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
 try:
  req=urllib.request.Request(url,data=body,headers={'Content-Type':content_type,'Accept':'application/json'},method='POST')
  try:response=opener.open(req,timeout=20)
  except urllib.error.HTTPError as e:response=e
  with response:
   raw=response.read(2097153)
   if len(raw)>2097152:raise ValueError('Metadata response exceeds cap; no further read')
   record.update(status=response.code,content_type=response.headers.get('Content-Type'),response_bytes=len(raw),response_sha256=hashlib.sha256(raw).hexdigest())
  try:
   parsed=json.loads(raw)
   record['response_json']=parsed
   prefix.with_suffix('.response').write_text(json.dumps(redact(parsed),ensure_ascii=False,indent=2),encoding='utf8')
  except (ValueError,UnicodeDecodeError):record['response_is_json']=False
 except Exception as e:record.update(error_type=type(e).__name__,error=str(e))
 prefix.with_suffix('.json').write_text(json.dumps(redact(record),ensure_ascii=False,indent=2),encoding='utf8')
 # Never print a complete response that could contain session IDs/signed URLs.
 summary={k:record[k] for k in ('provider','profile','status','response_bytes','error_type','error') if k in record}
 if isinstance(record.get('response_json'),dict):
  r=record['response_json'];summary['response_keys']=list(r);summary['api_status']=r.get('status');summary['has_version']=bool(r.get('version'));summary['has_ui']=bool(r.get('ui'))
 print(json.dumps(summary,ensure_ascii=False),flush=True)
 return record

def test():
 for text in ('&project=T307F&version=1758947246','&local=pt-BR','&utf8=ação'):
  for n in (0,1,14):
   key=bytes([0,127,254]);cipher=adups_encode(text,key,n)
   assert adups_decode(cipher)==text
 for provider in ('positivo','adups-full','adups-delta'):
  for which in BUILDS:
   url,body,ct,params=build_request(provider,which)
   assert url in ALLOWED and len(body)<10000
   assert not set(params)&{'sn','ma','imei','imei1','imei2','mac','androidId','mid','fcmId','tk','ss'}
 try:build_request('report','current')
 except ValueError:pass
 else:raise AssertionError('Non-query endpoint accepted')
 print('PASS: 9 codec round-trips, 6 request profiles, report endpoint rejected')

if __name__=='__main__':
 if sys.argv[1:] == ['test']:test()
 elif sys.argv[1:] in (['adups-identified'],['adups-identified-cn']):
  use_cn=sys.argv[1]=='adups-identified-cn'
  resolver=socket.getaddrinfo
  if use_cn:
   dns=json.loads((OUT/'adups-cn-dns.json').read_text())
   addresses=[r['data'] for r in dns.get('Answer',[]) if r.get('type')==1 and r.get('name')=='fota5p.adups.cn.']
   if len(addresses)!=1 or not ipaddress.ip_address(addresses[0]).is_global:raise ValueError('Unexpected DNS evidence')
   def mapped(host,port,*args,**kwargs):return resolver(addresses[0] if host=='fota5p.adups.cn' else host,port,*args,**kwargs)
   socket.getaddrinfo=mapped
  props=dict(re.findall(r'^\[([^]]+)\]: \[(.*)\]$',(ROOT/'backup/getprop.txt').read_text(encoding='utf8'),re.M))
  serial=props.get('ro.serialno')
  if not serial or serial!=props.get('ro.boot.serialno'):raise ValueError('Backup serial missing/inconsistent')
  certificate=subprocess.run([r'C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe','-printcert','-rfc','-file',str(OUT/'dajing-backup/resources/META-INF/CERT.RSA')],capture_output=True,check=True).stdout.decode()
  public_base64=''.join(re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',certificate,re.S).group(1).split())
  fota_sign=hashlib.md5(public_base64.encode()).hexdigest()
  # MID is a client-generated nonce in the APK, not a credential or tablet ID.
  mid=datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')+''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz') for _ in range(2))+str(1000+secrets.randbelow(9000))
  ext='_'.join(props.get(k,'').replace('_','$') for k in ('ro.product.model','ro.product.brand','ro.product.name','ro.product.device','ro.product.board','ro.product.manufacturer','ro.product.platform','ro.product.product'))
  extra=dict(imei1=serial,esn=serial,mid=mid,isNewMid='1',devicesinfoExt=ext,fotaSign=fota_sign,connect_type='-1')
  try:
   for provider in ('adups-delta','adups-full'):
    for which in BUILDS:query(provider,which,extra,'-identified-cn' if use_cn else '-identified',use_cn=use_cn)
  finally:socket.getaddrinfo=resolver
 elif sys.argv[1:] == ['identified']:
  props=dict(re.findall(r'^\[([^]]+)\]: \[(.*)\]$',(ROOT/'backup/getprop.txt').read_text(encoding='utf8'),re.M))
  serial=props.get('ro.serialno')
  if not serial or serial!=props.get('ro.boot.serialno'):raise ValueError('Backup serial missing/inconsistent')
  for which in BUILDS:
   result=query('positivo',which,{'sn':serial},'-identified-br2')
   response=result.get('response_json',{})
   if response.get('ur') and response.get('ss'):
    # One bounded protocol continuation, no automatic installation/download.
    query('positivo',which,{'sn':serial,'ss':response['ss'],'br':2},'-identified-br2-recheck')
 elif sys.argv[1:] == ['recheck']:
  for which in BUILDS:
   prior=json.loads((OUT/f'query-positivo-{which}.json').read_text(encoding='utf8'))['response_json']
   if prior.get('ur') and prior.get('ss') and prior['ss']!='[REDACTED]':
    query('positivo',which,{'ss':prior['ss'],'br':prior.get('bl',{}).get('r',0)},'-recheck')
  for p in OUT.glob('query-*.json'):
   record=json.loads(p.read_text(encoding='utf8'))
   p.write_text(json.dumps(redact(record),ensure_ascii=False,indent=2),encoding='utf8')
   if 'response_json' in record:p.with_suffix('.response').write_text(json.dumps(redact(record['response_json']),ensure_ascii=False,indent=2),encoding='utf8')
 elif len(sys.argv)==3:query(*sys.argv[1:])
 else:raise SystemExit('usage: query_metadata.py test | PROVIDER current/stock')
