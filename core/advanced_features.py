import json, time, os
from collections import Counter, defaultdict

class AIThreatAnalyst:
    def analyze(self, data):
        s=data.get('summary',{}); apps=data.get('apps',[]); net=data.get('net',[]); logs=data.get('logs',[])
        lines=[f"Genel risk: {s.get('level','?')} / {s.get('score','?')}"]
        risky=[a for a in apps if int(a.get('risk',0) or 0)>=100]
        if risky: lines.append(f"Yüksek riskli uygulama sayısı: {len(risky)}. İlk hedef: {risky[0].get('package')}")
        unknown=[n for n in net if 'Unknown' in (n.get('company','')+n.get('country','')) and int(n.get('risk',0) or 0)>0]
        if unknown: lines.append(f"Bilinmeyen şirket/ülke socket sayısı: {len(unknown)}. GeoIP veritabanı ile doğrulanmalı.")
        crashes=[l for l in logs if int(l.get('risk',0) or 0)>=45]
        if crashes: lines.append(f"Kritik crash/log izi: {len(crashes)}. Medya/WebView/Bluetooth yüzeyleri korelasyon için izlenmeli.")
        if not risky and not unknown and not crashes: lines.append('Kritik IOC görülmedi; cihaz yine de canlı izleme ile takip edilmeli.')
        lines.append('Öneri: şüpheli pakette önce APK çek + hash al + rapora ekle, sonra force-stop uygula. Suspend hassas uygulamalarda son seçenek olmalı.')
        return '\n'.join(lines)

class HuntEngine:
    def query(self, data, q):
        q=(q or '').strip().lower(); rows=[]
        def match(obj): return q in json.dumps(obj, ensure_ascii=False).lower()
        if not q: return rows
        for section in ['apps','net','logs','timeline','sys']:
            for item in data.get(section,[]) or []:
                if match(item): rows.append({'section':section,'result':json.dumps(item, ensure_ascii=False)[:900]})
        return rows

class DeviceMapBuilder:
    def build(self, sockets):
        rows=[]
        for n in sockets or []:
            pkg=n.get('packages') or 'UNKNOWN_UID'
            rows.append({'device':'Android Device','app':pkg,'remote':n.get('remote',''), 'country':n.get('country',''), 'company':n.get('company',''), 'risk':n.get('risk',0)})
        return rows

class PermissionMatrix:
    KEYS=['SMS','CONTACTS','AUDIO','CAMERA','LOCATION','CALL_LOG','ACCESSIBILITY','INSTALL','OVERLAY','BOOT']
    def build(self, apps):
        rows=[]
        for a in apps or []:
            blob=' '.join((a.get('permissions') or [])+(a.get('reasons') or [])).upper()
            vals=[]
            for k in self.KEYS:
                vals.append('YES' if k in blob or (k=='INSTALL' and 'REQUEST_INSTALL_PACKAGES' in blob) or (k=='BOOT' and 'BOOT_COMPLETED' in blob) else '')
            if any(vals): rows.append([a.get('package',''), a.get('risk',0)] + vals)
        return rows

class MobileEDR:
    def evaluate(self, data):
        alerts=[]
        for a in data.get('apps',[]) or []:
            reasons=' '.join(a.get('reasons') or [])
            if 'Accessibility' in reasons and int(a.get('risk',0) or 0)>80:
                alerts.append({'rule':'EDR-001 Accessibility + High Risk','target':a.get('package'),'severity':'HIGH','action':'APK çek, force-stop, gerekirse suspend'})
            if 'REQUEST_INSTALL_PACKAGES' in reasons:
                alerts.append({'rule':'EDR-002 Installer Permission','target':a.get('package'),'severity':'MEDIUM','action':'Kaynağı doğrula'})
        for n in data.get('net',[]) or []:
            if n.get('scope')=='public' and 'Unknown' in (n.get('company','')):
                alerts.append({'rule':'EDR-010 Unknown Public IP','target':n.get('remote'),'severity':'MEDIUM','action':'GeoIP/ASN doğrula, ilgili paketi izle'})
        return alerts

class AttackSimulator:
    def scenarios(self):
        return [
            ['SIM-001','Fake Accessibility Trojan','Accessibility + BOOT_COMPLETED + SMS = kritik alarm üretmeli'],
            ['SIM-002','Fake C2 Beacon','Bilinmeyen public IP’ye periyodik 443 bağlantısı alarm üretmeli'],
            ['SIM-003','Fake Media Exploit Chain','mediacodec crash sonrası socket açılırsa zero-click korelasyonu yükselmeli'],
        ]

class SessionRecorder:
    def __init__(self, path): self.path=path; os.makedirs(os.path.dirname(path), exist_ok=True)
    def log(self, action, detail=''):
        with open(self.path,'a',encoding='utf-8') as f: f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{action}\t{detail}\n")
