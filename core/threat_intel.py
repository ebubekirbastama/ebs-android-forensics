import hashlib, re, os

SUSPICIOUS_IPS = {'45.158.57.39':'Unknown VPS / Review', '2.58.141.9':'Hosting / Review'}
MALWARE_KEYWORDS = ['spynote','ahmyth','anubis','xenomorph','brata','cerberus','hydra','joker','pegasus','predator']
MITRE_MAP = {
    'Accessibility':'T1621 Abuse Accessibility Features','BOOT_COMPLETED':'T1624.001 Event Triggered Execution','REQUEST_INSTALL_PACKAGES':'T1476 Deliver Malicious App via Unknown Sources',
    'SMS':'T1412 Capture SMS Messages','Location':'T1430 Location Tracking','Audio':'T1429 Audio Capture','Camera':'T1512 Video Capture','Overlay':'T1620 Screen Overlay'
}
class ThreatIntelCenter:
    def match_apps(self, apps):
        rows=[]
        for a in apps or []:
            p=(a.get('package') or '').lower(); reasons=[]; score=0; mitre=[]
            for k in MALWARE_KEYWORDS:
                if k in p: reasons.append('Malware keyword: '+k); score+=80
            perms=' '.join(a.get('permissions') or [])+' '+' '.join(a.get('reasons') or [])
            if 'Accessibility' in perms: mitre.append(MITRE_MAP['Accessibility']); score+=25
            if 'BOOT_COMPLETED' in perms: mitre.append(MITRE_MAP['BOOT_COMPLETED']); score+=20
            if 'REQUEST_INSTALL_PACKAGES' in perms: mitre.append(MITRE_MAP['REQUEST_INSTALL_PACKAGES']); score+=20
            if 'SMS' in perms: mitre.append(MITRE_MAP['SMS']); score+=15
            if score: rows.append({'target':a.get('package'), 'type':'APP_IOC', 'score':score, 'reason':'; '.join(reasons + mitre), 'mitre':', '.join(mitre)})
        return rows
    def match_network(self, sockets):
        rows=[]
        for n in sockets or []:
            ip=(n.get('remote') or '').split(':')[0]
            if ip in SUSPICIOUS_IPS:
                rows.append({'target':ip,'type':'IP_IOC','score':75,'reason':SUSPICIOUS_IPS[ip], 'mitre':'T1437 Application Layer Protocol'})
        return rows
    def summarize(self, apps, sockets): return self.match_apps(apps)+self.match_network(sockets)

class SimpleYaraEngine:
    RULES = [
        ('Android_Accessibility_Trojan', ['AccessibilityService','BIND_ACCESSIBILITY_SERVICE','BOOT_COMPLETED']),
        ('Android_SMS_Stealer', ['READ_SMS','RECEIVE_SMS','SEND_SMS']),
        ('Android_Dropper_Installer', ['REQUEST_INSTALL_PACKAGES','QUERY_ALL_PACKAGES']),
    ]
    def scan_text(self, name, text):
        hits=[]
        for rule, words in self.RULES:
            found=[w for w in words if w.lower() in (text or '').lower()]
            if len(found)>=2: hits.append({'file':name,'rule':rule,'matches':', '.join(found),'risk':70})
        return hits
    def sha256(self, path):
        h=hashlib.sha256()
        with open(path,'rb') as f:
            for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
        return h.hexdigest()
