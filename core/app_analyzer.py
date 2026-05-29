import os, re
from dataclasses import dataclass, asdict

HIGH_RISK_PERMS = {
    'android.permission.READ_SMS':25,'android.permission.SEND_SMS':25,'android.permission.RECEIVE_SMS':25,
    'android.permission.READ_CONTACTS':20,'android.permission.RECORD_AUDIO':25,'android.permission.CAMERA':20,
    'android.permission.ACCESS_FINE_LOCATION':15,'android.permission.READ_CALL_LOG':25,
    'android.permission.SYSTEM_ALERT_WINDOW':35,'android.permission.REQUEST_INSTALL_PACKAGES':40,
    'android.permission.BIND_ACCESSIBILITY_SERVICE':55,'android.permission.QUERY_ALL_PACKAGES':20,
    'android.permission.FOREGROUND_SERVICE':10,'android.permission.READ_EXTERNAL_STORAGE':15
}

@dataclass
class AppRecord:
    package: str
    apk_path: str = ''
    uid: str = ''
    permissions: list = None
    risk: int = 0
    reasons: list = None
    category: str = 'Other'
    icon: str = '📦'

class AppAnalyzer:
    def __init__(self, adb): self.adb = adb

    def list_packages(self):
        r = self.adb.shell('pm list packages -f -U -3', timeout=30)
        apps=[]
        for line in r.stdout.splitlines():
            # package:/path/base.apk=com.pkg uid:10123
            m = re.match(r'package:(.*?)=(\S+)(?:\s+uid:(\d+))?', line.strip())
            if m:
                apps.append(AppRecord(m.group(2), m.group(1), m.group(3) or '', [], 0, []))
        return apps


    def classify_category(self, package, dumpsys_text=''):
        p = (package or '').lower()
        text = (dumpsys_text or '').lower()
        if any(x in p for x in ['bank','vakif','ziraat','kuveyt','finans','garanti','akbank','yapi','isbank','papara','wallet']):
            return 'Bankacılık', '🏦'
        if any(x in p for x in ['whatsapp','telegram','instagram','facebook','messenger','twitter','xcorp','snapchat','tiktok']):
            return 'Sosyal / Mesajlaşma', '💬'
        if any(x in p for x in ['authenticator','azure.authenticator','google.android.apps.authenticator','edevlet','kimlik']):
            return 'Kimlik / 2FA', '🔐'
        if any(x in p for x in ['chrome','browser','opera','firefox','webview']):
            return 'Tarayıcı / Web', '🌐'
        if any(x in p for x in ['maps','location','navigation','gps']):
            return 'Konum / Harita', '🗺️'
        if any(x in p for x in ['camera','gallery','photo','video','media']):
            return 'Medya', '🎞️'
        if 'android.permission.RECORD_AUDIO'.lower() in text or 'android.permission.camera'.lower() in text:
            return 'Ses/Kamera Yetkili', '🎙️'
        if package.startswith('com.google'):
            return 'Google Servisi', '🟢'
        if package.startswith('com.huawei'):
            return 'Huawei Servisi', '🔴'
        return 'Other', '📦'

    def enrich_permissions(self, app):
        out = self.adb.shell(f'dumpsys package {app.package}', timeout=20).stdout
        perms = []
        capture=False
        for line in out.splitlines():
            s=line.strip()
            if 'requested permissions:' in s: capture=True; continue
            if capture:
                if not s or s.endswith(':'): break
                if s.startswith('android.permission.') or s.startswith('com.'):
                    perms.append(s.split(':')[0].strip())
        app.permissions = sorted(set(perms))
        app.category, app.icon = self.classify_category(app.package, out)
        score=0; reasons=[]
        for p in app.permissions:
            if p in HIGH_RISK_PERMS:
                score += HIGH_RISK_PERMS[p]; reasons.append(p)
        # persistence hints
        if 'RECEIVE_BOOT_COMPLETED' in out: score += 25; reasons.append('BOOT_COMPLETED receiver')
        if 'AccessibilityService' in out: score += 60; reasons.append('Accessibility service declared')
        if 'DeviceAdminReceiver' in out: score += 45; reasons.append('Device admin receiver')
        app.risk=score; app.reasons=reasons
        return app

    def analyze(self, limit=None):
        apps=self.list_packages()
        enriched=[]
        for app in apps[:limit] if limit else apps:
            enriched.append(self.enrich_permissions(app))
        return [asdict(a) for a in enriched]

    def package_path(self, package):
        r=self.adb.shell(f'pm path {package}', timeout=10).stdout
        paths=[]
        for line in r.splitlines():
            if line.startswith('package:'): paths.append(line.replace('package:','').strip())
        return paths

    def pull_apk(self, package, dest_dir):
        os.makedirs(dest_dir, exist_ok=True)
        paths=self.package_path(package)
        pulled=[]
        for i,p in enumerate(paths):
            name = f'{package}_{i}.apk' if i else f'{package}.apk'
            local=os.path.join(dest_dir, name)
            res=self.adb.pull(p, local, timeout=180)
            if res.ok: pulled.append(local)
        return pulled
