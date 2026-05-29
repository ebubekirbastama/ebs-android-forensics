class SystemAccessAnalyzer:
    def __init__(self, adb): self.adb=adb
    def analyze(self):
        findings=[]
        acc=self.adb.shell('settings get secure enabled_accessibility_services', timeout=10).stdout
        notif=self.adb.shell('settings get secure enabled_notification_listeners', timeout=10).stdout
        admin=self.adb.shell('dumpsys device_policy', timeout=15).stdout[:5000]
        if acc and acc.lower()!='null': findings.append({'category':'Accessibility','risk':60,'value':acc,'reason':'Erişilebilirlik servisleri aktif'})
        if notif and notif.lower()!='null': findings.append({'category':'Notification Listener','risk':45,'value':notif,'reason':'Bildirim erişimi aktif'})
        if 'Active admin' in admin or 'admin' in admin.lower(): findings.append({'category':'Device Admin','risk':40,'value':admin[:1000],'reason':'Device policy/admin izleri'})
        return findings
