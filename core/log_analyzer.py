import re, subprocess, threading

class CrashLogAnalyzer:
    KEYWORDS = [
        ('Fatal signal', 'Gerçek native/app crash', 'fatal_signal', 65),
        ('FATAL EXCEPTION', 'Gerçek Java app crash', 'fatal_exception', 65),
        ('crash_dump', 'Crash dump helper', 'crash_dump', 30),
        ('avc:  denied', 'SELinux denial', 'selinux_denial', 25),
        ('Permission Denial', 'Permission denial', 'permission_denial', 25),
        ('mediaserver', 'Mediaserver yüzeyi', 'mediaserver', 20),
        ('mediacodec', 'MediaCodec yüzeyi', 'mediacodec', 20),
        ('bluetooth', 'Bluetooth yüzeyi', 'bluetooth', 20),
        ('WebView', 'WebView yüzeyi', 'webview', 15),
        ('system_server', 'System_server anomalisi', 'system_server', 20),
        ('zygote', 'Zygote olayı', 'zygote', 15),
    ]
    def __init__(self, adb): self.adb=adb

    def collect_buffers(self):
        data={}
        for b in ['crash','events','system','main']:
            data[b]=self.adb.run(['logcat','-b',b,'-d','-v','time'], timeout=40).stdout
        return data

    def classify_line(self, line, source='main'):
        found=[]
        for needle,cat,key,score in self.KEYWORDS:
            if needle.lower() in line.lower():
                risk=score
                if key=='selinux_denial':
                    if any(x in line.lower() for x in ['mediacodec','mediaserver','bluetooth']): risk += 20
                    else: risk += 10
                decision='İzlenmeli'
                if risk>=60: decision='Yüksek önem'
                elif key=='selinux_denial': decision='Çoğunlukla engellenmiş erişim'
                elif key=='crash_dump': decision='Tek başına exploit kanıtı değil'
                found.append({'source':source,'category':cat,'key':key,'risk':risk,'decision':decision,'line':line[:2000]})
        return found

    def analyze(self):
        buffers=self.collect_buffers()
        results=[]
        for src,text in buffers.items():
            for line in text.splitlines():
                results += self.classify_line(line, src)
        # de-dup close lines
        seen=set(); out=[]
        for r in results:
            sig=(r['source'], r['key'], r['line'][:160])
            if sig not in seen:
                seen.add(sig); out.append(r)
        return out

class LiveLogcat:
    def __init__(self, adb_path='adb', serial=None):
        self.adb_path=adb_path; self.serial=serial; self.proc=None; self.thread=None; self.running=False
    def start(self, on_line):
        cmd=[self.adb_path]
        if self.serial: cmd += ['-s', self.serial]
        cmd += ['logcat','-v','time']
        self.proc=subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace')
        self.running=True
        def loop():
            for line in self.proc.stdout:
                if not self.running: break
                on_line(line.rstrip())
        self.thread=threading.Thread(target=loop, daemon=True); self.thread.start()
    def stop(self):
        self.running=False
        if self.proc:
            try: self.proc.terminate()
            except Exception: pass
            self.proc=None
