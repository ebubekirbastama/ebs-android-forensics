import os, sys, webbrowser, subprocess
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QObject, QEvent
from PySide6.QtWidgets import *
from PySide6.QtGui import QAction, QColor, QBrush
from core.adb_client import ADBClient
from core.device_info import DeviceInfoCollector
from core.app_analyzer import AppAnalyzer
from core.network_analyzer import NetworkAnalyzer
from core.log_analyzer import CrashLogAnalyzer, LiveLogcat
from core.system_access import SystemAccessAnalyzer
from core.process_monitor import ProcessMonitor
from core.active_response import ActiveResponseEngine
from core.evidence_locker import EvidenceLocker
from core.risk_engine import RiskEngine
from core.timeline import TimelineEngine
from core.report_generator import ReportGenerator
from core.threat_intel import ThreatIntelCenter, SimpleYaraEngine
from core.advanced_features import AIThreatAnalyst, HuntEngine, DeviceMapBuilder, PermissionMatrix, MobileEDR, AttackSimulator, SessionRecorder

APP_QSS = '''
QMainWindow,QWidget{background:#050b14;color:#dbeafe;font-family:Segoe UI;font-size:12px}
QLabel#title{font-size:30px;font-weight:900;color:#e0f2fe}
QLabel#sub{color:#38bdf8}
QPushButton{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #0f766e,stop:.45 #1d4ed8,stop:1 #7f1d1d);color:#f8fafc;border:1px solid #22d3ee;border-radius:10px;padding:9px 14px;font-weight:800;letter-spacing:.4px}
QPushButton:hover{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #16a34a,stop:.5 #2563eb,stop:1 #dc2626);border:1px solid #a7f3d0;color:white}
QPushButton:pressed{background:#dc2626;border:2px solid #22c55e;padding-top:11px;padding-left:16px}
QPushButton:disabled{background:#1f2937;color:#64748b;border:1px solid #334155}
QTabWidget::pane{border:1px solid #164e63;background:#050b14}
QTabBar::tab{background:#09111f;color:#dbeafe;padding:10px 16px;border-top-left-radius:8px;border-top-right-radius:8px;margin-right:3px;border:1px solid #172554}
QTabBar::tab:selected{background:#0f766e;color:white;border:1px solid #22d3ee}
QTableWidget{background:#020617;color:#dbeafe;gridline-color:#155e75;selection-background-color:#064e3b;selection-color:#ffffff;alternate-background-color:#061426;border:1px solid #164e63}
QTableWidget::item{background:#020617;color:#dbeafe;border-bottom:1px solid #0f2a44;padding:4px}
QTableWidget::item:alternate{background:#061426}
QTableWidget::item:selected{background:#065f46;color:#ffffff;border:1px solid #22c55e}
QTableCornerButton::section{background:#020617;border:1px solid #164e63}
QHeaderView::section{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #052e2b,stop:1 #172554);color:#dbeafe;border:1px solid #155e75;padding:7px;font-weight:800}
QHeaderView{background:#020617;color:#dbeafe}
QTextEdit{background:#020617;color:#bbf7d0;border:1px solid #155e75;font-family:Consolas, monospace}
QLineEdit,QComboBox{background:#061426;color:#dbeafe;border:1px solid #0f766e;border-radius:7px;padding:7px;selection-background-color:#065f46}
QComboBox QAbstractItemView{background:#020617;color:#dbeafe;selection-background-color:#065f46;border:1px solid #0f766e}
QProgressBar{border:1px solid #164e63;border-radius:7px;text-align:center;background:#020617;color:#dbeafe;font-weight:700}
QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #22c55e,stop:.5 #38bdf8,stop:1 #ef4444);border-radius:7px}
QGroupBox{background:#07111f;border:1px solid #0f766e;border-radius:14px;margin-top:8px;padding:14px;color:#93c5fd;font-weight:700}
QScrollBar:vertical{background:#020617;width:14px;border:1px solid #0f2a44}
QScrollBar::handle:vertical{background:#0f766e;border-radius:6px;min-height:24px}
QScrollBar::handle:vertical:hover{background:#22c55e}
QScrollBar:horizontal{background:#020617;height:14px;border:1px solid #0f2a44}
QScrollBar::handle:horizontal{background:#0f766e;border-radius:6px;min-width:24px}
QMenu{background:#020617;color:#dbeafe;border:1px solid #0f766e}
QMenu::item:selected{background:#065f46;color:white}
.Card{background:#101827;border:1px solid #3158d4;border-radius:14px;padding:10px}
'''


class ForensicButtonFX(QObject):
    """Butonlara tıklama sesi ve kısa red/green incident-response efekti verir."""
    def eventFilter(self, obj, event):
        try:
            if isinstance(obj, QPushButton) and event.type() == QEvent.MouseButtonPress:
                QApplication.beep()
                old = obj.styleSheet()
                obj.setStyleSheet(old + "; QPushButton{border:2px solid #22c55e;color:#ffffff;}")
                QTimer.singleShot(140, lambda o=obj, st=old: o.setStyleSheet(st))
        except Exception:
            pass
        return False

def harden_table(table):
    """Varsayılan beyaz header/corner/viewport alanlarını dark forensic temaya zorlar."""
    table.setAlternatingRowColors(True)
    table.setShowGrid(True)
    table.setStyleSheet(table.styleSheet() + """
        QTableWidget{background:#020617;color:#dbeafe;alternate-background-color:#061426;gridline-color:#155e75;}
        QTableWidget::item{background:#020617;color:#dbeafe;}
        QTableWidget::item:alternate{background:#061426;}
        QTableWidget::item:selected{background:#065f46;color:#ffffff;}
        QTableCornerButton::section{background:#020617;border:1px solid #164e63;}
    """)
    table.viewport().setStyleSheet('background:#020617;color:#dbeafe;')
    table.horizontalHeader().setStyleSheet('background:#020617;color:#dbeafe;')
    table.verticalHeader().setStyleSheet('background:#020617;color:#dbeafe;')

class AnalysisWorker(QThread):
    progress=Signal(int,str); done=Signal(dict); error=Signal(str)
    def __init__(self, adb, locker): super().__init__(); self.adb=adb; self.locker=locker
    def run(self):
        try:
            self.locker.new_case()
            self.progress.emit(5,'Cihaz bilgisi')
            device=DeviceInfoCollector(self.adb).collect(); self.locker.save_json('metadata/device.json', device)
            self.progress.emit(20,'Uygulamalar ve izinler')
            apps=AppAnalyzer(self.adb).analyze(); self.locker.save_json('metadata/apps.json', apps)
            self.progress.emit(40,'Ağ/socket analizi')
            net=NetworkAnalyzer(self.adb).analyze(); self.locker.save_json('network/sockets.json', net)
            self.progress.emit(60,'Crash/log sınıflandırma')
            logs=CrashLogAnalyzer(self.adb).analyze(); self.locker.save_json('logs/crash_findings.json', logs)
            self.progress.emit(75,'Sistem erişimleri')
            sysf=SystemAccessAnalyzer(self.adb).analyze(); self.locker.save_json('metadata/system_access.json', sysf)
            self.progress.emit(88,'Timeline ve risk')
            timeline=TimelineEngine().build(apps,net,logs,sysf); self.locker.save_json('metadata/timeline.json', timeline)
            summary=RiskEngine().summarize(apps,net,logs,sysf); self.locker.save_json('metadata/summary.json', summary)
            report_path=self.locker.path('reports','ebs_sentinel_report.html')
            ReportGenerator().generate(report_path, device, summary, apps, net, logs, sysf, timeline)
            self.progress.emit(100,'Tamamlandı')
            self.done.emit({'device':device,'apps':apps,'net':net,'logs':logs,'sys':sysf,'timeline':timeline,'summary':summary,'report':report_path,'case':self.locker.case_dir})
        except Exception as e: self.error.emit(str(e))


class LiveLogWorker(QThread):
    line = Signal(str)
    error = Signal(str)
    stopped = Signal()

    def __init__(self, adb_path='adb', serial=None, parent=None):
        super().__init__(parent)
        self.adb_path = adb_path or 'adb'
        self.serial = serial
        self._stop = False
        self.proc = None

    def run(self):
        cmd = [self.adb_path]
        if self.serial:
            cmd += ['-s', self.serial]
        cmd += ['logcat', '-v', 'threadtime']
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1
            )
            if not self.proc.stdout:
                self.error.emit('logcat çıktısı okunamadı.')
                return
            for raw in self.proc.stdout:
                if self._stop:
                    break
                line = raw.rstrip('\r\n')
                if line:
                    self.line.emit(line)
        except FileNotFoundError:
            self.error.emit('ADB bulunamadı. adb.exe PATH içinde olmalı veya adb_path doğru ayarlanmalı.')
        except Exception as e:
            self.error.emit(f'Canlı log başlatılamadı: {e}')
        finally:
            try:
                if self.proc and self.proc.poll() is None:
                    self.proc.terminate()
            except Exception:
                pass
            self.stopped.emit()

    def stop(self):
        self._stop = True
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
        except Exception:
            pass

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle('EBS Sentinel DFIR X Pro'); self.resize(1420,850); self.setStyleSheet(APP_QSS)
        self.adb=ADBClient(); self.locker=EvidenceLocker(os.path.join(os.getcwd(),'evidence')); self.live=None; self.data={}
        self.apps_an=AppAnalyzer(self.adb); self.resp=ActiveResponseEngine(self.adb); self.threat=ThreatIntelCenter(); self.yara=SimpleYaraEngine(); self.hunt=HuntEngine(); self.ai=AIThreatAnalyst(); self.edr=MobileEDR()
        self.all_app_rows=[]; self.effect_tick=0
        self.build_ui(); self.refresh_devices()
        self.fx_filter=ForensicButtonFX(self); QApplication.instance().installEventFilter(self.fx_filter)
        self.fx_timer=QTimer(self); self.fx_timer.timeout.connect(self.update_cyber_effect); self.fx_timer.start(420)
    def build_ui(self):
        root=QWidget(); v=QVBoxLayout(root); self.setCentralWidget(root)
        h=QHBoxLayout(); left=QVBoxLayout(); title=QLabel('EBS Sentinel DFIR X'); title.setObjectName('title'); sub=QLabel('Mobile Forensics • Threat Hunting • Zero-Click Detection • Active Response'); sub.setObjectName('sub'); left.addWidget(title); left.addWidget(sub); h.addLayout(left,1)
        h.addWidget(QLabel('ADB:')); self.device_label=QLabel('- / device'); self.device_label.setStyleSheet('color:#86efac;font-weight:700'); h.addWidget(self.device_label)
        self.btn_analyze=QPushButton('Tam Analiz Başlat'); self.btn_analyze.clicked.connect(self.start_analysis); h.addWidget(self.btn_analyze)
        self.btn_report=QPushButton('HTML Rapor Aç'); self.btn_report.clicked.connect(self.open_report); h.addWidget(self.btn_report); v.addLayout(h)
        cards=QHBoxLayout(); self.cards={}
        for k in ['Genel Risk','Riskli Uygulama','Riskli Socket','Crash/Log İzi','Sistem Erişimi']:
            w=QGroupBox(k); w.setStyleSheet('QGroupBox{border:1px solid #3158d4;border-radius:14px;margin-top:8px;padding:14px;color:#93c5fd}'); lay=QVBoxLayout(w); lab=QLabel('0'); lab.setStyleSheet('font-size:25px;font-weight:800;color:white'); lay.addWidget(lab); self.cards[k]=lab; cards.addWidget(w)
        v.addLayout(cards); self.fx_label=QLabel('EBS ACTIVE FORENSIC GRID // WAITING FOR TARGET DEVICE'); self.fx_label.setStyleSheet('color:#67e8f9;font-weight:800;letter-spacing:2px;padding:6px;border:1px solid #164e63;background:#020617'); v.addWidget(self.fx_label); self.progress=QProgressBar(); v.addWidget(self.progress)
        self.tabs=QTabWidget(); v.addWidget(self.tabs,1)
        self.tables={}
        for name, headers in {
            'Dashboard':['Tip','Değer','Açıklama'], 'Uygulamalar':['Icon','Kategori','Paket','UID','Risk','Nedenler'], 'Ağ / Socket':['Proto','Local','Remote','Ülke','Firma/ASN','State','UID','Paket','Risk','Neden'], 'Crash Analizi':['Buffer','Kategori','Anahtar','Risk','Karar','Satır'], 'Process Monitor':['User','PID','PPID','Name'], 'Active Response':['Hedef','Aksiyon','Sonuç'], 'Durdurulanlar':['Paket','Durum','Suspended','Stopped','Background'], 'Timeline':['Zaman','Tip','Başlık','Risk','Detay'], 'Evidence Locker':['Anahtar','Değer'], 'Threat Intel':['Hedef','Tip','Skor','MITRE','Sebep'], 'Live Device Map':['Cihaz','Uygulama','Remote','Ülke','Firma','Risk'], 'Permission Matrix':['Paket','Risk','SMS','CONTACTS','AUDIO','CAMERA','LOCATION','CALL_LOG','ACCESSIBILITY','INSTALL','OVERLAY','BOOT'], 'Mobile EDR':['Kural','Hedef','Seviye','Aksiyon'], 'YARA / VT':['Dosya/Paket','Kural/SHA256','Risk','Sonuç'], 'Session Recorder':['Zaman','Aksiyon','Detay']
        }.items():
            page=QWidget(); lay=QVBoxLayout(page)
            if name=='Uygulamalar':
                filter_row=QHBoxLayout()
                self.app_search=QLineEdit(); self.app_search.setPlaceholderText('Uygulama ara: paket adı, kategori, izin, risk nedeni...')
                self.app_search.textChanged.connect(self.apply_app_filters); filter_row.addWidget(self.app_search,2)
                self.app_category=QComboBox(); self.app_category.addItems(['Tüm Kategoriler','Bankacılık','Sosyal / Mesajlaşma','Kimlik / 2FA','Tarayıcı / Web','Konum / Harita','Medya','Ses/Kamera Yetkili','Google Servisi','Huawei Servisi','Other'])
                self.app_category.currentTextChanged.connect(self.apply_app_filters); filter_row.addWidget(self.app_category,1)
                b_icon=QPushButton('İkonlu Listeyi Yenile'); b_icon.clicked.connect(self.apply_app_filters); filter_row.addWidget(b_icon)
                lay.addLayout(filter_row)
            if name=='Process Monitor':
                b=QPushButton('Processleri Yenile'); b.clicked.connect(self.load_processes); lay.addWidget(b)
            if name=='Durdurulanlar':
                row_btn=QHBoxLayout()
                b=QPushButton('Durdurulan/Suspend Edilenleri Listele'); b.clicked.connect(self.load_intervention_targets); row_btn.addWidget(b)
                b2=QPushButton('Seçileni Başlat / Unsuspend'); b2.clicked.connect(self.launch_selected_intervention); row_btn.addWidget(b2)
                b3=QPushButton('Seçileni Sadece Unsuspend'); b3.clicked.connect(self.unsuspend_selected_intervention); row_btn.addWidget(b3)
                row_btn.addStretch(); lay.addLayout(row_btn)
            if name=='Evidence Locker':
                b=QPushButton('Case Klasörünü Aç'); b.clicked.connect(self.open_case); lay.addWidget(b)
            table=QTableWidget(0,len(headers)); table.setHorizontalHeaderLabels(headers); table.horizontalHeader().setStretchLastSection(True); table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive); table.verticalHeader().setDefaultSectionSize(30); table.setAlternatingRowColors(True); table.setSelectionBehavior(QAbstractItemView.SelectRows); table.setContextMenuPolicy(Qt.CustomContextMenu); table.customContextMenuRequested.connect(lambda pos,t=table,n=name:self.context_menu(n,t,pos)); harden_table(table); lay.addWidget(table); self.tables[name]=table; self.tabs.addTab(page,name)
        hunt=QWidget(); hl=QVBoxLayout(hunt); hr=QHBoxLayout(); self.hunt_query=QLineEdit(); self.hunt_query.setPlaceholderText('Hunt query: package, ip, accessibility, crash, country, company...'); hb=QPushButton('Threat Hunt Çalıştır'); hb.clicked.connect(self.run_hunt); hr.addWidget(self.hunt_query,1); hr.addWidget(hb); hl.addLayout(hr); self.hunt_table=QTableWidget(0,2); self.hunt_table.setHorizontalHeaderLabels(['Bölüm','Sonuç']); self.hunt_table.horizontalHeader().setStretchLastSection(True); harden_table(self.hunt_table); hl.addWidget(self.hunt_table); self.tabs.addTab(hunt,'Threat Hunting')
        ai_page=QWidget(); al=QVBoxLayout(ai_page); ab=QPushButton('AI Threat Analyst Özeti Oluştur'); ab.clicked.connect(self.run_ai_analyst); al.addWidget(ab); self.ai_text=QTextEdit(); self.ai_text.setReadOnly(True); al.addWidget(self.ai_text); self.tabs.addTab(ai_page,'AI Analyst')
        sim_page=QWidget(); sl=QVBoxLayout(sim_page); sb=QPushButton('Lab Senaryolarını Yükle'); sb.clicked.connect(self.load_simulator); sl.addWidget(sb); self.sim_table=QTableWidget(0,3); self.sim_table.setHorizontalHeaderLabels(['ID','Senaryo','Beklenen Alarm']); self.sim_table.horizontalHeader().setStretchLastSection(True); harden_table(self.sim_table); sl.addWidget(self.sim_table); self.tabs.addTab(sim_page,'Attack Simulator')
        live=QWidget(); l=QVBoxLayout(live); row=QHBoxLayout(); b1=QPushButton('Canlı Log Başlat'); b1.clicked.connect(self.start_live); b2=QPushButton('Durdur'); b2.clicked.connect(self.stop_live); b3=QPushButton('Temizle'); b3.clicked.connect(lambda:self.live_text.clear()); row.addWidget(b1); row.addWidget(b2); row.addWidget(b3); row.addStretch(); l.addLayout(row); self.live_text=QTextEdit(); self.live_text.setReadOnly(True); l.addWidget(self.live_text,2); self.live_table=QTableWidget(0,5); self.live_table.setHorizontalHeaderLabels(['Kategori','Anahtar','Risk','Karar','Satır']); self.live_table.horizontalHeader().setStretchLastSection(True); harden_table(self.live_table); l.addWidget(self.live_table,1); self.tabs.addTab(live,'Canlı Log Analiz')
    def fill(self, table, rows):
        table.setRowCount(0)
        for r in rows:
            i=table.rowCount(); table.insertRow(i)
            row_risk = 0
            try:
                risk_cols = [c for c in range(table.columnCount()) if 'risk' in table.horizontalHeaderItem(c).text().lower()]
                if risk_cols and len(r) > risk_cols[0]:
                    row_risk = int(str(r[risk_cols[0]]).strip() or 0)
            except Exception:
                row_risk = 0
            for c,val in enumerate(r):
                item = QTableWidgetItem(str(val))
                if row_risk >= 70:
                    item.setBackground(QBrush(QColor('#2a0606'))); item.setForeground(QBrush(QColor('#fecaca')))
                elif row_risk >= 35:
                    item.setBackground(QBrush(QColor('#1f1a05'))); item.setForeground(QBrush(QColor('#fde68a')))
                else:
                    item.setBackground(QBrush(QColor('#020617' if i % 2 == 0 else '#061426'))); item.setForeground(QBrush(QColor('#dbeafe')))
                table.setItem(i,c,item)
        harden_table(table)
    def refresh_devices(self):
        dev=self.adb.devices(); self.device_label.setText((dev[0]['serial']+' / '+dev[0]['state']) if dev else 'Cihaz yok')
    def start_analysis(self):
        self.refresh_devices(); self.worker=AnalysisWorker(self.adb,self.locker); self.worker.progress.connect(lambda p,s:(self.progress.setValue(p), self.statusBar().showMessage(s))); self.worker.done.connect(self.analysis_done); self.worker.error.connect(lambda e: QMessageBox.critical(self,'Hata',e)); self.btn_analyze.setDisabled(True); self.worker.finished.connect(lambda:self.btn_analyze.setDisabled(False)); self.worker.start()
    def analysis_done(self,d):
        self.data=d; s=d['summary']; self.cards['Genel Risk'].setText(f"{s['level']} / {s['score']}"); self.cards['Riskli Uygulama'].setText(str(s['risky_apps'])); self.cards['Riskli Socket'].setText(str(s['risky_sockets'])); self.cards['Crash/Log İzi'].setText(str(s['crash_log'])); self.cards['Sistem Erişimi'].setText(str(s['system_findings']))
        self.fill(self.tables['Dashboard'], [['Case',d['case'],'Evidence klasörü'],['Rapor',d['report'],'HTML rapor'],['Cihaz',d['device'].get('model',''),'Model'],['Security Patch',d['device'].get('security_patch',''),'Eski yama zero-click riskini artırır']])
        self.all_app_rows = sorted(d['apps'], key=lambda x:x.get('risk',0), reverse=True); self.apply_app_filters()
        self.fill(self.tables['Ağ / Socket'], [[n['proto'],n['local'],n['remote'],n.get('country',''),(n.get('company','')+' '+n.get('asn','')).strip(),n['state'],n['uid'],n.get('packages',''),n['risk'],n.get('reasons','')] for n in d['net']])
        self.fill(self.tables['Crash Analizi'], [[l['source'],l['category'],l['key'],l['risk'],l['decision'],l['line']] for l in sorted(d['logs'],key=lambda x:x.get('risk',0), reverse=True)])
        self.fill(self.tables['Timeline'], [[t['time'],t['type'],t['title'],t['risk'],t['detail']] for t in d['timeline']])
        self.fill(self.tables['Evidence Locker'], [['Case',d['case']],['Report',d['report']]])
        self.fill_advanced_tabs(d)

    def fill_advanced_tabs(self, d):
        try:
            iocs=self.threat.summarize(d.get('apps',[]), d.get('net',[]))
            self.fill(self.tables['Threat Intel'], [[x.get('target',''),x.get('type',''),x.get('score',''),x.get('mitre',''),x.get('reason','')] for x in sorted(iocs,key=lambda z:z.get('score',0), reverse=True)])
            dm=DeviceMapBuilder().build(d.get('net',[]))
            self.fill(self.tables['Live Device Map'], [[x['device'],x['app'],x['remote'],x['country'],x['company'],x['risk']] for x in dm])
            pm=PermissionMatrix().build(d.get('apps',[]))
            self.fill(self.tables['Permission Matrix'], pm)
            edr=self.edr.evaluate(d)
            self.fill(self.tables['Mobile EDR'], [[x['rule'],x['target'],x['severity'],x['action']] for x in edr])
            yara_rows=[]
            for a in d.get('apps',[]):
                txt=' '.join([a.get('package',''), ' '.join(a.get('permissions') or []), ' '.join(a.get('reasons') or [])])
                for hit in self.yara.scan_text(a.get('package',''), txt):
                    yara_rows.append([hit['file'], hit['rule'], hit['risk'], hit['matches']])
            self.fill(self.tables['YARA / VT'], yara_rows)
            self.run_ai_analyst()
            self.load_simulator()
            self.record_session('ANALYSIS_COMPLETE', f"score={d.get('summary',{}).get('score')}")
        except Exception as e:
            self.statusBar().showMessage(f'Advanced tab fill error: {e}')

    def run_hunt(self):
        rows=self.hunt.query(self.data, self.hunt_query.text() if hasattr(self,'hunt_query') else '')
        self.fill(self.hunt_table, [[r['section'], r['result']] for r in rows])
        self.record_session('HUNT_QUERY', getattr(self,'hunt_query',QLineEdit()).text() if hasattr(self,'hunt_query') else '')

    def run_ai_analyst(self):
        if hasattr(self,'ai_text'):
            self.ai_text.setPlainText(self.ai.analyze(self.data or {}))
            self.record_session('AI_ANALYST', 'summary generated')

    def load_simulator(self):
        if hasattr(self,'sim_table'):
            self.fill(self.sim_table, AttackSimulator().scenarios())

    def record_session(self, action, detail=''):
        try:
            if self.locker.case_dir:
                SessionRecorder(os.path.join(self.locker.case_dir,'session','actions.log')).log(action, detail)
                if 'Session Recorder' in self.tables:
                    import time
                    t=self.tables['Session Recorder']; i=t.rowCount(); t.insertRow(i)
                    for c,v in enumerate([time.strftime('%H:%M:%S'), action, detail]): t.setItem(i,c,QTableWidgetItem(str(v)))
        except Exception:
            pass

    def context_menu(self, name, table, pos):
        row=table.currentRow();
        if row<0: return
        menu=QMenu(self); pkg=''
        if name=='Uygulamalar': pkg=table.item(row,2).text()
        elif name=='Ağ / Socket': pkg=(table.item(row,5).text() or '').split(',')[0].strip()
        elif name=='Process Monitor': pid=table.item(row,1).text(); act=menu.addAction('PID öldür (kill -9)'); act.triggered.connect(lambda:self.run_kill_pid(pid)); menu.exec(table.mapToGlobal(pos)); return
        elif name=='Durdurulanlar': pkg=table.item(row,0).text()
        if pkg:
            for text,fn in [('Güvenli Durdur / Force-stop',self.resp.safe_stop),('Force-stop',self.resp.force_stop),('Suspend/Uyut (Dikkat)',self.resp.suspend),('Unsuspend/Aç',self.resp.unsuspend),('Başlat / Launch',self.resp.launch_package)]:
                a=menu.addAction(text); a.triggered.connect(lambda checked=False,p=pkg,f=fn,t=text:self.run_resp(p,t,f))
            a=menu.addAction('Background ağ/çalışma kısıtla'); a.triggered.connect(lambda:self.log_action(pkg,'Restrict background',self.resp.restrict_background(pkg)))
            a=menu.addAction('Background kısıtını kaldır'); a.triggered.connect(lambda:self.log_action(pkg,'Allow background',self.resp.allow_background(pkg)))
            a=menu.addAction('APK’yı Evidence klasörüne çek'); a.triggered.connect(lambda:self.extract_apk(pkg))
            menu.exec(table.mapToGlobal(pos))
    def run_resp(self,pkg,text,fn):
        if 'Suspend' in text and self.resp.is_sensitive_package(pkg):
            ok=QMessageBox.question(self,'Hassas uygulama uyarısı',f'{pkg} bankacılık/kimlik doğrulama kategorisine benziyor. Suspend uygulamayı yönetiliyor/kullanılamıyor durumuna alabilir. Devam edilsin mi?')
            if ok != QMessageBox.Yes:
                self.log_action(pkg,text,'İptal edildi: hassas uygulamada suspend önerilmez. Force-stop kullanıldı/kullanılmalı.')
                return
        r=fn(pkg)
        if hasattr(r, 'stdout'):
            result=(r.stdout or '')+(r.stderr or 'OK')
        else:
            result=str(r) if r else 'OK'
        self.log_action(pkg,text,result)
        if 'Suspend' in text or text in ('Unsuspend/Aç','Başlat / Launch','Güvenli Durdur / Force-stop','Force-stop'):
            self.load_intervention_targets(silent=True)
    def log_action(self,target,action,result):
        try: QApplication.beep()
        except Exception: pass
        t=self.tables['Active Response']; i=t.rowCount(); t.insertRow(i); 
        for c,v in enumerate([target,action,result[:1000] or 'OK']): t.setItem(i,c,QTableWidgetItem(str(v)))
        self.record_session(action, f'{target}: {str(result)[:250]}')


    def apply_app_filters(self):
        try:
            q=(self.app_search.text() if hasattr(self,'app_search') else '').strip().lower()
            cat=(self.app_category.currentText() if hasattr(self,'app_category') else 'Tüm Kategoriler')
            rows=[]
            for a in self.all_app_rows:
                category=a.get('category','Other')
                hay=' '.join([a.get('package',''), category, ' '.join(a.get('permissions') or []), ' '.join(a.get('reasons') or [])]).lower()
                if cat != 'Tüm Kategoriler' and category != cat:
                    continue
                if q and q not in hay:
                    continue
                rows.append([a.get('icon','📦'), category, a.get('package',''), a.get('uid',''), a.get('risk',0), ', '.join(a.get('reasons') or [])])
            self.fill(self.tables['Uygulamalar'], rows)
            self.statusBar().showMessage(f'Uygulama filtresi: {len(rows)} kayıt')
        except Exception as e:
            self.statusBar().showMessage(f'Uygulama filtresi hatası: {e}')

    def run_kill_pid(self, pid):
        r=self.resp.kill_pid(pid)
        self.log_action(str(pid),'kill_pid',(r.stdout or '')+(r.stderr or 'OK'))

    def update_cyber_effect(self):
        if not hasattr(self, 'fx_label'):
            return
        self.effect_tick += 1
        phases = [
            'NSA_STYLE LIVE TRIAGE // ADB CHANNEL OPEN // █▒▒▒▒',
            'CIA_STYLE INCIDENT RESPONSE // SOCKET TRACE // ██▒▒▒',
            'EBS DFIR MATRIX // CRASH ATTRIBUTION ENGINE // ███▒▒',
            'ZERO-CLICK SURFACE WATCH // MEDIA WEBVIEW BT // ████▒',
            'ACTIVE RESPONSE READY // FORCE-STOP UNSUSPEND LAUNCH // █████',
        ]
        self.fx_label.setText(phases[self.effect_tick % len(phases)])

    def _known_app_packages(self):
        apps=self.data.get('apps') or []
        return [a.get('package') for a in apps if a.get('package')]

    def load_intervention_targets(self, silent=False):
        try:
            packages=self._known_app_packages() or None
            states=self.resp.list_intervention_targets(packages)
            self.fill(self.tables['Durdurulanlar'], [[s['package'],s['status'],s['suspended'],s['stopped'],s['background']] for s in states])
            if not silent:
                self.statusBar().showMessage(f'Durdurulan/suspend edilen uygulama sayısı: {len(states)}')
        except Exception as e:
            if not silent:
                QMessageBox.warning(self,'Listeleme Hatası',str(e))

    def _selected_intervention_pkg(self):
        t=self.tables['Durdurulanlar']; row=t.currentRow()
        if row < 0:
            QMessageBox.information(self,'Seçim gerekli','Durdurulanlar listesinden bir paket seç.')
            return None
        return t.item(row,0).text()

    def launch_selected_intervention(self):
        pkg=self._selected_intervention_pkg()
        if not pkg: return
        result=self.resp.launch_package(pkg)
        self.log_action(pkg,'Başlat / Launch',result or 'OK')
        self.load_intervention_targets(silent=True)

    def unsuspend_selected_intervention(self):
        pkg=self._selected_intervention_pkg()
        if not pkg: return
        r=self.resp.unsuspend(pkg)
        self.log_action(pkg,'Unsuspend/Aç',(r.stdout or '')+(r.stderr or 'OK'))
        self.load_intervention_targets(silent=True)
    def extract_apk(self,pkg):
        if not self.locker.case_dir: self.locker.new_case()
        files=self.apps_an.pull_apk(pkg,self.locker.path('apks'))
        msg=[]
        for f in files: msg.append(f'{f}\nSHA256: {self.locker.register_file_hash(f)}')
        self.log_action(pkg,'APK Extract','\n'.join(msg) if msg else 'APK alınamadı')
    def load_processes(self):
        rows=ProcessMonitor(self.adb).list_processes(); self.fill(self.tables['Process Monitor'], [[r['user'],r['pid'],r['ppid'],r['name']] for r in rows])
    def start_live(self):
        if self.live:
            self.statusBar().showMessage('Canlı log zaten çalışıyor.')
            return
        self.refresh_devices()
        if not self.adb.serial:
            QMessageBox.warning(self, 'ADB Cihaz Yok', 'Canlı log için önce USB hata ayıklama açık bir Android cihaz bağla.')
            return
        self.live_analyzer = CrashLogAnalyzer(self.adb)
        self.live = LiveLogWorker(self.adb.adb_path, self.adb.serial, self)
        self.live.line.connect(self.on_live_line)
        self.live.error.connect(lambda e: QMessageBox.critical(self, 'Canlı Log Hatası', e))
        self.live.stopped.connect(self.on_live_stopped)
        self.live.start()
        self.statusBar().showMessage('Canlı log analizi başladı.')

    @Slot(str)
    def on_live_line(self, line):
        try:
            self.live_text.append(line)
            # QTextEdit büyüyüp arayüzü kilitlemesin diye son 5000 blok tutulur.
            self.live_text.document().setMaximumBlockCount(5000)
            for f in self.live_analyzer.classify_line(line, 'live'):
                i = self.live_table.rowCount()
                self.live_table.insertRow(i)
                risk=int(f.get('risk',0) or 0)
                for c, v in enumerate([f.get('category',''), f.get('key',''), risk, f.get('decision',''), f.get('line','')]):
                    item = QTableWidgetItem(str(v))
                    if risk >= 70:
                        item.setBackground(QBrush(QColor('#2a0606'))); item.setForeground(QBrush(QColor('#fecaca')))
                    elif risk >= 35:
                        item.setBackground(QBrush(QColor('#1f1a05'))); item.setForeground(QBrush(QColor('#fde68a')))
                    else:
                        item.setBackground(QBrush(QColor('#020617'))); item.setForeground(QBrush(QColor('#dbeafe')))
                    self.live_table.setItem(i, c, item)
                if self.live_table.rowCount() > 1000:
                    self.live_table.removeRow(0)
        except Exception as e:
            self.statusBar().showMessage(f'Canlı log satırı işlenemedi: {e}')

    def stop_live(self):
        if self.live:
            self.live.stop()
            self.live.wait(1500)
            self.live = None
            self.statusBar().showMessage('Canlı log durduruldu.')

    def on_live_stopped(self):
        self.live = None
        self.statusBar().showMessage('Canlı log kapandı.')
    def open_report(self):
        p=self.data.get('report')
        if p and os.path.exists(p): webbrowser.open(p)
    def open_case(self):
        p=self.locker.case_dir
        if p and os.path.exists(p): os.startfile(p) if sys.platform.startswith('win') else webbrowser.open(p)

if __name__=='__main__':
    app=QApplication(sys.argv); w=MainWindow(); w.show(); sys.exit(app.exec())
