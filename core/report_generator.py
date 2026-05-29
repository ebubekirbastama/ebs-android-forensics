import html, os
from datetime import datetime
class ReportGenerator:
    def generate(self, path, device, summary, apps, net, logs, sysfindings, timeline):
        def esc(x): return html.escape(str(x if x is not None else ''))
        css='''body{font-family:Arial;background:#07111f;color:#e5e7eb;margin:24px}h1,h2{color:#93c5fd}.card{background:#101827;border:1px solid #3158d4;border-radius:14px;padding:16px;margin:12px 0}table{border-collapse:collapse;width:100%;background:#0b1220}td,th{border:1px solid #27448f;padding:7px;font-size:12px;vertical-align:top}th{background:#182b62}.risk{font-size:28px;font-weight:bold;color:#fca5a5}.ok{color:#86efac}.warn{color:#fbbf24}'''
        out=[f'<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>EBS Sentinel DFIR X</title><style>{css}</style></head><body>']
        out.append('<h1>EBS Sentinel DFIR X Pro</h1>')
        out.append(f'<div class="card"><div>Analiz zamanı: {datetime.now().isoformat(timespec="seconds")}</div><div class="risk">Genel risk: {esc(summary["level"])} / {summary["score"]}</div><ul><li>Riskli uygulama: {summary["risky_apps"]}</li><li>Riskli socket: {summary["risky_sockets"]}</li><li>Crash/log izi: {summary["crash_log"]}</li><li>Sistem erişimi: {summary["system_findings"]}</li></ul></div>')
        out.append('<h2>Cihaz Bilgisi</h2><table>')
        for k,v in device.items(): out.append(f'<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>')
        out.append('</table>')
        out.append('<h2>Sistem Erişim Bulguları</h2><table><tr><th>Kategori</th><th>Risk</th><th>Neden</th><th>Değer</th></tr>')
        for s in sysfindings: out.append(f'<tr><td>{esc(s["category"])}</td><td>{s["risk"]}</td><td>{esc(s["reason"])}</td><td>{esc(s["value"])}</td></tr>')
        out.append('</table>')
        out.append('<h2>Yüksek Riskli Uygulamalar</h2><table><tr><th>Paket</th><th>UID</th><th>Risk</th><th>Nedenler</th></tr>')
        for a in sorted(apps,key=lambda x:x.get('risk',0), reverse=True): out.append(f'<tr><td>{esc(a["package"])}</td><td>{esc(a.get("uid"))}</td><td>{a.get("risk")}</td><td>{esc(", ".join(a.get("reasons") or []))}</td></tr>')
        out.append('</table>')
        out.append('<h2>Ağ / Socket</h2><table><tr><th>Proto</th><th>Local</th><th>Remote</th><th>State</th><th>UID</th><th>Paket</th><th>Risk</th><th>Neden</th></tr>')
        for n in net: out.append(f'<tr><td>{esc(n["proto"])}</td><td>{esc(n["local"])}</td><td>{esc(n["remote"])}</td><td>{esc(n["state"])}</td><td>{esc(n["uid"])}</td><td>{esc(n.get("packages"))}</td><td>{n.get("risk")}</td><td>{esc(n.get("reasons"))}</td></tr>')
        out.append('</table>')
        out.append('<h2>Crash / Log Bulguları</h2><table><tr><th>Kaynak</th><th>Kategori</th><th>Anahtar</th><th>Risk</th><th>Karar</th><th>Satır</th></tr>')
        for l in sorted(logs,key=lambda x:x.get('risk',0), reverse=True)[:500]: out.append(f'<tr><td>{esc(l["source"])}</td><td>{esc(l["category"])}</td><td>{esc(l["key"])}</td><td>{l["risk"]}</td><td>{esc(l["decision"])}</td><td>{esc(l["line"])}</td></tr>')
        out.append('</table>')
        out.append('<h2>Timeline</h2><table><tr><th>Time</th><th>Tip</th><th>Başlık</th><th>Risk</th><th>Detay</th></tr>')
        for t in timeline[:500]: out.append(f'<tr><td>{esc(t["time"])}</td><td>{esc(t["type"])}</td><td>{esc(t["title"])}</td><td>{t["risk"]}</td><td>{esc(t["detail"])}</td></tr>')
        out.append('</table></body></html>')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path,'w',encoding='utf-8') as f: f.write('\n'.join(out))
        return path
