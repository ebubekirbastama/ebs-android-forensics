class RiskEngine:
    def summarize(self, apps, net, logs, sysfindings):
        risky_apps=[a for a in apps if a.get('risk',0)>=70]
        risky_net=[n for n in net if n.get('risk',0)>=20]
        risky_logs=[l for l in logs if l.get('risk',0)>=45]
        score = sum(a.get('risk',0) for a in risky_apps[:10])//5 + sum(n.get('risk',0) for n in risky_net[:20])//3 + sum(l.get('risk',0) for l in risky_logs[:20])//4 + sum(s.get('risk',0) for s in sysfindings)
        if score >= 180: level='KRİTİK'
        elif score >= 100: level='YÜKSEK'
        elif score >= 50: level='ORTA'
        else: level='DÜŞÜK'
        return {'score':score,'level':level,'risky_apps':len(risky_apps),'risky_sockets':len(risky_net),'crash_log':len(risky_logs),'system_findings':len(sysfindings)}
