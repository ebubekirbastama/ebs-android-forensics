from datetime import datetime
class TimelineEngine:
    def build(self, apps, net, logs, sysfindings):
        events=[]
        for a in apps:
            if a.get('risk',0) >= 80:
                events.append({'time':'-', 'type':'APP_RISK', 'title':a['package'], 'detail':', '.join(a.get('reasons') or [])[:300], 'risk':a['risk']})
        for n in net:
            if n.get('risk',0) >= 20:
                events.append({'time':'-', 'type':'NETWORK', 'title':n.get('packages') or n.get('uid'), 'detail':f"{n.get('local')} -> {n.get('remote')} {n.get('state')}", 'risk':n['risk']})
        for l in logs[:200]:
            events.append({'time':l['line'][:18], 'type':'LOG', 'title':l['category'], 'detail':l['line'][:300], 'risk':l['risk']})
        for s in sysfindings:
            events.append({'time':'-', 'type':'SYSTEM_ACCESS', 'title':s['category'], 'detail':s['reason'], 'risk':s['risk']})
        return sorted(events, key=lambda x: x.get('risk',0), reverse=True)
