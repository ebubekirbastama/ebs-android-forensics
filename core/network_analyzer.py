import socket, struct, os
from core.geoip_resolver import GeoIPResolver
TCP_STATES={'01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV','04':'FIN_WAIT1','05':'FIN_WAIT2','06':'TIME_WAIT','07':'CLOSE','08':'CLOSE_WAIT','09':'LAST_ACK','0A':'LISTEN','0B':'CLOSING'}

def _hex_ip(h):
    try: return socket.inet_ntoa(struct.pack('<L', int(h,16)))
    except Exception: return '0.0.0.0'

def _parse_addr(x):
    ip,port=x.split(':')
    return _hex_ip(ip), int(port,16)

class NetworkAnalyzer:
    def __init__(self, adb):
        self.adb=adb
        root=os.path.abspath(os.path.join(os.path.dirname(__file__),'..'))
        self.geo=GeoIPResolver(os.path.join(root,'assets','geoip.csv'))

    def uid_package_map(self):
        mp={}
        out=self.adb.shell('pm list packages -U', timeout=30).stdout
        for line in out.splitlines():
            if 'uid:' in line:
                pkg=line.split('package:')[-1].split()[0]
                uid=line.split('uid:')[-1].strip()
                mp.setdefault(uid, []).append(pkg)
        return mp

    def parse_proc_net(self, proto='tcp'):
        out=self.adb.shell(f'cat /proc/net/{proto}', timeout=15).stdout
        rows=[]
        for line in out.splitlines()[1:]:
            parts=line.split()
            if len(parts) < 8: continue
            lip,lport=_parse_addr(parts[1]); rip,rport=_parse_addr(parts[2])
            st=TCP_STATES.get(parts[3], parts[3])
            uid=parts[7]
            rows.append({'proto':proto,'local':f'{lip}:{lport}','remote':f'{rip}:{rport}','state':st,'uid':uid})
        return rows

    def analyze(self):
        uidmap=self.uid_package_map()
        rows=[]
        for proto in ['tcp','udp']:
            rows += self.parse_proc_net(proto)
        for r in rows:
            r['packages'] = ', '.join(uidmap.get(r['uid'], []))
            risk=0; reasons=[]
            rip = r['remote'].split(':')[0]
            if r['state']=='ESTABLISHED': risk += 15
            if rip not in ('0.0.0.0','127.0.0.1') and not rip.startswith('192.168.') and r['state'] not in ('LISTEN','TIME_WAIT'):
                risk += 10; reasons.append('Dış bağlantı')
            if not r['packages'] and r['uid'] not in ('0','1000'):
                risk += 10; reasons.append('UID paketle eşleşmedi')
            if r['uid']=='0':
                reasons.append('UID 0: kapanmış/kernel socket olabilir; düşük güven')
            geo=self.geo.lookup(rip)
            r.update(geo)
            if geo.get('scope')=='public' and geo.get('company','').startswith('Unknown') and r['state'] not in ('LISTEN','TIME_WAIT'):
                risk += 20; reasons.append('Bilinmeyen public IP/ASN')
            r['risk']=risk; r['reasons']='; '.join(reasons)
        return rows
