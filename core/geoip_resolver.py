import ipaddress, csv, os

class GeoIPResolver:
    """Offline-first IP enrichment. Optional assets/geoip.csv columns: prefix,country,company,asn."""
    DEFAULT_PREFIXES = [
        ('8.8.8.0/24','US','Google LLC','AS15169'),('8.34.208.0/20','US','Google LLC','AS15169'),
        ('64.233.160.0/19','US','Google LLC','AS15169'),('66.249.64.0/19','US','Google LLC','AS15169'),
        ('72.14.192.0/18','US','Google LLC','AS15169'),('74.125.0.0/16','US','Google LLC','AS15169'),
        ('108.177.0.0/17','US','Google LLC','AS15169'),('142.250.0.0/15','US','Google LLC','AS15169'),
        ('172.217.0.0/16','US','Google LLC','AS15169'),('172.253.0.0/16','US','Google LLC','AS15169'),
        ('173.194.0.0/16','US','Google LLC','AS15169'),('192.178.0.0/15','US','Google LLC','AS15169'),
        ('216.58.192.0/19','US','Google LLC','AS15169'),('216.239.32.0/19','US','Google LLC','AS15169'),
        ('13.64.0.0/11','US','Microsoft Azure','AS8075'),('20.0.0.0/8','US','Microsoft Corporation / Azure','AS8075'),
        ('40.64.0.0/10','US','Microsoft Azure','AS8075'),('52.128.0.0/9','US','Microsoft Azure','AS8075'),
        ('150.171.0.0/16','US','Microsoft Corporation','AS8075'),('13.107.0.0/16','US','Microsoft Corporation','AS8068'),
        ('1.1.1.0/24','US','Cloudflare','AS13335'),('1.0.0.0/24','US','Cloudflare','AS13335'),
        ('104.16.0.0/12','US','Cloudflare','AS13335'),('162.158.0.0/15','US','Cloudflare','AS13335'),
        ('199.232.0.0/16','US','Fastly CDN','AS54113'),('151.101.0.0/16','US','Fastly CDN','AS54113'),
        ('149.154.160.0/20','NL','Telegram Messenger Network','AS62041'),('91.108.4.0/22','NL','Telegram Messenger Network','AS62041'),
        ('31.13.64.0/18','US','Meta Platforms','AS32934'),('157.240.0.0/16','US','Meta Platforms','AS32934'),
        ('17.0.0.0/8','US','Apple Inc.','AS714'),('185.60.216.0/22','US','Meta Platforms / WhatsApp','AS32934'),
    ]
    def __init__(self, csv_path=None):
        self.nets=[]
        for p,c,co,a in self.DEFAULT_PREFIXES: self._add(p,c,co,a)
        if csv_path and os.path.exists(csv_path):
            with open(csv_path, newline='', encoding='utf-8') as f:
                for row in csv.DictReader(f): self._add(row.get('prefix',''), row.get('country',''), row.get('company',''), row.get('asn',''))
    def _add(self,prefix,country,company,asn):
        try: self.nets.append((ipaddress.ip_network(prefix, strict=False), country or 'Unknown', company or 'Unknown', asn or ''))
        except Exception: pass
    def lookup(self, ip):
        try: obj=ipaddress.ip_address((ip or '').split('%')[0])
        except Exception: return {'country':'Invalid','company':'Invalid IP','asn':'','scope':'invalid'}
        if obj.is_loopback: return {'country':'Local','company':'Loopback','asn':'','scope':'local'}
        if obj.is_private: return {'country':'Private','company':'Private/LAN or carrier NAT','asn':'','scope':'private'}
        if obj.is_multicast: return {'country':'Multicast','company':'Multicast','asn':'','scope':'multicast'}
        for net,country,company,asn in self.nets:
            if obj in net: return {'country':country,'company':company,'asn':asn,'scope':'public'}
        return {'country':'Unknown','company':'Unknown ASN/Company - add GeoLite CSV for accuracy','asn':'','scope':'public'}
