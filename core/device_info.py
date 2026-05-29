class DeviceInfoCollector:
    def __init__(self, adb):
        self.adb = adb

    def collect(self):
        props = {}
        mapping = {
            'brand': 'ro.product.brand', 'manufacturer': 'ro.product.manufacturer',
            'model': 'ro.product.model', 'device': 'ro.product.device',
            'android': 'ro.build.version.release', 'sdk': 'ro.build.version.sdk',
            'security_patch': 'ro.build.version.security_patch', 'fingerprint': 'ro.build.fingerprint',
            'build_id': 'ro.build.display.id'
        }
        for k, prop in mapping.items():
            props[k] = self.adb.shell(f'getprop {prop}').stdout
        props['battery'] = self.adb.shell('dumpsys battery', timeout=15).stdout[:3000]
        props['adb_serial'] = self.adb.serial or ''
        return props
