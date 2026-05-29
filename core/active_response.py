import re


class ActiveResponseEngine:
    """Active response actions over ADB.

    Notes:
    - force-stop is temporary and Android does not expose a perfect global
      "force-stopped apps" list on every build.
    - suspend is persistent and can be listed more reliably.
    - launch_package first unsuspends the target, then starts the default
      launcher activity with monkey.
    """
    def __init__(self, adb):
        self.adb = adb


    SENSITIVE_HINTS = ('bank','vakif','ziraat','kuveyt','finans','garanti','akbank','isbank','yapi','authenticator','edevlet','kimlik','wallet','papara')

    def is_sensitive_package(self, package):
        p = (package or '').lower()
        return any(x in p for x in self.SENSITIVE_HINTS)

    def safe_stop(self, package):
        """Default intervention: force-stop only. Does not suspend sensitive apps."""
        return self.force_stop(package)

    def force_stop(self, package):
        return self.adb.shell(f'am force-stop {package}', timeout=10)

    def suspend(self, package):
        return self.adb.shell(f'cmd package suspend {package}', timeout=10)

    def unsuspend(self, package):
        return self.adb.shell(f'cmd package unsuspend {package}', timeout=10)

    def launch_package(self, package):
        # If package was suspended by our tool, Android will not launch it until unsuspended.
        u = self.unsuspend(package)
        r = self.adb.shell(
            f'monkey -p {package} -c android.intent.category.LAUNCHER 1',
            timeout=12,
        )
        return (u.stdout or '') + (u.stderr or '') + '\n' + (r.stdout or '') + (r.stderr or '')

    def restrict_background(self, package):
        r1 = self.adb.shell(f'cmd appops set {package} RUN_IN_BACKGROUND ignore', timeout=10)
        r2 = self.adb.shell(f'cmd appops set {package} RUN_ANY_IN_BACKGROUND ignore', timeout=10)
        return r1.stdout + r1.stderr + '\n' + r2.stdout + r2.stderr

    def allow_background(self, package):
        r1 = self.adb.shell(f'cmd appops set {package} RUN_IN_BACKGROUND allow', timeout=10)
        r2 = self.adb.shell(f'cmd appops set {package} RUN_ANY_IN_BACKGROUND allow', timeout=10)
        return r1.stdout + r1.stderr + '\n' + r2.stdout + r2.stderr

    def kill_pid(self, pid):
        return self.adb.shell(f'kill -9 {pid}', timeout=10)

    def list_suspended_packages(self):
        """Return packages currently suspended by PackageManager where supported."""
        candidates = [
            'cmd package list packages --suspended',
            'pm list packages --suspended',
        ]
        found = []
        for cmd in candidates:
            r = self.adb.shell(cmd, timeout=15)
            text = (r.stdout or '') + '\n' + (r.stderr or '')
            for line in text.splitlines():
                line = line.strip()
                if line.startswith('package:'):
                    found.append(line.split(':', 1)[1].strip())
            if found:
                break
        return sorted(set(found))

    def list_user_packages(self):
        r = self.adb.shell('pm list packages -3', timeout=20)
        out = r.stdout or ''
        return sorted({ln.split(':', 1)[1].strip() for ln in out.splitlines() if ln.startswith('package:')})

    def package_state(self, package):
        """Best-effort state detection for stopped/suspended/background-restricted."""
        r = self.adb.shell(f'dumpsys package {package}', timeout=15)
        text = (r.stdout or '') + '\n' + (r.stderr or '')
        low = text.lower()

        stopped = 'stopped=true' in low or 'stopped=true' in text
        suspended = package in self.list_suspended_packages() or 'suspended=true' in low

        bg = 'unknown'
        appops = self.adb.shell(f'cmd appops get {package}', timeout=10)
        appops_text = (appops.stdout or '') + '\n' + (appops.stderr or '')
        if 'RUN_IN_BACKGROUND: ignore' in appops_text or 'RUN_ANY_IN_BACKGROUND: ignore' in appops_text:
            bg = 'restricted'
        elif 'RUN_IN_BACKGROUND: allow' in appops_text or 'RUN_ANY_IN_BACKGROUND: allow' in appops_text:
            bg = 'allowed'

        status = []
        if suspended: status.append('SUSPENDED')
        if stopped: status.append('STOPPED')
        if bg == 'restricted': status.append('BACKGROUND_RESTRICTED')
        return {
            'package': package,
            'suspended': suspended,
            'stopped': stopped,
            'background': bg,
            'status': ', '.join(status) if status else 'ACTIVE/UNKNOWN',
        }

    def list_intervention_targets(self, packages=None):
        """List apps that are suspended/stopped/background-restricted.

        For performance, pass packages from the current app analysis table when possible.
        """
        packages = packages or self.list_user_packages()
        states = []
        suspended_set = set(self.list_suspended_packages())
        for pkg in packages:
            st = self.package_state(pkg)
            if pkg in suspended_set:
                st['suspended'] = True
                st['status'] = 'SUSPENDED' if st['status'] == 'ACTIVE/UNKNOWN' else st['status']
            if st['suspended'] or st['stopped'] or st['background'] == 'restricted':
                states.append(st)
        return states
