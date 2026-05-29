import subprocess
import shlex
from dataclasses import dataclass

@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    code: int

class ADBClient:
    def __init__(self, adb_path='adb'):
        self.adb_path = adb_path
        self.serial = None

    def _base(self):
        cmd = [self.adb_path]
        if self.serial:
            cmd += ['-s', self.serial]
        return cmd

    def run(self, args, timeout=20):
        if isinstance(args, str):
            args = shlex.split(args)
        try:
            p = subprocess.run(self._base() + args, text=True, capture_output=True, timeout=timeout, errors='replace')
            return CommandResult(p.returncode == 0, p.stdout.strip(), p.stderr.strip(), p.returncode)
        except Exception as e:
            return CommandResult(False, '', str(e), -1)

    def shell(self, command, timeout=20):
        return self.run(['shell', command], timeout=timeout)

    def devices(self):
        r = self.run(['devices'], timeout=10)
        out = []
        for line in r.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if len(parts) >= 2:
                out.append({'serial': parts[0], 'state': parts[1]})
        if out and not self.serial:
            self.serial = out[0]['serial']
        return out

    def pull(self, remote, local, timeout=120):
        return self.run(['pull', remote, local], timeout=timeout)
