import re
class ProcessMonitor:
    def __init__(self, adb): self.adb=adb
    def list_processes(self):
        out=self.adb.shell('ps -A -o USER,PID,PPID,NAME', timeout=15).stdout
        rows=[]
        for line in out.splitlines()[1:]:
            parts=line.split(None,3)
            if len(parts)==4:
                rows.append({'user':parts[0], 'pid':parts[1], 'ppid':parts[2], 'name':parts[3]})
        return rows
    def top_snapshot(self):
        return self.adb.shell('top -b -n 1', timeout=10).stdout
