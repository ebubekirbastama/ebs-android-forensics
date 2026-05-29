import os, json, hashlib, shutil
from datetime import datetime

class EvidenceLocker:
    def __init__(self, root='evidence'):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.case_dir = None

    def new_case(self, prefix='EBS'):
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.case_dir = os.path.join(self.root, f'{prefix}_CASE_{stamp}')
        for d in ['logs','apks','reports','network','metadata','screenshots','hashes']:
            os.makedirs(os.path.join(self.case_dir, d), exist_ok=True)
        return self.case_dir

    def path(self, *parts):
        if not self.case_dir:
            self.new_case()
        return os.path.join(self.case_dir, *parts)

    def save_text(self, rel, text):
        p = self.path(*rel.split('/'))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8', errors='replace') as f: f.write(text or '')
        return p

    def save_json(self, rel, obj):
        return self.save_text(rel, json.dumps(obj, ensure_ascii=False, indent=2))

    def sha256(self, file_path):
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for b in iter(lambda: f.read(1024*1024), b''):
                h.update(b)
        return h.hexdigest()

    def register_file_hash(self, file_path):
        digest = self.sha256(file_path)
        self.save_text(f'hashes/{os.path.basename(file_path)}.sha256', f'{digest}  {file_path}\n')
        return digest
