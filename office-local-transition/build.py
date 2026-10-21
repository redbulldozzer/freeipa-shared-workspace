#!/usr/bin/python3
"""Small distributable with an allowlist: no inventory, credentials or journals."""
import hashlib
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
dist = root/'dist'
dist.mkdir(exist_ok=True)
archive = dist/'office-local-transition-0.1.0.tar.gz'
names = ['install.py', 'entry.py', 'gui.py', 'README.md',
         *sorted('transition/'+p.name for p in (root/'transition').glob('*.py'))]
with tarfile.open(archive, 'w:gz') as tar:
    for name in names:
        path = root/name
        if path.is_symlink():
            raise SystemExit('Symlink in source manifest')
        tar.add(path, arcname='office-local-transition/'+name, recursive=False)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(dist/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n')
print(archive)
print(digest)
