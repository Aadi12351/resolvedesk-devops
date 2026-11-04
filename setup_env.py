"""Generate local secrets once. Never overwrite an existing .env."""
from pathlib import Path
import secrets, os
p=Path('.env')
if p.exists():
 print('.env already exists; keeping existing credentials.')
else:
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:
  f.write('SECRET_KEY='+secrets.token_hex(32)+'\nPOSTGRES_PASSWORD='+secrets.token_hex(24)+'\nCOOKIE_SECURE=false\n')
 print('Created .env with random credentials.')
