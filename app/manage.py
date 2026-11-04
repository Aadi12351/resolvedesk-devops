"""Explicit administrator bootstrap; no default admin credentials."""
import argparse, getpass
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.main import Base, engine, User, hash_password
if __name__=='__main__':
 p=argparse.ArgumentParser(); p.add_argument('command',choices=['init-db','create-admin']); p.add_argument('--email'); p.add_argument('--name',default='Administrator'); a=p.parse_args()
 Base.metadata.create_all(engine)
 if a.command=='create-admin':
  if not a.email: p.error('--email is required')
  password=getpass.getpass('Admin password (10–128 characters): ')
  if not 10<=len(password)<=128: p.error('Invalid password length')
  if password!=getpass.getpass('Confirm password: '): p.error('Passwords do not match')
  with Session(engine) as db:
   if db.scalar(select(User).where(User.email==a.email.strip().lower())): p.error('Email already exists; use another email')
   db.add(User(name=a.name,email=a.email.strip().lower(),password=hash_password(password),role='admin')); db.commit()
  print('Administrator created.')
 else: print('Database initialized.')
