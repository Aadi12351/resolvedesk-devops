import os, re, secrets, hashlib, hmac
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, String, Text, ForeignKey, select, func, or_, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from sqlalchemy.exc import IntegrityError

URL=os.getenv('DATABASE_URL','sqlite:///./resolvedesk.db')
KEY=os.getenv('SECRET_KEY','')
if len(KEY)<32: raise RuntimeError('Set SECRET_KEY to a random value of at least 32 characters. See README.')
engine=create_engine(URL, pool_pre_ping=True, connect_args={'check_same_thread':False} if URL.startswith('sqlite') else {})
class Base(DeclarativeBase): pass
class User(Base):
 __tablename__='users'
 id:Mapped[int]=mapped_column(primary_key=True)
 name:Mapped[str]=mapped_column(String(80))
 email:Mapped[str]=mapped_column(String(254),unique=True)
 password:Mapped[str]=mapped_column(String(256))
 role:Mapped[str]=mapped_column(String(20),default='customer')
class Ticket(Base):
 __tablename__='tickets'
 id:Mapped[int]=mapped_column(primary_key=True)
 title:Mapped[str]=mapped_column(String(150))
 description:Mapped[str]=mapped_column(Text)
 priority:Mapped[str]=mapped_column(String(20),default='Medium')
 status:Mapped[str]=mapped_column(String(30),default='Open')
 owner_id:Mapped[int]=mapped_column(ForeignKey('users.id'))
 assignee_id:Mapped[int|None]=mapped_column(ForeignKey('users.id'),nullable=True)
 created:Mapped[str]=mapped_column(String(40),default=lambda:datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))
class Comment(Base):
 __tablename__='comments'
 id:Mapped[int]=mapped_column(primary_key=True)
 ticket_id:Mapped[int]=mapped_column(ForeignKey('tickets.id'))
 user_id:Mapped[int]=mapped_column(ForeignKey('users.id'))
 body:Mapped[str]=mapped_column(Text)
 created:Mapped[str]=mapped_column(String(40),default=lambda:datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))
def hash_password(p):
 salt=secrets.token_hex(16)
 return salt+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt.encode(),600000).hex()
def verify(p,stored):
 salt,digest=stored.split(':')
 return hmac.compare_digest(digest,hashlib.pbkdf2_hmac('sha256',p.encode(),salt.encode(),600000).hex())
@asynccontextmanager
async def lifespan(app):
 Base.metadata.create_all(engine)
 yield
app=FastAPI(title='ResolveDesk',version='1.0.0',lifespan=lifespan)
app.add_middleware(SessionMiddleware,secret_key=KEY,max_age=28800,same_site='lax',https_only=os.getenv('COOKIE_SECURE','false').lower()=='true')
ROOT=Path(__file__).parent
templates=Jinja2Templates(directory=str(ROOT/'templates'))
app.mount('/static',StaticFiles(directory=str(ROOT/'static')),name='static')
STATUSES=['Open','In Progress','Resolved']; PRIORITIES=['Low','Medium','High','Urgent']
def current(r,db):
 u=db.get(User,r.session.get('uid',0))
 if not u: raise HTTPException(401,'Please sign in.')
 return u
def csrf(r,value):
 if not value or not hmac.compare_digest(value,r.session.get('csrf','')): raise HTTPException(403,'Invalid form token. Reload the page and retry.')
def view(r,name,**kw):
 r.session.setdefault('csrf',secrets.token_urlsafe(32))
 return templates.TemplateResponse(request=r,name=name,context=dict(csrf=r.session['csrf'],statuses=STATUSES,priorities=PRIORITIES,**kw))
def go(url): return RedirectResponse(url,status_code=303)
def accessible(db,u,id):
 t=db.get(Ticket,id)
 if not t: raise HTTPException(404,'Ticket not found')
 if u.role=='customer' and t.owner_id!=u.id: raise HTTPException(403,'Access denied')
 return t
@app.middleware('http')
async def headers(r,call_next):
 response=await call_next(r)
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Referrer-Policy']='same-origin'
 response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'"
 if not r.url.path.startswith('/static'): response.headers['Cache-Control']='no-store'
 return response
@app.get('/health/live')
def live(): return {'status':'ok'}
@app.get('/health/ready')
def ready():
 try:
  with engine.connect() as c: c.execute(text('SELECT 1'))
 except Exception: raise HTTPException(503,'Database unavailable')
 return {'status':'ready'}
@app.get('/login')
def login_page(r:Request): return view(r,'auth.html',register=False,error=None)
@app.get('/register')
def register_page(r:Request): return view(r,'auth.html',register=True,error=None)
@app.post('/register')
def register(r:Request,name:str=Form(...),email:str=Form(...),password:str=Form(...),token:str=Form(...)):
 csrf(r,token); email=email.strip().lower(); name=name.strip()
 if not 2<=len(name)<=80 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email) or len(email)>254 or not 10<=len(password)<=128:
  return view(r,'auth.html',register=True,error='Use a valid name/email and a password of 10–128 characters.')
 with Session(engine) as db:
  u=User(name=name,email=email,password=hash_password(password),role='customer'); db.add(u)
  try: db.commit()
  except IntegrityError:
   db.rollback(); return view(r,'auth.html',register=True,error='This email is already registered.')
 return go('/login')
@app.post('/login')
def login(r:Request,email:str=Form(...),password:str=Form(...),token:str=Form(...)):
 csrf(r,token)
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.email==email.strip().lower()))
  if not u or not verify(password,u.password): return view(r,'auth.html',register=False,error='Email or password is incorrect.')
  r.session.clear(); r.session['uid']=u.id; r.session['csrf']=secrets.token_urlsafe(32)
 return go('/')
@app.post('/logout')
def logout(r:Request,token:str=Form(...)):
 csrf(r,token); r.session.clear(); return go('/login')
@app.get('/')
def dashboard(r:Request,q:str='',status:str='',priority:str='',page:int=1):
 if not r.session.get('uid'): return go('/login')
 with Session(engine) as db:
  u=current(r,db); base=select(Ticket)
  if u.role=='customer': base=base.where(Ticket.owner_id==u.id)
  counts={s:db.scalar(select(func.count()).select_from(base.where(Ticket.status==s).subquery())) for s in STATUSES}
  if q: base=base.where(or_(Ticket.title.ilike('%'+q[:100]+'%'),Ticket.description.ilike('%'+q[:100]+'%')))
  if status in STATUSES: base=base.where(Ticket.status==status)
  if priority in PRIORITIES: base=base.where(Ticket.priority==priority)
  total=db.scalar(select(func.count()).select_from(base.subquery())); page=max(1,min(page,max(1,(total+9)//10)))
  tickets=db.scalars(base.order_by(Ticket.id.desc()).offset((page-1)*10).limit(10)).all()
  return view(r,'dashboard.html',user=u,tickets=tickets,counts=counts,q=q,status=status,priority=priority,page=page,total=total)
@app.get('/tickets/new')
def new_page(r:Request):
 with Session(engine) as db: return view(r,'new.html',user=current(r,db))
@app.post('/tickets')
def create_ticket(r:Request,title:str=Form(...),description:str=Form(...),priority:str=Form(...),token:str=Form(...)):
 csrf(r,token)
 if not 3<=len(title.strip())<=150 or not 10<=len(description.strip())<=10000 or priority not in PRIORITIES: raise HTTPException(422,'Check title, description and priority.')
 with Session(engine) as db:
  u=current(r,db); t=Ticket(title=title.strip(),description=description.strip(),priority=priority,owner_id=u.id); db.add(t); db.commit(); id=t.id
 return go(f'/tickets/{id}')
@app.get('/tickets/{id}')
def detail(r:Request,id:int):
 with Session(engine) as db:
  u=current(r,db); t=accessible(db,u,id)
  comments=db.execute(select(Comment,User.name).join(User,Comment.user_id==User.id).where(Comment.ticket_id==id).order_by(Comment.id)).all()
  staff=db.scalars(select(User).where(User.role.in_(['agent','admin']))).all()
  owner=db.get(User,t.owner_id)
  assignee=db.get(User,t.assignee_id) if t.assignee_id else None
  return view(r,'detail.html',user=u,t=t,comments=comments,staff=staff,owner=owner,assignee=assignee)
@app.post('/tickets/{id}/comment')
def comment(r:Request,id:int,body:str=Form(...),token:str=Form(...)):
 csrf(r,token)
 if not 1<=len(body.strip())<=5000: raise HTTPException(422,'Comment must be 1–5000 characters.')
 with Session(engine) as db:
  u=current(r,db); accessible(db,u,id); db.add(Comment(ticket_id=id,user_id=u.id,body=body.strip())); db.commit()
 return go(f'/tickets/{id}')
@app.post('/tickets/{id}/update')
def update(r:Request,id:int,status:str=Form(...),priority:str=Form(...),assignee_id:str=Form(''),token:str=Form(...)):
 csrf(r,token)
 with Session(engine) as db:
  u=current(r,db); t=accessible(db,u,id)
  if u.role not in ['agent','admin']: raise HTTPException(403,'Staff access required')
  if status not in STATUSES or priority not in PRIORITIES: raise HTTPException(422,'Invalid status or priority')
  if u.role=='admin':
   if assignee_id:
    if not assignee_id.isdigit(): raise HTTPException(422,'Invalid assignee')
    a=db.get(User,int(assignee_id))
    if not a or a.role not in ['agent','admin']: raise HTTPException(422,'Invalid assignee')
    t.assignee_id=a.id
   else: t.assignee_id=None
  t.status=status; t.priority=priority; db.commit()
 return go(f'/tickets/{id}')
@app.get('/admin')
def admin(r:Request):
 with Session(engine) as db:
  u=current(r,db)
  if u.role!='admin': raise HTTPException(403,'Admin access required')
  return view(r,'admin.html',user=u,users=db.scalars(select(User).order_by(User.id)).all())
@app.post('/admin/users/{id}/role')
def role(r:Request,id:int,role:str=Form(...),token:str=Form(...)):
 csrf(r,token)
 with Session(engine) as db:
  u=current(r,db)
  if u.role!='admin': raise HTTPException(403,'Admin access required')
  if id==u.id: raise HTTPException(422,'You cannot change your own role.')
  if role not in ['customer','agent','admin']: raise HTTPException(422,'Invalid role')
  target=db.get(User,id)
  if not target: raise HTTPException(404,'User not found')
  target.role=role; db.commit()
 return go('/admin')
