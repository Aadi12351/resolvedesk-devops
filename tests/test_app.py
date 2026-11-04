import os,re,tempfile
os.environ['SECRET_KEY']='test-only-secret-not-for-deployment-123456'
os.environ['DATABASE_URL']='sqlite:///'+tempfile.mktemp(suffix='.db')
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.main import app,Base,engine,User,Ticket,hash_password
@pytest.fixture(autouse=True)
def database():
 Base.metadata.drop_all(engine); Base.metadata.create_all(engine)
 with Session(engine) as db:
  db.add(User(name='Admin',email='admin@example.com',password=hash_password('AdminPass123!'),role='admin')); db.commit()
 yield
@pytest.fixture
def client():
 with TestClient(app) as c: yield c
def token(c,path='/login'):
 return re.search('name="token" value="([^"]+)"',c.get(path).text).group(1)
def register(c,email='user@example.com'):
 return c.post('/register',data={'name':'Test User','email':email,'password':'Password123!','token':token(c,'/register')})
def login(c,email='user@example.com',password='Password123!'):
 return c.post('/login',data={'email':email,'password':password,'token':token(c)})
def ticket(c,title='Printer issue'):
 return c.post('/tickets',data={'title':title,'description':'Printer does not respond to any requests.','priority':'High','token':token(c,'/tickets/new')})
def test_health(client):
 assert client.get('/health/live').json()=={'status':'ok'}
 assert client.get('/health/ready').status_code==200
def test_auth_and_duplicate(client):
 assert 'Sign in' in register(client).text
 assert 'already registered' in register(client).text
 assert 'incorrect' in login(client,password='WrongPassword').text
 assert 'Ticket inbox' in login(client).text
def test_csrf(client):
 assert client.post('/register',data={'name':'Test','email':'t@example.com','password':'Password123!','token':'bad'}).status_code==403
def test_registration_validation(client):
 assert 'valid name/email' in client.post('/register',data={'name':'A','email':'bad','password':'short','token':token(client,'/register')}).text
def test_ticket_workflow(client):
 register(client);login(client);r=ticket(client)
 assert r.status_code==200 and 'Printer issue' in r.text
 assert client.post('/tickets/1/comment',data={'body':'Please help','token':token(client,'/tickets/1')}).status_code==200
 assert 'Please help' in client.get('/tickets/1').text
 assert client.post('/tickets/1/update',data={'status':'Resolved','priority':'High','token':token(client,'/tickets/1')}).status_code==403
 assert client.get('/admin').status_code==403
 assert 'Printer issue' in client.get('/?q=Printer&priority=High').text
 assert 'No tickets here' in client.get('/?q=absent').text
def test_owner_isolation(client):
 register(client);login(client);ticket(client)
 with TestClient(app) as other:
  register(other,'other@example.com');login(other,'other@example.com')
  assert other.get('/tickets/1').status_code==403
  assert 'Printer issue' not in other.get('/').text
  assert other.post('/tickets/1/comment',data={'body':'intrusion','token':token(other,'/')}).status_code==403
def test_admin_assignment_and_roles(client):
 register(client);login(client);ticket(client)
 with TestClient(app) as admin:
  login(admin,'admin@example.com','AdminPass123!')
  assert admin.get('/admin').status_code==200
  assert admin.post('/admin/users/2/role',data={'role':'agent','token':token(admin,'/admin')}).status_code==200
  assert admin.post('/tickets/1/update',data={'status':'In Progress','priority':'Urgent','assignee_id':'2','token':token(admin,'/tickets/1')}).status_code==200
  assert 'Test User' in admin.get('/tickets/1').text
  assert admin.post('/admin/users/1/role',data={'role':'customer','token':token(admin,'/admin')}).status_code==422
  assert admin.post('/tickets/1/update',data={'status':'Fake','priority':'Urgent','token':token(admin,'/tickets/1')}).status_code==422
  assert admin.post('/tickets/1/update',data={'status':'Resolved','priority':'Low','assignee_id':'999','token':token(admin,'/tickets/1')}).status_code==422
 # Existing customer session resolves role from DB on every request
 assert client.post('/tickets/1/update',data={'status':'Resolved','priority':'Medium','token':token(client,'/tickets/1')}).status_code==200
def test_escape_logout_and_missing(client):
 register(client);login(client);ticket(client,'<script>alert(1)</script>')
 assert '&lt;script&gt;' in client.get('/tickets/1').text
 assert '<script>alert(1)</script>' not in client.get('/tickets/1').text
 assert client.get('/tickets/999').status_code==404
 client.post('/logout',data={'token':token(client,'/')})
 assert client.get('/tickets/1').status_code==401
def test_pagination(client):
 register(client);login(client)
 with Session(engine) as db:
  for n in range(12): db.add(Ticket(title=f'Ticket {n}',description='Test description',owner_id=2,priority='Medium'))
  db.commit()
 assert 'Next' in client.get('/').text
 assert 'Page 2' in client.get('/?page=2').text
