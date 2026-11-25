#!/usr/bin/env python3
"""Opt-in: create synthetic DBs and temporary keys; never point to production."""
import hashlib
import os
import pathlib
import subprocess
import tempfile

root=pathlib.Path(__file__).resolve().parent.parent
if os.environ.get('ALLOW_DISPOSABLE_DATABASE')!='yes':raise SystemExit('Requires explicit disposable database opt-in')
for key in ('DB_HOST','DB_PORT','TEST_ADMIN_PASSWORD','TEST_MIGRATOR_PASSWORD'):
 if not os.environ.get(key):raise SystemExit('Missing '+key)
env=os.environ.copy();env.update(PGHOST=env['DB_HOST'],PGPORT=env['DB_PORT'],PGUSER='sobralis_admin',PGPASSWORD=env['TEST_ADMIN_PASSWORD'])
source='sobralis_encrypted_backup_test';restore='sobralis_backup_restore_test';created=[]
def run(args,*,e=env,**kw):return subprocess.run(args,env=e,check=True,**kw)
def scalar(db,sql):return run(['psql','-X','-v','ON_ERROR_STOP=1','-At','-d',db,'-c',sql],capture_output=True,text=True).stdout.strip()
def digest(db):
 names=scalar(db,"select tablename from pg_tables where schemaname='public' order by tablename").splitlines();result={}
 for name in names:
  assert name.replace('_','').isalnum();expr='to_jsonb(t)';result[name]=scalar(db,'select count(*)::text||\':\'||md5(coalesce(string_agg('+expr+"::text,E'\\n' order by "+expr+'::text),\'\')) from public."'+name+'" t')
 return result
try:
 for db in (source,restore):
  run(['createdb','-O','sobralis_migrator',db]);created.append(db)
  run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-d',db,'-c',f'REVOKE ALL ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO sobralis_runtime, sobralis_migrator; GRANT USAGE ON SCHEMA public TO sobralis_runtime;'])
 app=env.copy();app.update(DB_NAME=source,DB_USER='sobralis_migrator',DB_PASSWORD=env['TEST_MIGRATOR_PASSWORD'],NODE_ENV='test')
 run(['npm','run','migrate'],cwd=root/'backend',e=app)
 run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-d',source,'-c',"INSERT INTO users(email,display_name,email_verified_at) VALUES('backup@example.test','SYNTHETIC_PRIVATE_MARKER_684937',now())"])
 with tempfile.TemporaryDirectory(prefix='sobralis-backup-test-') as tmp:
  tmp=pathlib.Path(tmp);home=tmp/'keys';home.mkdir(mode=0o700);out=tmp/'encrypted';out.mkdir(mode=0o700);gpg=env.copy();gpg['GNUPGHOME']=str(home)
  run(['gpg','--no-options','--batch','--no-tty','--pinentry-mode','loopback','--passphrase','','--quick-gen-key','Synthetic Backup Test <backup@example.test>','rsa2048','encrypt','1d'],e=gpg,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   keys=run(['gpg','--no-options','--batch','--with-colons','--list-keys'],e=gpg,capture_output=True,text=True).stdout.splitlines();fingerprint=next(x.split(':')[9] for x in keys if x.startswith('fpr:'))
   backup=out/'synthetic.dump.gpg';tool=[str(root/'scripts/encrypted-pg-backup.py'),'--recipient',fingerprint,'--output',str(backup)];backup_env=gpg.copy();backup_env['PGDATABASE']=source
   run(tool,e=backup_env,capture_output=True,text=True);assert backup.stat().st_mode&0o777==0o600;cipher=backup.read_bytes();assert b'SYNTHETIC_PRIVATE_MARKER_684937' not in cipher;before=hashlib.sha256(cipher).hexdigest()
   again=subprocess.run(tool,env=backup_env,capture_output=True,text=True);assert again.returncode!=0 and hashlib.sha256(backup.read_bytes()).hexdigest()==before
   missing=out/'missing.dump.gpg';bad_env=backup_env.copy();bad_env['PGDATABASE']='sobralis_backup_missing_test';r=subprocess.run([str(root/'scripts/encrypted-pg-backup.py'),'--recipient',fingerprint,'--output',str(missing)],env=bad_env,capture_output=True,text=True);assert r.returncode!=0 and not missing.exists();assert not list(out.glob('.sobralis-encrypted-*'))
   public=tmp/'public';public.mkdir(mode=0o755);unsafe=subprocess.run([str(root/'scripts/encrypted-pg-backup.py'),'--recipient',fingerprint,'--output',str(public/'x.gpg')],env=backup_env,capture_output=True,text=True);assert unsafe.returncode!=0 and not (public/'x.gpg').exists()
   empty_home=tmp/'other-keys';empty_home.mkdir(mode=0o700);other_env=gpg.copy();other_env['GNUPGHOME']=str(empty_home);wrong=subprocess.run(['gpg','--no-options','--batch','--decrypt',str(backup)],env=other_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);assert wrong.returncode!=0
   invalid=subprocess.run([str(root/'scripts/encrypted-pg-backup.py'),'--recipient','1234','--output',str(out/'invalid.gpg')],env=backup_env,capture_output=True,text=True);assert invalid.returncode!=0 and not (out/'invalid.gpg').exists()
   tampered=out/'tampered.gpg';tampered.write_bytes(cipher[:-32]+bytes([cipher[-32]^1])+cipher[-31:]);bad=subprocess.run(['gpg','--no-options','--batch','--decrypt',str(tampered)],env=gpg,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);assert bad.returncode!=0
   decrypt=subprocess.Popen(['gpg','--no-options','--batch','--decrypt',str(backup)],env=gpg,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
   restored=subprocess.Popen(['pg_restore','--exit-on-error','-d',restore],env=env,stdin=decrypt.stdout,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);decrypt.stdout.close();errors=restored.communicate()[1];assert restored.returncode==0,errors.decode();assert decrypt.wait()==0
   original=digest(source);copy=digest(restore);assert original==copy;assert len(original)>30
   print('Encrypted backup: no plaintext file, no overwrite, integrity failure, dump failure and full isolated restore verified for',len(original),'tables')
  finally:subprocess.run(['gpgconf','--kill','gpg-agent'],env=gpg,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
finally:
 for db in reversed(created):run(['dropdb',db])
