#!/usr/bin/env python3
"""Create and remove only a new named synthetic database; never use production."""
import os,pathlib,subprocess
root=pathlib.Path(__file__).resolve().parent.parent
if os.environ.get('ALLOW_DISPOSABLE_DATABASE')!='yes':raise SystemExit('Requires explicit disposable database opt-in')
for key in ('DB_HOST','DB_PORT','TEST_ADMIN_PASSWORD','TEST_MIGRATOR_PASSWORD','TEST_RUNTIME_PASSWORD'):
 if not os.environ.get(key):raise SystemExit('Missing '+key)
name='sobralis_sessions_test';env=os.environ.copy();env.update(PGHOST=env['DB_HOST'],PGPORT=env['DB_PORT'],PGUSER='sobralis_admin',PGPASSWORD=env['TEST_ADMIN_PASSWORD'])
def run(args,**kw):return subprocess.run(args,env=kw.pop('env',env),check=True,**kw)
# Fail instead of overwriting an existing database.
run(['createdb','-O','sobralis_migrator',name]);created=True
try:
 run(['psql','-X','-q','-v','ON_ERROR_STOP=1','-d',name,'-c',f'REVOKE ALL ON DATABASE {name} FROM PUBLIC; GRANT CONNECT ON DATABASE {name} TO sobralis_runtime, sobralis_migrator; GRANT USAGE ON SCHEMA public TO sobralis_runtime;'])
 app=env.copy();app.update(DB_NAME=name,DB_USER='sobralis_migrator',DB_PASSWORD=env['TEST_MIGRATOR_PASSWORD'],NODE_ENV='test')
 run(['npm','run','migrate'],cwd=root/'backend',env=app)
 app.update(DB_USER='sobralis_runtime',DB_PASSWORD=env['TEST_RUNTIME_PASSWORD'],RUN_SESSION_TEST='yes')
 run(['npx','tsx','tests/live-revoke-other-sessions.ts'],cwd=root/'backend',env=app)
finally:
 if created:run(['dropdb',name])
