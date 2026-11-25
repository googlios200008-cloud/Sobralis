// Mutates the migration ledger: ONLY an empty, dedicated disposable test database.
import assert from 'node:assert/strict';import {spawn,type ChildProcess} from 'node:child_process';import {createServer} from 'node:net';import pg from 'pg';
if(process.env.DB_NAME!=='sobralis_schema_readiness_test'||process.env.RUN_SCHEMA_READINESS_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires explicit disposable schema-readiness test database');
const admin=new pg.Pool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT),database:process.env.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
async function port(){const s=createServer();await new Promise<void>((resolve,reject)=>s.once('error',reject).listen(0,'127.0.0.1',resolve));const n=(s.address() as {port:number}).port;await new Promise<void>(r=>s.close(()=>r()));return n}
function child(port:number,mode:string|undefined='test'){return spawn(process.execPath,['dist/server.js'],{cwd:process.cwd(),env:{...process.env,NODE_ENV:mode,SAFE_DIAGNOSTICS:'true',HOST:'127.0.0.1',PORT:String(port),PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'schema-readiness-secret-'.repeat(3)},stdio:['ignore','pipe','pipe']})}
function exited(p:ChildProcess){return new Promise<number|null>((resolve,reject)=>{p.once('error',reject);p.once('exit',resolve)})}
async function started(p:ChildProcess){await new Promise<void>((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('API startup timed out')),10000);p.stdout!.on('data',chunk=>{if(String(chunk).includes('API started')){clearTimeout(timer);resolve()}});p.once('exit',()=>{clearTimeout(timer);reject(Error('API exited before readiness'))});p.once('error',reject)})}
let live:ChildProcess|undefined,done:Promise<number|null>|undefined;
try{
 const fingerprint=(await admin.query<{checksum:string}>("SELECT checksum FROM schema_migrations WHERE name='0031_runtime_schema_check.sql'")).rows[0]!.checksum;
 const withoutMode=child(await port(),'');assert.equal(await exited(withoutMode),1);
 const p=await port();live=child(p);done=exited(live);await started(live);
 assert.equal((await fetch(`http://127.0.0.1:${p}/ready`)).status,200);
 try{
  await admin.query("UPDATE schema_migrations SET checksum='modified-secret-test' WHERE name='0031_runtime_schema_check.sql'");
  const health=await fetch(`http://127.0.0.1:${p}/health`),ready=await fetch(`http://127.0.0.1:${p}/ready`);assert.equal(health.status,200);assert.equal(ready.status,503);assert.doesNotMatch(await ready.text(),/modified-secret-test|schema_migrations/);
  const diagnostic=new Promise<string>((resolve,reject)=>{const timer=setTimeout(()=>reject(Error('diagnostic timed out')),5000);live!.stdout!.on('data',function handler(chunk){const line=String(chunk);if(line.includes('\"event\":\"server_error\"')){clearTimeout(timer);live!.stdout!.off('data',handler);resolve(line)}})});
  const apiBlocked=await fetch(`http://127.0.0.1:${p}/api/auth/registration-config?token=secret-test-query`,{headers:{'x-request-id':'secret-spoofed-id'}});assert.equal(apiBlocked.status,503);assert.doesNotMatch(await apiBlocked.text(),/modified-secret-test|schema_migrations/);const requestId=apiBlocked.headers.get('x-request-id');assert.match(requestId??'',/^[0-9a-f-]{36}$/i);const line=await diagnostic;assert.doesNotMatch(line,/modified-secret-test|schema_migrations|secret-test-query|secret-spoofed-id/);const entry=JSON.parse(line.trim());assert.equal(entry.requestId,requestId);assert.equal(entry.category,'auth');assert.equal(entry.status,503);

  const bad=child(await port()),badDone=exited(bad);let log='';bad.stderr!.on('data',x=>{log+=String(x)});assert.equal(await badDone,1);assert.match(log,/API startup failed/);assert.doesNotMatch(log,/modified-secret-test|schema_migrations|password/i);
 }finally{await admin.query("UPDATE schema_migrations SET checksum=$1 WHERE name='0031_runtime_schema_check.sql'",[fingerprint])}
 assert.equal((await fetch(`http://127.0.0.1:${p}/ready`)).status,200);assert.equal((await fetch(`http://127.0.0.1:${p}/api/auth/registration-config`)).status,200);
 const runtime=new pg.Pool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT),database:process.env.DB_NAME,user:process.env.DB_USER,password:process.env.DB_PASSWORD});
 try{await assert.rejects(()=>runtime.query('SELECT * FROM schema_migrations'));const expected=(await admin.query('SELECT count(*)::int n FROM schema_migrations')).rows[0].n;assert.equal((await runtime.query('SELECT * FROM public.runtime_schema_state()')).rows.length,expected)}finally{await runtime.end()}
 console.log('Schema readiness: explicit mode, startup, incompatible checksum, no sensitive details, recovery and restricted runtime access passed');
}finally{if(live){live.kill('SIGTERM');await done}await admin.end()}
