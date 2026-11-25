// Opt-in synthetic accounts only, on the disposable auth test database.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';import {hashToken} from '../src/security.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Disposable auth database and explicit opt-in required');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5),PASSWORD_RESET_ENABLED:'true'},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
let failMail=false;const delivered:{to:string;link:string}[]=[],mailer={async sendVerification(){},async sendPasswordReset(to:string,link:string){if(failMail)throw Error('synthetic delivery failure');delivered.push({to,link})}};
const app=await createApp({checkDatabase:async()=>{},security:{pool,config:sec,mailer}}),origin={origin:'https://test.invalid'},suffix=randomBytes(8).toString('hex');
const emails=[`recovery-live-${suffix}@example.test`,`recovery-pending-${suffix}@example.test`],password='Test-old-password-2026',newPassword='Test-new-password-2026';let ids:string[]=[],group:string|null=null;
async function call(method:'GET'|'POST',url:string,remote:string,payload?:unknown,cookie?:string){return app.inject({method,url,remoteAddress:remote,headers:{...origin,...cookie?{cookie}:{}},...(payload===undefined?{}:{payload})})}
function cookie(r:{headers:Record<string,unknown>}){let h=r.headers['set-cookie'];if(Array.isArray(h))h=h[0];return String(h).split(';')[0]!}
try{
 const passHash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 ids=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES($1,'Synthetic',$3,now()),($2,'Pending',$3,NULL) RETURNING id",[...emails,passHash])).rows.map(x=>x.id);const [id]=ids;
 group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Synthetic recovery',$1) RETURNING id",[id])).rows[0]!.id;await admin.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[group,id]);await admin.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2033-01-01','free')",[group,id]);
 const config=await call('GET','/api/auth/recovery-config','192.0.2.1');assert.deepEqual(config.json(),{enabled:true});assert.equal(config.headers['cache-control'],'no-store');
 const l1=await call('POST','/api/auth/login','192.0.2.2',{email:emails[0],password}),l2=await call('POST','/api/auth/login','192.0.2.3',{email:emails[0],password});assert.equal(l1.statusCode,200);assert.equal(l2.statusCode,200);const c1=cookie(l1),c2=cookie(l2);
 assert.equal((await app.inject({method:'POST',url:'/api/auth/request-password-reset',headers:{origin:'https://evil.invalid'},payload:{email:emails[0]}})).statusCode,403);
 const generic=await call('POST','/api/auth/request-password-reset','192.0.2.4',{email:`absent-${suffix}@example.test`});const pending=await call('POST','/api/auth/request-password-reset','192.0.2.5',{email:emails[1]});const real=await call('POST','/api/auth/request-password-reset','192.0.2.6',{email:emails[0]});assert.equal(generic.statusCode,202);assert.equal(pending.statusCode,202);assert.equal(real.statusCode,202);assert.deepEqual(generic.json(),real.json());assert.deepEqual(pending.json(),real.json());assert.equal(delivered.length,1);
 assert.equal((await call('POST','/api/auth/request-password-reset','192.0.2.7',{email:emails[0]})).statusCode,202);assert.equal(delivered.length,1);
 const url=new URL(delivered[0]!.link);assert.equal(url.pathname,'/reset-password');const raw=url.hash.slice(1);assert.match(raw,/^[A-Za-z0-9_-]{43}$/);
 const rec=(await admin.query<{token_hash:string}>('SELECT token_hash FROM password_reset_tokens WHERE user_id=$1',[id])).rows[0]!;assert.equal(rec.token_hash,hashToken(raw));assert.notEqual(rec.token_hash,raw);await assert.rejects(()=>pool.query('SELECT * FROM password_reset_tokens'));
 assert.equal((await call('POST','/api/auth/reset-password','192.0.2.8',{token:raw,password:'short'})).statusCode,400);
 const resets=await Promise.all([call('POST','/api/auth/reset-password','192.0.2.9',{token:raw,password:newPassword}),call('POST','/api/auth/reset-password','192.0.2.10',{token:raw,password:newPassword})]);assert.deepEqual(resets.map(x=>x.statusCode).sort(),[200,400]);
 assert.equal((await call('GET','/api/auth/me','192.0.2.11',undefined,c1)).statusCode,401);assert.equal((await call('GET','/api/auth/me','192.0.2.12',undefined,c2)).statusCode,401);
 assert.equal((await call('POST','/api/auth/login','192.0.2.13',{email:emails[0],password})).statusCode,401);assert.equal((await call('POST','/api/auth/login','192.0.2.14',{email:emails[0],password:newPassword})).statusCode,200);
 assert.equal((await call('POST','/api/auth/reset-password','192.0.2.15',{token:raw,password})).statusCode,400);
 assert.equal((await admin.query('SELECT status FROM schedule_entries WHERE community_id=$1 AND user_id=$2',[group,id])).rows[0].status,'free');
 // Loss and restoration of verified status may never revive an old reset link.
 await admin.query("UPDATE password_reset_tokens SET created_at=now()-interval '11 minutes' WHERE user_id=$1",[id]);await call('POST','/api/auth/request-password-reset','192.0.2.16',{email:emails[0]});const oldLink=new URL(delivered.at(-1)!.link).hash.slice(1);
 await admin.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[id]);await admin.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[id]);
 assert.equal((await call('POST','/api/auth/reset-password','192.0.2.17',{token:oldLink,password})).statusCode,400);
 // Email changes, including changing back, invalidate outstanding links.
 await admin.query("UPDATE password_reset_tokens SET created_at=now()-interval '11 minutes' WHERE user_id=$1",[id]);await call('POST','/api/auth/request-password-reset','192.0.2.18',{email:emails[0]});const emailLink=new URL(delivered.at(-1)!.link).hash.slice(1);
 await admin.query('UPDATE users SET email=$2 WHERE id=$1',[id,`changed-${suffix}@example.test`]);await admin.query('UPDATE users SET email=$2 WHERE id=$1',[id,emails[0]]);
 assert.equal((await call('POST','/api/auth/reset-password','192.0.2.19',{token:emailLink,password})).statusCode,400);
 // An expired token does not change credentials.
 await admin.query("UPDATE password_reset_tokens SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE user_id=$1",[id]);await call('POST','/api/auth/request-password-reset','192.0.2.20',{email:emails[0]});const exp=new URL(delivered.at(-1)!.link).hash.slice(1);
 await admin.query("UPDATE password_reset_tokens SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE token_hash=$1",[hashToken(exp)]);assert.equal((await call('POST','/api/auth/reset-password','192.0.2.21',{token:exp,password})).statusCode,400);
 // The same generic response is returned on a failed transport; the verified
 // account stays usable, and a persistent cooldown prevents an email flood.
 await admin.query("UPDATE password_reset_tokens SET created_at=now()-interval '2 hours' WHERE user_id=$1",[id]);
 const count=delivered.length;failMail=true;const originalError=console.error;console.error=()=>{};
 try{const failed=await call('POST','/api/auth/request-password-reset','192.0.2.22',{email:emails[0]});assert.equal(failed.statusCode,202);assert.deepEqual(failed.json(),generic.json())}finally{console.error=originalError;failMail=false}
 await call('POST','/api/auth/request-password-reset','192.0.2.23',{email:emails[0]});assert.equal(delivered.length,count);
 assert.equal((await call('POST','/api/auth/login','192.0.2.24',{email:emails[0],password:newPassword})).statusCode,200);
 for(let i=0;i<3;i++)assert.equal((await call('POST','/api/auth/request-password-reset','192.0.2.25',{email:`missing-${suffix}@example.test`})).statusCode,202);
 assert.equal((await call('POST','/api/auth/request-password-reset','192.0.2.25',{email:`missing-${suffix}@example.test`})).statusCode,429);
 // An Argon2 verification already completed against the old hash cannot
 // create a session after an in-flight password change commits.
 const before=(await admin.query<{password_hash:string;recovery_generation:string}>('SELECT password_hash,recovery_generation FROM users WHERE id=$1',[id])).rows[0]!;const next=await argon2.hash('Replacement-password-2026',{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});const hold=await admin.connect();let committed=false;try{
  await hold.query('BEGIN');await hold.query('UPDATE users SET password_hash=$2 WHERE id=$1',[id,next]);let settled=false;
  const session=pool.query<{issued:boolean}>('SELECT public.issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[id,emails[0],before.recovery_generation,before.password_hash,hashToken(randomBytes(32).toString('base64url'))]).then(r=>{settled=true;return r});
  await new Promise(r=>setTimeout(r,120));assert.equal(settled,false);await hold.query('COMMIT');committed=true;assert.equal((await session).rows[0]!.issued,false);
 }finally{if(!committed)await hold.query('ROLLBACK');hold.release()}
 // Password still matching is insufficient if the account verification changed and came back.
 const snapshot=(await admin.query<{password_hash:string;recovery_generation:string}>('SELECT password_hash,recovery_generation FROM users WHERE id=$1',[id])).rows[0]!;
 await admin.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[id]);await admin.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[id]);
 assert.equal((await pool.query<{issued:boolean}>('SELECT public.issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[id,emails[0],snapshot.recovery_generation,snapshot.password_hash,hashToken(randomBytes(32).toString('base64url'))])).rows[0]!.issued,false);
 await assert.rejects(()=>pool.query("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",[id,'f'.repeat(64)]));
 console.log('Recovery: generic responses, single-use tokens, sessions, retained data, account generation and login race passed');
}finally{await app.close();await pool.end();const c=await admin.connect();try{await c.query('BEGIN');if(group){await c.query('DELETE FROM schedule_entries WHERE community_id=$1',[group]);await c.query('DELETE FROM community_members WHERE community_id=$1',[group]);await c.query("DELETE FROM communities WHERE id=$1 AND name='Synthetic recovery'",[group])}await c.query('DELETE FROM password_reset_tokens WHERE user_id=ANY($1::uuid[])',[ids]);await c.query('DELETE FROM user_sessions WHERE user_id=ANY($1::uuid[])',[ids]);await c.query('DELETE FROM users WHERE id=ANY($1::uuid[]) AND email=ANY($2::text[])',[ids,emails]);await c.query('COMMIT')}catch(e){await c.query('ROLLBACK');throw e}finally{c.release();await admin.end()}}
