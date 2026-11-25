// Synthetic data only. The runner creates and removes the named disposable DB.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
import argon2 from 'argon2';
import {createApp} from '../src/app.js';
import {readConfig,readSecurityConfig} from '../src/config.js';
import {createPool} from '../src/db.js';
import {hashToken} from '../src/security.js';
if(process.env.DB_NAME!=='sobralis_sessions_test'||process.env.RUN_SESSION_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires explicitly opted-in disposable sessions database');
const cfg=readConfig(process.env),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD}),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),app=await createApp({checkDatabase:async()=>{},security:{pool,config:sec}});
const pass='Synthetic-only-session-password-2026!',otherPass='Synthetic-other-password-2026!',origin='https://test.invalid';
type Session={cookie:string;csrf:string};
async function login(email:string,password:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',remoteAddress:remote,headers:{origin},payload:{email,password}});assert.equal(r.statusCode,200);const header=r.headers['set-cookie'];const raw=Array.isArray(header)?header[0]:header;assert.equal(typeof raw,'string');return {cookie:String(raw).split(';')[0]!,csrf:r.json().csrfToken}}
async function me(s:Session){return app.inject({method:'GET',url:'/api/auth/me',headers:{cookie:s.cookie}})}
async function revoke(s:Session,password:string,remote:string,extra:Record<string,string>={}){return app.inject({method:'POST',url:'/api/auth/revoke-other-sessions',remoteAddress:remote,headers:{origin,cookie:s.cookie,'x-csrf-token':s.csrf,...extra},payload:{password}})}
try{
 const hash=await argon2.hash(pass,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1}),hash2=await argon2.hash(otherPass,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const rows=await admin.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('session-a@example.test','A',$1,now()),('session-b@example.test','B',$2,now()) RETURNING id",[hash,hash2]);const [a,b]=rows.rows.map(x=>x.id);
 const [a1,a2,a3,bs]=await Promise.all([login('session-a@example.test',pass,'192.0.2.1'),login('session-a@example.test',pass,'192.0.2.2'),login('session-a@example.test',pass,'192.0.2.3'),login('session-b@example.test',otherPass,'192.0.2.4')]);
 assert.equal((await revoke(a1!,'wrong-password','192.0.2.5')).statusCode,401);assert.equal((await me(a2!)).statusCode,200);
 assert.equal((await revoke(a1!,pass,'192.0.2.6',{origin:'https://evil.invalid'})).statusCode,403);assert.equal((await revoke(a1!,pass,'192.0.2.7',{'x-csrf-token':'bad'})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/api/auth/revoke-other-sessions',headers:{origin},payload:{password:pass}})).statusCode,401);
 const snapshot=(await admin.query<{password_hash:string;recovery_generation:string}>('SELECT password_hash,recovery_generation FROM users WHERE id=$1',[a])).rows[0]!;
 const reset=hashToken(randomBytes(32).toString('base64url'));assert.equal((await pool.query<{issued:boolean}>('SELECT public.issue_password_reset($1,$2) issued',['session-a@example.test',reset])).rows[0]!.issued,true);
 const cross=await pool.query<{n:number}>('SELECT public.revoke_other_sessions($1,$2,$3,$4) n',[b,hashToken(a1!.cookie.split('=')[1]!),hash2,(await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[b])).rows[0].recovery_generation]);assert.equal(cross.rows[0]!.n,-1);
 const response=await revoke(a1!,pass,'192.0.2.8');assert.equal(response.statusCode,200,response.body);assert.deepEqual(response.json(),{status:'ok',revoked:2});assert.equal(response.headers['cache-control'],'no-store');assert.doesNotMatch(response.body,/Synthetic|password|token|session-b/);
 assert.equal((await me(a1!)).statusCode,200);assert.equal((await me(a2!)).statusCode,401);assert.equal((await me(a3!)).statusCode,401);assert.equal((await me(bs!)).statusCode,200);
 assert.equal((await pool.query<{valid:boolean}>('SELECT public.check_password_reset($1) valid',[reset])).rows[0]!.valid,false);
 const oldLogin=await pool.query<{issued:boolean}>('SELECT public.issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[a,'session-a@example.test',snapshot.recovery_generation,snapshot.password_hash,hashToken(randomBytes(32).toString('base64url'))]);assert.equal(oldLogin.rows[0]!.issued,false);
 const fresh=await login('session-a@example.test',pass,'192.0.2.9');assert.equal((await me(fresh)).statusCode,200);
 const expired=await admin.query('UPDATE user_sessions SET revoked_at=now() WHERE token_hash=$1',[hashToken(a1!.cookie.split('=')[1]!)]);assert.equal(expired.rowCount,1);assert.equal((await revoke(a1!,pass,'192.0.2.10')).statusCode,401);assert.equal((await me(fresh)).statusCode,200);
 // Deterministic lock-order tests: a previously verified login must wait for
 // revocation and fail; if issuance commits first, revocation must see it.
 const fhash=hashToken(fresh.cookie.split('=')[1]!);let generation=(await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation;
 const hold=await pool.connect();let inTx=false;
 try{
  await hold.query('BEGIN');inTx=true;
  assert.equal((await hold.query('SELECT public.revoke_other_sessions($1,$2,$3,$4) n',[a,fhash,hash,generation])).rows[0].n,0);
  let settled=false;const delayed=pool.query('SELECT public.issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[a,'session-a@example.test',generation,hash,hashToken(randomBytes(32).toString('base64url'))]).then(x=>{settled=true;return x});
  await new Promise(r=>setTimeout(r,120));assert.equal(settled,false);await hold.query('COMMIT');inTx=false;assert.equal((await delayed).rows[0].issued,false);
  generation=(await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation;
  await hold.query('BEGIN');inTx=true;const th=hashToken(randomBytes(32).toString('base64url'));
  assert.equal((await hold.query('SELECT public.issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[a,'session-a@example.test',generation,hash,th])).rows[0].issued,true);
  settled=false;const delayedRevoke=pool.query('SELECT public.revoke_other_sessions($1,$2,$3,$4) n',[a,fhash,hash,generation]).then(x=>{settled=true;return x});
  await new Promise(r=>setTimeout(r,120));assert.equal(settled,false);await hold.query('COMMIT');inTx=false;assert.equal((await delayedRevoke).rows[0].n,1);
  assert.ok((await admin.query('SELECT revoked_at FROM user_sessions WHERE token_hash=$1',[th])).rows[0].revoked_at);
 }finally{if(inTx)await hold.query('ROLLBACK');hold.release()}
 // User lock held, current session revoked in the meantime: no effects.
 generation=(await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation;
 const lock=await admin.connect();let locked=false;try{
  await lock.query('BEGIN');locked=true;await lock.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[a]);let settled=false;
  const pending=pool.query('SELECT public.revoke_other_sessions($1,$2,$3,$4) n',[a,fhash,hash,generation]).then(x=>{settled=true;return x});
  await new Promise(r=>setTimeout(r,120));assert.equal(settled,false);await admin.query('UPDATE user_sessions SET revoked_at=now() WHERE token_hash=$1',[fhash]);await lock.query('COMMIT');locked=false;
  assert.equal((await pending).rows[0].n,-1);assert.equal((await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation,generation);
 }finally{if(locked)await lock.query('ROLLBACK');lock.release()}
 // Time passing while another transaction holds the current session row must
 // not let an expired session authorize the operation once the lock is free.
 const expSession=await login('session-a@example.test',pass,'192.0.2.30'),expHash=hashToken(expSession.cookie.split('=')[1]!);
 generation=(await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation;
 const expiryLock=await admin.connect();let expLocked=false;try{
  await expiryLock.query('BEGIN');expLocked=true;await expiryLock.query("UPDATE user_sessions SET expires_at=clock_timestamp()+interval '500 milliseconds' WHERE token_hash=$1",[expHash]);
  let settled=false;const pending=pool.query('SELECT public.revoke_other_sessions($1,$2,$3,$4) n',[a,expHash,hash,generation]).then(x=>{settled=true;return x});
  await new Promise(r=>setTimeout(r,800));assert.equal(settled,false);await expiryLock.query('COMMIT');expLocked=false;assert.equal((await pending).rows[0].n,-1);
  assert.equal((await admin.query('SELECT recovery_generation FROM users WHERE id=$1',[a])).rows[0].recovery_generation,generation);
 }finally{if(expLocked)await expiryLock.query('ROLLBACK');expiryLock.release()}
 for(let i=0;i<5;i++)assert.equal((await revoke(bs!,'wrong','192.0.2.31')).statusCode,401);
 assert.equal((await revoke(bs!,otherPass,'192.0.2.31')).statusCode,429);assert.equal((await me(bs!)).statusCode,200);
 await assert.rejects(()=>pool.query('UPDATE users SET recovery_generation=gen_random_uuid() WHERE id=$1',[a]));
 console.log('Sessions: password/CSRF, cross-account isolation, reset links, concurrent login and logout passed');
}finally{await app.close();await pool.end();await admin.end()}
