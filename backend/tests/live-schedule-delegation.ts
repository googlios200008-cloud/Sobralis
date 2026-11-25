// Opt-in; creates synthetic accounts only in disposable sobralis_auth_test.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires disposable sobralis_auth_test and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-delegation-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];return {cookie:String(c).split(';')[0]!,csrf:r.json().csrfToken,remote}}
async function req(method:'GET'|'POST'|'DELETE'|'PUT',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})})}
try{
 const suffix=randomBytes(6).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1}),emails=['owner','delegate','outsider','viewer','third'].map(x=>`deleg-${x}-${suffix}@example.test`);
 const rows=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at) SELECT x,$6,'Synthetic',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5]::text[]) x RETURNING id`,[...emails,hash]);const ids=rows.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.81.0.${i+1}`));const [owner,delegate,outsider,viewer,third]=sessions as [Session,Session,Session,Session,Session];
 const community=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Delegation test',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'owner','full'),($1,$3,'editor','full'),($1,$4,'viewer','full'),($1,$5,'editor','full')`,[community,ids[0],ids[1],ids[3],ids[4]]);
 const base=`/api/communities/${community}/schedule-delegations`,write=`/api/communities/${community}/schedules/2030-01-02/delegated/${ids[0]}`;
 // The legacy single-day route must serialize with membership revocation,
 // just like a range write, without changing its response shape.
 const own=`/api/communities/${community}/schedules/2030-01-05`;
 const ownSaved=await req('PUT',own,third,{status:'free'});assert.equal(ownSaved.statusCode,200,ownSaved.body);assert.equal(ownSaved.json().entry.status,'free');
 const downgrade=await admin.connect();let downgradeDone=false;try{
  await downgrade.query('BEGIN');await downgrade.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[community,ids[4]]);
  const pending=req('PUT',own,third,{status:'busy'});await new Promise(resolve=>setTimeout(resolve,100));await downgrade.query('COMMIT');downgradeDone=true;
  assert.equal((await pending).statusCode,403);
 }finally{if(!downgradeDone)await downgrade.query('ROLLBACK');downgrade.release()}
 assert.equal((await admin.query<{status:string}>("SELECT status FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date='2030-01-05'",[community,ids[4]])).rows[0]!.status,'free');
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[community,ids[4]]);
 const leave=await admin.connect();let leaveDone=false;try{
  await leave.query('BEGIN');await leave.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[community,ids[4]]);
  const pending=req('PUT',own,third,{status:'work'});await new Promise(resolve=>setTimeout(resolve,100));await leave.query('COMMIT');leaveDone=true;
  assert.equal((await pending).statusCode,404);
 }finally{if(!leaveDone)await leave.query('ROLLBACK');leave.release()}
 assert.equal((await admin.query<{status:string}>("SELECT status FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date='2030-01-05'",[community,ids[4]])).rows[0]!.status,'free');
 await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[community,ids[4]]);
 assert.equal((await req('PUT',write,delegate,{status:'free'})).statusCode,404);
 assert.equal((await req('POST',base,owner,{delegateId:ids[2]})).statusCode,404);assert.equal((await req('POST',base,owner,{delegateId:ids[3]})).statusCode,404);assert.equal((await req('POST',base,owner,{delegateId:ids[0]})).statusCode,404);
 assert.equal((await req('POST',base,viewer,{delegateId:ids[1]})).statusCode,404);assert.equal((await req('GET',base,outsider)).statusCode,404);
 const badCsrf=await app.inject({method:'POST',url:base,headers:{...origin,cookie:owner.cookie,'x-csrf-token':'bad'},payload:{delegateId:ids[1]}});assert.equal(badCsrf.statusCode,403);
 const grant=await req('POST',base,owner,{delegateId:ids[1]});assert.equal(grant.statusCode,201,grant.body);const gid=grant.json().id;assert.equal((await req('POST',base,owner,{delegateId:ids[1]})).json().id,gid);
 const ownerList=await req('GET',base,owner),delegateList=await req('GET',base,delegate),thirdList=await req('GET',base,third);assert.equal(ownerList.json().delegations.length,1);assert.equal(delegateList.json().delegations.length,1);assert.equal(thirdList.json().delegations.length,0);
 assert.equal((await req('PUT',write,third,{status:'busy'})).statusCode,404);assert.equal((await req('PUT',write,delegate,{status:'free',userId:ids[4]})).statusCode,400);
 assert.equal((await req('PUT',write,delegate,{status:'free'})).statusCode,200);assert.equal((await admin.query<{status:string}>("SELECT status FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date='2030-01-02'",[community,ids[0]])).rows[0]?.status,'free');
 assert.equal((await req('DELETE',`${base}/${gid}`,delegate,{})).statusCode,404);assert.equal((await req('DELETE',`${base}/${gid}`,owner,{})).statusCode,200);assert.equal((await req('PUT',write,delegate,{status:'work'})).statusCode,404);
 const log=await admin.query<{action:string}>('SELECT action FROM schedule_delegation_audit WHERE delegation_id=$1 ORDER BY created_at',[gid]);assert.deepEqual(log.rows.map(x=>x.action),['granted','schedule_changed','revoked']);await assert.rejects(()=>pool.query('SELECT * FROM schedule_delegations'));await assert.rejects(()=>pool.query('SELECT * FROM schedule_delegation_audit'));
 const range=`/api/communities/${community}/schedule-range`,body={ownerId:ids[0],from:'2030-03-01',to:'2030-03-03',status:'free'};
 assert.equal((await req('PUT',range,owner,body)).statusCode,200);
 assert.equal((await req('PUT',range,viewer,{...body,ownerId:ids[3]})).statusCode,404);
 assert.equal((await req('PUT',range,outsider,body)).statusCode,404);
 assert.equal((await req('PUT',range,delegate,body)).statusCode,404);
 assert.equal((await req('PUT',range,owner,{...body,to:'2030-04-01'})).statusCode,400);
 assert.equal((await req('PUT',range,owner,{...body,to:'2029-03-01'})).statusCode,400);
 assert.equal((await req('PUT',range,owner,{...body,from:'2030-02-30'})).statusCode,400);
 assert.equal((await req('PUT',range,owner,{...body,actorId:ids[1]})).statusCode,400);
 const cs=await app.inject({method:'PUT',url:range,headers:{...origin,cookie:owner.cookie,'x-csrf-token':'bad'},payload:body});assert.equal(cs.statusCode,403);
 assert.equal((await admin.query<{n:number}>("SELECT count(*)::int n FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date BETWEEN '2030-03-01' AND '2030-03-03' AND status='free'",[community,ids[0]])).rows[0]!.n,3);
 const rangeGrant=(await req('POST',base,owner,{delegateId:ids[1]})).json().id;
 const changed=await req('PUT',range,delegate,{...body,status:'work'});assert.equal(changed.statusCode,200,changed.body);assert.equal(changed.json().days,3);
 assert.equal((await admin.query<{n:number}>("SELECT count(*)::int n FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date BETWEEN '2030-03-01' AND '2030-03-03' AND status='work'",[community,ids[0]])).rows[0]!.n,3);
 const blocker=await admin.connect();let done=false;try{
  await blocker.query('BEGIN');await blocker.query('UPDATE schedule_delegations SET revoked_at=now() WHERE id=$1',[rangeGrant]);
  const pending=req('PUT',range,delegate,{...body,status:'busy'});await new Promise(resolve=>setTimeout(resolve,100));await blocker.query('COMMIT');done=true;
  assert.equal((await pending).statusCode,404);
 }finally{if(!done)await blocker.query('ROLLBACK');blocker.release()}
 assert.equal((await admin.query<{n:number}>("SELECT count(*)::int n FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date BETWEEN '2030-03-01' AND '2030-03-03' AND status='work'",[community,ids[0]])).rows[0]!.n,3);
 const gid2=(await req('POST',base,owner,{delegateId:ids[1]})).json().id;const race=await Promise.all([req('DELETE',`${base}/${gid2}`,owner,{}),req('PUT',write,delegate,{status:'busy'})]);assert.equal(race[0]!.statusCode,200);assert.ok([200,404].includes(race[1]!.statusCode));assert.equal((await req('PUT',write,delegate,{status:'work'})).statusCode,404);
 await req('POST',base,owner,{delegateId:ids[1]});await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[community,ids[1]]);await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[community,ids[1]]);assert.equal((await req('PUT',write,delegate,{status:'free'})).statusCode,404);
 await req('POST',base,owner,{delegateId:ids[1]});await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[community,ids[1]]);await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[community,ids[1]]);assert.equal((await req('PUT',write,delegate,{status:'free'})).statusCode,404);
 await req('POST',base,owner,{delegateId:ids[1]});await admin.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[ids[1]]);await admin.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[ids[1]]);assert.equal((await req('PUT',write,delegate,{status:'free'})).statusCode,404);
 console.log('Delegation: grant, strict authorization, revoke/race, leaving, downgrade, verification, audit and SQL restrictions passed');
}finally{await app.close();await pool.end();await admin.end()}
