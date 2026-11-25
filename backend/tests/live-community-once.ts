// Synthetic data only, in a disposable database with explicit opt-in.
import assert from 'node:assert/strict';import {randomBytes,randomUUID} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_community_once_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires explicitly opted-in disposable community-once database');
const cfg=readConfig(process.env),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD}),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),app=await createApp({checkDatabase:async()=>{},security:{pool,config:sec}}),origin='https://test.invalid';
try{
 const suffix=randomBytes(8).toString('hex'),emails=[`once-a-${suffix}@example.test`,`once-b-${suffix}@example.test`],password='Synthetic-community-once-2026',hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const ids=(await admin.query<{id:string}>('INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES($1,\'A\',$3,now()),($2,\'B\',$3,now()) RETURNING id',[...emails,hash])).rows.map(r=>r.id);
 async function login(email:string,remoteAddress:string){const r=await app.inject({method:'POST',url:'/api/auth/login',headers:{origin},remoteAddress,payload:{email,password}});assert.equal(r.statusCode,200);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];return {cookie:String(c).split(';')[0]!,csrf:r.json().csrfToken,remoteAddress}}
 const a=await login(emails[0]!,'192.0.2.81'),b=await login(emails[1]!,'192.0.2.82');
 let remote=90;const post=(session:typeof a,name:string,key?:string)=>app.inject({method:'POST',url:'/api/communities',remoteAddress:`192.0.2.${remote++}`, headers:{origin,cookie:session.cookie,'x-csrf-token':session.csrf},payload:{name,...(key?{clientRequestId:key}:{})}});
 const key=randomUUID();const same=await Promise.all(Array.from({length:6},()=>post(a,'Unique retry',key)));for(const r of same)assert.equal(r.statusCode,201,r.body);const id=same[0]!.json().community.id;assert.ok(same.every(r=>r.json().community.id===id));assert.equal((await admin.query('SELECT count(*)::int n FROM communities WHERE name=$1',['Unique retry'])).rows[0].n,1);
 assert.equal((await post(a,'Changed input',key)).statusCode,409);assert.equal((await post(a,'Bad request','invalid')).statusCode,400);
 const other=await post(b,'Unique retry',key);assert.equal(other.statusCode,201);assert.notEqual(other.json().community.id,id);
 const legacy=await post(a,'Legacy');assert.equal(legacy.statusCode,201);assert.notEqual(legacy.json().community.id,id);
 assert.equal((await app.inject({method:'POST',url:'/api/communities',headers:{origin:'https://evil.invalid',cookie:a.cookie,'x-csrf-token':a.csrf},payload:{name:'Forbidden',clientRequestId:randomUUID()}})).statusCode,403);
 await assert.rejects(()=>pool.query('SELECT * FROM community_creation_requests'));
 await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[id,ids[0]]);const changed=await post(a,'Unique retry',key);assert.equal(changed.statusCode,201);assert.equal(changed.json().community.role,'viewer');
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[id,ids[0]]);assert.equal((await post(a,'Unique retry',key)).statusCode,404);assert.equal((await admin.query('SELECT count(*)::int n FROM communities WHERE name=$1',['Unique retry'])).rows[0].n,2);
 console.log('Community creation: simultaneous retries, account isolation, conflicts, legacy and lost access passed');
}finally{await app.close();await pool.end();await admin.end()}
