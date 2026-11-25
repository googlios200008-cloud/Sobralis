// Synthetic data only; caller must create an empty dedicated migrated database.
import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_trip_once_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires explicitly opted-in disposable trip-once database');
const cfg=readConfig(process.env),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD}),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),app=await createApp({checkDatabase:async()=>{},security:{pool,config:sec}}),origin='https://test.invalid';
try{
 const password='Synthetic-trip-once-2026!',hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const ids=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('once-a@example.test','A',$1,now()),('once-b@example.test','B',$1,now()),('once-v@example.test','V',$1,now()) RETURNING id",[hash])).rows.map(r=>r.id);
 const g=(await admin.query<{id:string}>("SELECT id FROM create_community_for_owner('Group',$1)",[ids[0]])).rows[0]!.id;
 const g2=(await admin.query<{id:string}>("SELECT id FROM create_community_for_owner('Second',$1)",[ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'editor','full'),($1,$3,'viewer','full')",[g,ids[1],ids[2]]);
 async function login(email:string,remoteAddress:string){const r=await app.inject({method:'POST',url:'/api/auth/login',headers:{origin},remoteAddress,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];return {cookie:String(c).split(';')[0]!,csrf:r.json().csrfToken}}
 const a=await login('once-a@example.test','192.0.2.1'),b=await login('once-b@example.test','192.0.2.2'),viewer=await login('once-v@example.test','192.0.2.3');
 let remote=10;const post=(user:typeof a,group:string,title:string,key?:string,timezone='Europe/Moscow')=>app.inject({method:'POST',url:`/api/communities/${group}/trips`,remoteAddress:`198.51.100.${remote++}`,headers:{origin,cookie:user.cookie,'x-csrf-token':user.csrf},payload:{title,timezone,...(key?{clientRequestId:key}:{})}});
 const key=randomUUID(),same=await Promise.all(Array.from({length:8},()=>post(a,g,'Unique retry',key)));for(const r of same)assert.equal(r.statusCode,201,r.body);
 const id=same[0]!.json().trip.id;assert.ok(same.every(r=>r.json().trip.id===id));assert.equal((await admin.query("SELECT count(*)::int n FROM trips WHERE community_id=$1 AND title='Unique retry'",[g])).rows[0].n,1);
 assert.equal((await post(a,g,'Changed',key)).statusCode,409);assert.equal((await post(a,g,'Unique retry',key,'UTC')).statusCode,409);assert.equal((await post(a,g2,'Unique retry',key)).statusCode,409);
 assert.equal((await post(a,g,'Bad key','invalid')).statusCode,400);assert.equal((await post(a,randomUUID(),'No community',randomUUID())).statusCode,404);
 const badKey=randomUUID();assert.equal((await post(a,g,'Invalid zone',badKey,'Invalid/TimeZone')).statusCode,400);assert.equal((await post(a,g,'Now valid',badKey)).statusCode,201);
 const viewerKey=randomUUID();assert.equal((await post(viewer,g,'Not authorized',viewerKey)).statusCode,403);assert.equal((await admin.query('SELECT count(*)::int n FROM trip_creation_requests WHERE user_id=$1 AND request_id=$2',[ids[2],viewerKey])).rows[0].n,0);
 const other=await post(b,g,'Unique retry',key);assert.equal(other.statusCode,201,other.body);assert.notEqual(other.json().trip.id,id);
 const legacy=await post(a,g,'Legacy');assert.equal(legacy.statusCode,201);assert.notEqual(legacy.json().trip.id,id);
 assert.equal((await app.inject({method:'POST',url:`/api/communities/${g}/trips`,headers:{origin:'https://evil.invalid',cookie:a.cookie,'x-csrf-token':a.csrf},payload:{title:'Forbidden',clientRequestId:randomUUID()}})).statusCode,403);
 await assert.rejects(()=>pool.query('SELECT * FROM trip_creation_requests'));
 await admin.query("UPDATE trips SET title='Renamed' WHERE id=$1",[id]);assert.equal((await post(a,g,'Unique retry',key)).json().trip.title,'Renamed');
 await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[g,ids[0]]);assert.equal((await post(a,g,'Unique retry',key)).statusCode,201);
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[g,ids[0]]);assert.equal((await post(a,g,'Unique retry',key)).statusCode,404);
 await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[g,ids[0]]);await admin.query('UPDATE trips SET deleted_at=now() WHERE id=$1',[id]);assert.equal((await post(a,g,'Unique retry',key)).statusCode,404);
 console.log('Trip creation: concurrent retries, account and payload isolation, authorization, lost access and legacy behavior passed');
}finally{await app.close();await pool.end();await admin.end()}
