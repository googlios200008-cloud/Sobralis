// Run only on an explicitly disposable database; creates test accounts and trips.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
import argon2 from 'argon2';
import {createApp} from '../src/app.js';
import {readConfig,readSecurityConfig} from '../src/config.js';
import {createPool} from '../src/db.js';
if(!['sobralis_auth_test','sobralis_invitations_test'].includes(process.env.DB_NAME||'')||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),security=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:security}});
const origin={origin:'https://test.invalid'},password='test-only-trip-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try {
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','scoped','left'].map(x=>`trip-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$7,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];
 for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.20.0.${i+1}`));
 const [owner,editor,viewer,outsider,scoped,left]=sessions as [Session,Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'editor','full',now())`,[group,ids[0],ids[1],ids[2],ids[4],ids[5]]);
 const path=`/api/communities/${group}/trips`, payload={title:'Совместная поездка',timezone:'Europe/Moscow'};
 assert.equal((await app.inject({method:'POST',url:path,headers:origin,payload})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:path,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:path,headers:{...origin,cookie:owner.cookie},payload})).statusCode,403);
 assert.equal((await req('POST',path,viewer,payload)).statusCode,403);
 for(const s of [outsider,scoped,left])assert.equal((await req('POST',path,s,payload)).statusCode,404);
 assert.equal((await req('POST',path,owner,{...payload,userId:ids[3]})).statusCode,400);
 assert.equal((await req('POST',path,owner,{...payload,timezone:'Not/A_Real_Zone'})).statusCode,400);
 assert.equal((await req('POST',path,owner,{...payload,title:'   '})).statusCode,400);
 const ownerCreated=await req('POST',path,owner,payload);assert.equal(ownerCreated.statusCode,201,ownerCreated.body);const trip=ownerCreated.json().trip;
 assert.equal(trip.role,'owner');assert.equal(trip.communityId,group);assert.equal(trip.timezone,'Europe/Moscow');assert.equal(ownerCreated.headers['cache-control'],'no-store');
 const persisted=await admin.query<{created_by:string;role:string;user_id:string}>(`SELECT t.created_by,tm.user_id,tm.role FROM trips t JOIN trip_members tm ON tm.trip_id=t.id WHERE t.id=$1`,[trip.id]);
 assert.equal(persisted.rows.length,1);assert.deepEqual(persisted.rows[0],{created_by:ids[0],user_id:ids[0],role:'owner'});
 const editorCreated=await req('POST',path,editor,{title:'Вторая поездка'});assert.equal(editorCreated.statusCode,201,editorCreated.body);assert.equal(editorCreated.json().trip.role,'owner');assert.equal(editorCreated.json().trip.timezone,'Europe/Moscow');
 assert.equal((await req('GET',`/api/trips/${trip.id}`,owner)).statusCode,200);
 assert.equal((await req('GET',`/api/trips/${trip.id}`,editor)).statusCode,404);
 const invite=await req('POST',`/api/trips/${trip.id}/invites`,owner,{role:'viewer',expiresInHours:24,maxUses:1});assert.equal(invite.statusCode,201,invite.body);
 const token=new URL(invite.json().inviteUrl).hash.slice('#trip-invite='.length);
 assert.equal((await req('POST',`/api/invites/${token}/redeem`,outsider,{})).statusCode,200);
 const invitedTrips=await req('GET','/api/trips',outsider);assert.equal(invitedTrips.statusCode,200);assert.equal(invitedTrips.json().trips.some((t:{id:string})=>t.id===trip.id),true);
 assert.equal((await req('GET',`/api/communities/${group}/schedules?from=2026-12-01&to=2026-12-31`,outsider)).statusCode,404);
 assert.equal((await req('POST',path,outsider,payload)).statusCode,404);
 await assert.rejects(()=>pool.query("INSERT INTO trips(community_id,title,created_by) VALUES($1,'no',$2)",[group,ids[0]]));
 await assert.rejects(()=>pool.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner')",[trip.id,group,ids[1]]));
 // Seed enough records to exercise pagination without endpoint rate limits.
 await admin.query(`WITH made AS (INSERT INTO trips(community_id,title,created_by) SELECT $1,'Bulk '||x,$2 FROM generate_series(1,53) x RETURNING id,community_id)
 INSERT INTO trip_members(trip_id,community_id,user_id,role) SELECT id,community_id,$2,'owner' FROM made`,[group,ids[0]]);
 let cursor:string|null=null;const all:string[]=[];let pages=0;
 do {const r=await req('GET',`/api/trips${cursor?`?cursor=${cursor}`:''}`,owner);assert.equal(r.statusCode,200,r.body);assert.equal(r.headers['cache-control'],'no-store');const data=r.json();assert.ok(data.trips.length<=50);all.push(...data.trips.map((t:{id:string})=>t.id));cursor=data.nextCursor;pages++;assert.ok(pages<=3);}while(cursor);
 assert.equal(all.length,54);assert.equal(new Set(all).size,54);assert.ok(all.includes(trip.id));assert.equal(all.includes(editorCreated.json().trip.id),false);assert.equal(pages,2);
 await admin.query('UPDATE trips SET deleted_at=now() WHERE id=$1',[trip.id]);
 assert.equal((await req('GET',`/api/trips/${trip.id}`,owner)).statusCode,404);
 const afterDelete=await req('GET','/api/trips',outsider);assert.equal(afterDelete.json().trips.some((t:{id:string})=>t.id===trip.id),false);
 await admin.query('UPDATE trips SET deleted_at=NULL WHERE id=$1',[trip.id]);
 assert.equal((await req('GET','/api/trips?cursor=not-a-uuid',owner)).statusCode,400);
 assert.equal((await req('GET',`/api/trips?userId=${ids[0]}`,outsider)).statusCode,400);
 await admin.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[trip.id,ids[3]]);
 assert.equal((await req('GET','/api/trips',outsider)).json().trips.some((t:{id:string})=>t.id===trip.id),false);
 // A concurrent role removal must serialize with creation and leave no new trip.
 const blocker=await admin.connect();try{
   await blocker.query('BEGIN');await blocker.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
   const pending=req('POST',path,editor,{title:'Must not appear'});
   await new Promise(resolve=>setTimeout(resolve,100));await blocker.query('COMMIT');
   assert.equal((await pending).statusCode,404);
 }finally{try{await blocker.query('ROLLBACK')}catch{}blocker.release()}
 assert.equal(Number((await admin.query<{count:string}>("SELECT count(*) FROM trips WHERE community_id=$1 AND title='Must not appear'",[group])).rows[0]!.count),0);
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[3]]);
 assert.equal((await req('GET','/api/trips',outsider)).json().trips.length,0);
 await admin.query('UPDATE communities SET deleted_at=now() WHERE id=$1',[group]);
 assert.equal((await req('POST',path,owner,payload)).statusCode,404);
 assert.equal((await req('GET','/api/trips',owner)).json().trips.length,0);
 console.log('Live trip creation, authorization, listing, pagination, invitations and concurrency passed');
}finally{await app.close();await pool.end();await admin.end()}
