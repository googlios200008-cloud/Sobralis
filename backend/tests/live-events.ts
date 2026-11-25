// Opt-in integration test; never run against real data.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
import argon2 from 'argon2';
import {createApp} from '../src/app.js';
import {readConfig,readSecurityConfig} from '../src/config.js';
import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-event-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try{
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','tripeditor','tripviewer','left'].map(x=>`ev-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$8,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6,$7]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.30.0.${i+1}`));
 const [owner,editor,viewer,outsider,tripeditor,tripviewer,left]=sessions as [Session,Session,Session,Session,Session,Session,Session];
 const community=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'viewer','trip_only',NULL),($1,$7,'editor','full',now())`,[community,ids[0],ids[1],ids[2],ids[4],ids[5],ids[6]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Trip',$2) RETURNING id",[community,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor'),($1,$2,$5,'viewer')",[trip,community,ids[0],ids[4],ids[5]]);
 const cp=`/api/communities/${community}/events`,tp=`/api/trips/${trip}/events`;
 const payload={title:'Домашняя встреча',description:'Настолки',location:'Дом',startsAt:'2027-01-02T15:00:00Z',timezone:'Europe/Moscow',venue:'home',overnight:'yes',overnightCapacity:3,guests:'allowed',alcohol:'no',food:'Пицца'};
 assert.equal((await app.inject({method:'POST',url:cp,headers:origin,payload})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:cp,headers:{origin:'https://attacker.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:cp,headers:{...origin,cookie:owner.cookie},payload})).statusCode,403);
 assert.equal((await req('POST',cp,viewer,payload)).statusCode,403);
 for(const s of [outsider,tripeditor,tripviewer,left])assert.equal((await req('POST',cp,s,payload)).statusCode,404);
 assert.equal((await req('POST',tp,tripviewer,payload)).statusCode,403);
 for(const s of [outsider,editor,viewer,left])assert.equal((await req('POST',tp,s,payload)).statusCode,404);
 for(const bad of [{...payload,hostId:ids[1]},{...payload,organizerId:ids[1]},{...payload,overnightCapacity:100},{...payload,overnightCapacity:null},{...payload,venue:'other'}, {...payload,timezone:'invalid zone'},{...payload,startsAt:'2027-02-30T15:00:00Z'},{...payload,startsAt:'2027-01-02T18:00:00+03:00'},{...payload,startsAt:'2027-01-02T15:00:00'},{...payload,guests:'maybe'},{...payload,food:'food\0bad'}])
   assert.equal((await req('POST',cp,owner,bad)).statusCode,400,JSON.stringify(bad));
 const created=await req('POST',cp,owner,payload);assert.equal(created.statusCode,201,created.body);assert.equal(created.headers['cache-control'],'no-store');const event=created.json().event;
 assert.equal(event.organizer_id,ids[0]);assert.equal(event.host_id,ids[0]);assert.equal(event.trip_id,null);assert.equal(event.overnight_capacity,3);assert.equal(event.guests,'allowed');assert.equal(event.alcohol,'no');assert.equal(event.food,'Пицца');assert.equal(event.starts_at,'2027-01-02T15:00:00.000Z');
 const byEditor=await req('POST',cp,editor,{title:'Общая',startsAt:'2027-01-02T15:00:00Z'});assert.equal(byEditor.statusCode,201,byEditor.body);assert.equal(byEditor.json().event.host_id,null);assert.equal(byEditor.json().event.overnight,'undecided');
 const scoped=await req('POST',tp,tripeditor,{...payload,title:'Приватная встреча'});assert.equal(scoped.statusCode,201,scoped.body);const privateEvent=scoped.json().event;assert.equal(privateEvent.host_id,ids[4]);assert.equal(privateEvent.trip_id,trip);
 assert.equal((await req('GET',`/api/events/${event.id}`,viewer)).statusCode,200);
 assert.equal((await req('GET',`/api/events/${event.id}`,tripeditor)).statusCode,404);
 assert.equal((await req('GET',`/api/events/${privateEvent.id}`,viewer)).statusCode,404);
 assert.equal((await req('GET',`/api/events/${privateEvent.id}`,tripviewer)).statusCode,200);
 assert.equal((await req('GET',`/api/events/${privateEvent.id}`,outsider)).statusCode,404);
 assert.equal((await req('GET',cp,tripeditor)).statusCode,404);
 assert.equal((await req('GET',tp,viewer)).statusCode,404);
 const clist=await req('GET',cp,owner),tlist=await req('GET',tp,tripviewer);
 assert.equal(clist.statusCode,200);assert.equal(clist.headers['cache-control'],'no-store');assert.equal(clist.json().events.length,2);assert.equal(clist.json().events.some((e:{id:string})=>e.id===privateEvent.id),false);
 assert.equal(tlist.json().events.length,1);assert.equal(tlist.json().events[0].id,privateEvent.id);
 assert.equal((await req('GET',cp+'?cursor=not-uuid',owner)).statusCode,400);
 await assert.rejects(()=>pool.query('SELECT * FROM events'));
 await assert.rejects(()=>pool.query('SELECT * FROM event_polls'));
 await assert.rejects(()=>pool.query('SELECT * FROM conversation_messages'));
 // Same data returned regardless of the database session's configured timezone.
 const read=await req('GET',`/api/events/${event.id}`,owner);assert.equal(read.json().event.starts_at,event.starts_at);
 // More than one page, sorted by UUID, never leak restricted events into community list.
 await admin.query(`INSERT INTO events(community_id,organizer_id,title,starts_at,timezone)
 SELECT $1,$2,'Bulk '||n,'2027-01-02 15:00:00+00','Europe/Moscow' FROM generate_series(1,52) n`,[community,ids[0]]);
 let cursor:string|null=null;const all:string[]=[];let pages=0;
 do{const r=await req('GET',cp+(cursor?`?cursor=${cursor}`:''),owner);assert.equal(r.statusCode,200);all.push(...r.json().events.map((e:{id:string})=>e.id));cursor=r.json().nextCursor;pages++;assert.ok(pages<4);}while(cursor);
 assert.equal(all.length,54);assert.equal(new Set(all).size,54);assert.equal(all.includes(privateEvent.id),false);assert.equal(pages,2);
 // Revocation is checked inside the same SQL that reads/writes event data.
 const blocker=await admin.connect();let committed=false;try{
   await blocker.query('BEGIN');await blocker.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[trip,ids[4]]);
   const pending=req('POST',tp,tripeditor,{title:'Must not appear',startsAt:'2027-01-02T15:00:00Z'});
   await new Promise(resolve=>setTimeout(resolve,100));await blocker.query('COMMIT');committed=true;assert.equal((await pending).statusCode,404);
 }finally{if(!committed)await blocker.query('ROLLBACK');blocker.release()}
 assert.equal((await req('GET',`/api/events/${privateEvent.id}`,tripeditor)).statusCode,404);
 assert.equal(Number((await admin.query<{count:string}>("SELECT count(*) FROM events WHERE title='Must not appear' AND community_id=$1",[community])).rows[0]!.count),0);
 await admin.query('UPDATE events SET deleted_at=now() WHERE id=$1',[privateEvent.id]);assert.equal((await req('GET',`/api/events/${privateEvent.id}`,tripviewer)).statusCode,404);
 await admin.query('UPDATE trips SET deleted_at=now() WHERE id=$1',[trip]);assert.equal((await req('GET',tp,tripviewer)).statusCode,404);
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[community,ids[2]]);assert.equal((await req('GET',`/api/events/${event.id}`,viewer)).statusCode,404);
 await admin.query('UPDATE communities SET deleted_at=now() WHERE id=$1',[community]);assert.equal((await req('GET',cp,owner)).statusCode,404);assert.equal((await req('GET',`/api/events/${event.id}`,owner)).statusCode,404);
 console.log('Live scoped events, host rules, privacy, pagination and authorization races passed');
}finally{await app.close();await pool.end();await admin.end()}
