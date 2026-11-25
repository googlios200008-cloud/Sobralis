// Opt-in only: synthetic data in a disposable sobralis_auth_test database.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(!['sobralis_auth_test','sobralis_invitations_test'].includes(process.env.DB_NAME||'')||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='trip-member-test-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];return {cookie:String(c).split(';')[0]!,csrf:r.json().csrfToken,remote}}
async function req(method:'GET'|'POST'|'PUT'|'PATCH'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})})}
try{
 const suffix=randomBytes(6).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','viewer','editor','outsider','otherowner'].map(x=>`trip-members-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at) SELECT x,$6,'Synthetic',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.89.0.${i+1}`));const [owner,viewer,editor,outsider,otherowner]=sessions as [Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Trip member test',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'owner','full'),($1,$3,'viewer','full'),($1,$4,'editor','full'),($1,$5,'editor','full')",[group,ids[0],ids[1],ids[2],ids[4]]);
 const trips=await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'First',$2),($1,'Second',$2) RETURNING id",[group,ids[0]]);const [one,two]=trips.rows.map(x=>x.id);
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$3,$4,'owner'),($1,$3,$5,'viewer'),($1,$3,$6,'editor'),($1,$3,$7,'owner'),($2,$3,$4,'owner'),($2,$3,$5,'viewer')",[one,two,group,ids[0],ids[1],ids[2],ids[4]]);
 const ep=`/api/trips/${one}/members`,own=`/api/trips/${one}/membership`;
 assert.equal((await app.inject({method:'DELETE',url:own,headers:origin,payload:{}})).statusCode,401);
 assert.equal((await app.inject({method:'DELETE',url:own,headers:{origin:'https://evil.invalid',cookie:viewer.cookie,'x-csrf-token':viewer.csrf},payload:{}})).statusCode,403);
 assert.equal((await app.inject({method:'DELETE',url:own,headers:{...origin,cookie:viewer.cookie,'x-csrf-token':'invalid'},payload:{}})).statusCode,403);
 assert.equal((await req('DELETE',own,viewer,{userId:ids[0]})).statusCode,400);
 assert.equal((await req('DELETE',`${ep}/${ids[2]}`,viewer,{})).statusCode,404);
 assert.equal((await req('DELETE',`${ep}/${ids[1]}`,outsider,{})).statusCode,404);
 assert.equal((await req('DELETE',own,owner,{})).statusCode,409);
 assert.equal((await req('DELETE',`${ep}/${ids[4]}`,owner,{})).statusCode,409);
 const created=await req('POST',`/api/trips/${one}/events`,owner,{title:'Home gathering',startsAt:'2031-01-02T15:00:00Z'});assert.equal(created.statusCode,201,created.body);const event=created.json().event.id;
 const propose=await req('POST',`/api/events/${event}/host-proposals`,owner,{hostId:ids[1]});assert.equal(propose.statusCode,200,propose.body);
 assert.equal((await req('POST',`/api/events/${event}/host-proposals/${propose.json().proposalId}/respond`,viewer,{decision:'accept',clearPreviousLocation:true})).statusCode,200);
 assert.equal((await req('PUT',`/api/events/${event}/hosting`,viewer,{overnight:'yes',overnightCapacity:2})).statusCode,200);
 const removed=await req('DELETE',`${ep}/${ids[1]}`,owner,{});assert.equal(removed.statusCode,200,removed.body);assert.equal(removed.headers['cache-control'],'no-store');
 assert.equal((await req('GET',`/api/trips/${one}`,viewer)).statusCode,404);assert.equal((await req('GET',`/api/trips/${two}`,viewer)).statusCode,200);
 assert.equal((await req('GET',`/api/communities/${group}/members`,viewer)).statusCode,200);assert.equal((await req('DELETE',`${ep}/${ids[1]}`,owner,{})).statusCode,404);
 const inactive=(await req('GET',`/api/events/${event}`,owner)).json().event;assert.equal(inactive.host_active,false);assert.equal(inactive.overnight,'undecided');
 const raw=(await admin.query<{overnight:string;overnight_capacity:number}>('SELECT overnight,overnight_capacity FROM events WHERE id=$1',[event])).rows[0]!;assert.equal(raw.overnight,'yes');assert.equal(raw.overnight_capacity,2);
 const fresh=await req('POST',`/api/trips/${one}/invites`,owner,{role:'viewer',expiresInHours:24,maxUses:5});const freshToken=new URL(fresh.json().inviteUrl).hash.slice('#trip-invite='.length);
 assert.equal((await req('POST',`/api/invites/${freshToken}/redeem`,viewer,{})).statusCode,200);
 assert.equal((await req('GET',`/api/events/${event}`,owner)).json().event.host_active,false);
 // Invites used once before leaving are not reusable; another valid link can
 // re-admit the removed person, so revoking links remains a separate decision.
 const invite=await req('POST',`/api/trips/${one}/invites`,owner,{role:'viewer',expiresInHours:24,maxUses:5});const token=new URL(invite.json().inviteUrl).hash.slice('#trip-invite='.length);
 assert.equal((await req('POST',`/api/invites/${token}/redeem`,outsider,{})).statusCode,200);assert.equal((await req('GET',`/api/trips/${one}`,outsider)).statusCode,200);
 assert.equal((await req('DELETE',`${ep}/${ids[3]}`,owner,{})).statusCode,200);assert.equal((await req('GET',`/api/trips/${one}`,outsider)).statusCode,404);
 assert.equal((await req('POST',`/api/invites/${token}/redeem`,outsider,{})).statusCode,404);
 const newInvite=await req('POST',`/api/trips/${one}/invites`,owner,{role:'viewer',expiresInHours:24,maxUses:5});const token2=new URL(newInvite.json().inviteUrl).hash.slice('#trip-invite='.length);
 assert.equal((await req('POST',`/api/invites/${token2}/redeem`,outsider,{})).statusCode,200);
 assert.equal((await req('DELETE',own,outsider,{})).statusCode,200);assert.equal((await req('GET',`/api/trips/${one}`,outsider)).statusCode,404);
 assert.equal((await req('GET',`/api/communities/${group}/members`,outsider)).statusCode,404);
 const revision=(await req('GET',`/api/trips/${one}`,owner)).json().trip.revision;const editBody={expectedRevision:revision,startsOn:null,endsOn:null};
 // Rename waits for a concurrent revocation and must not write after it commits.
 const renameBlock=await admin.connect();let renameDone=false;try{
  await renameBlock.query('BEGIN');await renameBlock.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[one,ids[2]]);
  const pending=req('PATCH',`/api/trips/${one}`,editor,{...editBody,title:'Must not be written'});await new Promise(resolve=>setTimeout(resolve,100));await renameBlock.query('COMMIT');renameDone=true;assert.equal((await pending).statusCode,404);
 }finally{if(!renameDone)await renameBlock.query('ROLLBACK');renameBlock.release()}
 assert.equal((await admin.query('SELECT title FROM trips WHERE id=$1',[one])).rows[0].title,'First');
 await admin.query('UPDATE trip_members SET left_at=NULL WHERE trip_id=$1 AND user_id=$2',[one,ids[2]]);
 assert.equal((await req('PATCH',`/api/trips/${one}`,viewer,{...editBody,title:'Denied'})).statusCode,403);
 assert.equal((await req('PATCH',`/api/trips/${one}`,editor,{...editBody,title:'Renamed'})).statusCode,200);
 await assert.rejects(()=>pool.query("UPDATE trips SET title='Bypass' WHERE id=$1",[one]));
 // The actor losing owner authority while a remove is blocked wins.
 const block=await admin.connect();let done=false;try{
  await block.query('BEGIN');await block.query("UPDATE trip_members SET role='viewer' WHERE trip_id=$1 AND user_id=$2",[one,ids[0]]);
  const pending=req('DELETE',`${ep}/${ids[2]}`,owner,{});await new Promise(resolve=>setTimeout(resolve,100));await block.query('COMMIT');done=true;assert.equal((await pending).statusCode,404);
 }finally{if(!done)await block.query('ROLLBACK');block.release()}
 assert.equal((await req('GET',`/api/trips/${one}`,editor)).statusCode,200);await admin.query("UPDATE trip_members SET role='owner' WHERE trip_id=$1 AND user_id=$2",[one,ids[0]]);
 assert.equal((await req('DELETE',`${ep}/${ids[2]}`,owner,{})).statusCode,200);assert.equal((await req('GET',`/api/trips/${one}`,editor)).statusCode,404);
 // Two concurrent departures do not deadlock; only one can change membership.
 const race=await Promise.all([req('DELETE',`/api/trips/${two}/membership`,viewer,{}),req('DELETE',`/api/trips/${two}/membership`,viewer,{})]);assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,404]);
 assert.equal((await req('GET',`/api/trips/${one}`,viewer)).statusCode,200);assert.equal((await req('GET',`/api/trips/${two}`,viewer)).statusCode,404);
 assert.equal((await admin.query('SELECT id FROM events WHERE id=$1',[event])).rowCount,1);
 await assert.rejects(()=>pool.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[one,ids[1]]));
 console.log('Trip member removal/leave, privacy, re-entry, host consent, concurrent authority and retained history passed');
}finally{await app.close();await pool.end();await admin.end()}
