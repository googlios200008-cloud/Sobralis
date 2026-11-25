// Opt-in integration test against disposable data only.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-host-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST'|'PUT'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try {
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','tripeditor','tripviewer','left'].map(x=>`host-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$8,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6,$7]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.40.0.${i+1}`));
 const [owner,editor,viewer,outsider,tripeditor,tripviewer,left]=sessions as [Session,Session,Session,Session,Session,Session,Session];
 const community=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'viewer','trip_only',NULL),($1,$7,'editor','full',now())`,[community,ids[0],ids[1],ids[2],ids[4],ids[5],ids[6]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Trip',$2) RETURNING id",[community,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor'),($1,$2,$5,'viewer')",[trip,community,ids[0],ids[4],ids[5]]);
 const members=await req('GET',`/api/trips/${trip}/members`,tripviewer);assert.equal(members.statusCode,200,members.body);assert.equal(members.headers['cache-control'],'no-store');assert.deepEqual(new Set(members.json().members.map((m:{id:string})=>m.id)),new Set([ids[0],ids[4],ids[5]]));assert.equal('email' in members.json().members[0],false);assert.equal(members.json().nextCursor,null);
 assert.equal((await req('GET',`/api/trips/${trip}/members`,viewer)).statusCode,404);
 assert.equal((await req('GET',`/api/trips/${trip}/members`,outsider)).statusCode,404);
 assert.equal((await req('GET',`/api/trips/${trip}/members?cursor=bad`,owner)).statusCode,400);
 // Keyset pagination does not truncate a large trip or expose email fields.
 let bulkTrip:string|undefined,bulkIds:string[]=[];
 try{
  bulkTrip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Bulk members',$2) RETURNING id",[community,ids[0]])).rows[0]!.id;
  bulkIds=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) SELECT 'host-page-'||$1||'-'||n||'@example.test','Member',now() FROM generate_series(1,52) n RETURNING id",[suffix])).rows.map(x=>x.id);
  await admin.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) SELECT $1,x,'viewer','trip_only' FROM unnest($2::uuid[]) x",[community,bulkIds]);
  await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) SELECT $1,$2,x,'viewer' FROM unnest($3::uuid[]) x",[bulkTrip,community,[ids[0],...bulkIds]]);
  const first=await req('GET',`/api/trips/${bulkTrip}/members`,owner);assert.equal(first.statusCode,200);assert.equal(first.json().members.length,50);assert.ok(first.json().nextCursor);
  const last=await req('GET',`/api/trips/${bulkTrip}/members?cursor=${first.json().nextCursor}`,owner);assert.equal(last.statusCode,200);assert.equal(last.json().members.length,3);assert.equal(last.json().nextCursor,null);
  const combined=[...first.json().members,...last.json().members];assert.equal(new Set(combined.map((m:{id:string})=>m.id)).size,53);assert.ok(combined.every((m:object)=>!('email' in m)));
 }finally{
  if(bulkTrip)await admin.query('DELETE FROM trip_members WHERE trip_id=$1',[bulkTrip]);
  if(bulkTrip)await admin.query('DELETE FROM trips WHERE id=$1',[bulkTrip]);
  if(bulkIds.length){await admin.query('DELETE FROM community_members WHERE community_id=$1 AND user_id=ANY($2::uuid[])',[community,bulkIds]);await admin.query('DELETE FROM users WHERE id=ANY($1::uuid[])',[bulkIds])}
 }
 const c=await req('POST',`/api/communities/${community}/events`,owner,{title:'At home',startsAt:'2027-01-02T15:00:00Z',venue:'home',overnight:'yes',overnightCapacity:4,location:'Old location'});assert.equal(c.statusCode,201,c.body);const event=c.json().event.id,ep=`/api/events/${event}`;
 const t=await req('POST',`/api/trips/${trip}/events`,owner,{title:'Trip event',startsAt:'2027-01-02T15:00:00Z'});assert.equal(t.statusCode,201,t.body);const tripEvent=t.json().event.id,tp=`/api/events/${tripEvent}`;
 assert.equal((await app.inject({method:'POST',url:`${ep}/host-proposals`,headers:origin,payload:{hostId:ids[2]}})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:`${ep}/host-proposals`,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload:{hostId:ids[2]}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:`${ep}/host-proposals`,headers:{...origin,cookie:owner.cookie},payload:{hostId:ids[2]}})).statusCode,403);
 assert.equal((await req('POST',`${ep}/host-proposals`,viewer,{hostId:ids[1]})).statusCode,403);
 for(const s of [outsider,tripeditor,tripviewer,left])assert.equal((await req('POST',`${ep}/host-proposals`,s,{hostId:ids[1]})).statusCode,404);
 for(const id of [ids[3],ids[4],ids[5],ids[6]])assert.equal((await req('POST',`${ep}/host-proposals`,owner,{hostId:id})).statusCode,404);
 assert.equal((await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[0]})).statusCode,409);
 assert.equal((await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2],actorId:ids[0]})).statusCode,400);
 assert.equal((await req('GET',`${ep}/host-proposal`,outsider)).statusCode,404);
 assert.equal((await req('PUT',`${ep}/hosting`,viewer,{overnight:'no',overnightCapacity:null})).statusCode,403);
 assert.equal((await req('PUT',`${ep}/hosting`,owner,{overnight:'yes',overnightCapacity:0})).statusCode,400);
 assert.equal((await req('PUT',`${ep}/hosting`,owner,{overnight:'no',overnightCapacity:3})).statusCode,400);
 assert.equal((await req('PUT',`${ep}/hosting`,owner,{overnight:'yes',overnightCapacity:5})).statusCode,200);
 const p=await req('POST',`${ep}/host-proposals`,editor,{hostId:ids[2]});assert.equal(p.statusCode,200,p.body);const proposal=p.json().proposalId;
 const same=await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]});assert.equal(same.json().proposalId,proposal);
 const show=await req('GET',`${ep}/host-proposal`,viewer);assert.equal(show.statusCode,200);assert.equal(show.json().proposal.proposed_host,ids[2]);assert.equal(show.headers['cache-control'],'no-store');
 const before=(await req('GET',ep,viewer)).json().event;assert.equal(before.host_id,ids[0]);assert.equal(before.overnight_capacity,5);assert.equal(before.location,'Old location');
 assert.equal((await req('POST',`${ep}/host-proposals/${proposal}/respond`,owner,{decision:'accept',clearPreviousLocation:true})).statusCode,404);
 assert.equal((await req('POST',`${ep}/host-proposals/${proposal}/respond`,viewer,{decision:'accept'})).statusCode,409);
 assert.equal((await req('GET',ep,viewer)).json().event.location,'Old location');
 const accepted=await req('POST',`${ep}/host-proposals/${proposal}/respond`,viewer,{decision:'accept',clearPreviousLocation:true});assert.equal(accepted.statusCode,200,accepted.body);
 const after=(await req('GET',ep,owner)).json().event;assert.equal(after.host_id,ids[2]);assert.equal(after.venue_type,'home');assert.equal(after.overnight,'undecided');assert.equal(after.overnight_capacity,null);assert.equal(after.location,'');
 assert.equal((await req('GET',`${ep}/host-proposal`,owner)).json().proposal,null);
 assert.equal((await req('POST',`${ep}/host-proposals/${proposal}/respond`,viewer,{decision:'accept',clearPreviousLocation:true})).statusCode,409);
 assert.equal((await req('PUT',`${ep}/hosting`,owner,{overnight:'no',overnightCapacity:null})).statusCode,403);
 assert.equal((await req('PUT',`${ep}/hosting`,viewer,{overnight:'yes',overnightCapacity:2})).statusCode,200);
 assert.equal((await req('GET',ep,owner)).json().event.overnight_capacity,2);
 // Withdrawal is explicit, idempotent and hides historical terms from SQL and API readers.
 assert.equal((await req('DELETE',`${ep}/hosting`,owner,{})).statusCode,403);
 assert.equal((await app.inject({method:'DELETE',url:`${ep}/hosting`,headers:{origin:'https://evil.invalid',cookie:viewer.cookie,'x-csrf-token':viewer.csrf},payload:{}})).statusCode,403);
 assert.equal((await req('DELETE',`${ep}/hosting`,viewer,{})).statusCode,200);
 assert.equal((await req('DELETE',`${ep}/hosting`,viewer,{})).statusCode,200);
 let hidden=(await req('GET',ep,owner)).json().event;assert.equal(hidden.host_active,false);assert.equal(hidden.overnight,'undecided');assert.equal(hidden.overnight_capacity,null);assert.equal(hidden.location,'');
 const stored=(await admin.query('SELECT overnight,overnight_capacity FROM events WHERE id=$1',[event])).rows[0];assert.equal(stored.overnight,'yes');assert.equal(stored.overnight_capacity,2);
 assert.equal((await req('PUT',`${ep}/hosting`,viewer,{overnight:'no',overnightCapacity:null})).statusCode,403);
 const again=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]})).json().proposalId;
 assert.equal((await req('POST',`${ep}/host-proposals/${again}/respond`,viewer,{decision:'accept',clearPreviousLocation:true})).statusCode,200);
 assert.equal((await req('GET',ep,owner)).json().event.host_active,true);
 assert.equal((await req('GET',ep,owner)).json().event.overnight,'undecided');
 // New proposals invalidate old pending requests; cancelled and declined cannot be replayed.
 const p2=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[1]})).json().proposalId;
 const p3=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[0]})).json().proposalId;assert.notEqual(p2,p3);
 assert.equal((await req('POST',`${ep}/host-proposals/${p2}/respond`,editor,{decision:'accept'})).statusCode,409);
 assert.equal((await req('POST',`${ep}/host-proposals/${p3}/respond`,owner,{decision:'decline'})).statusCode,200);
 assert.equal((await req('GET',ep,viewer)).json().event.host_id,ids[2]);
 const p4=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[1]})).json().proposalId;
 assert.equal((await req('DELETE',`${ep}/host-proposals/${p4}`,viewer,{})).statusCode,403);
 assert.equal((await req('DELETE',`${ep}/host-proposals/${p4}`,editor,{})).statusCode,200);
 assert.equal((await req('POST',`${ep}/host-proposals/${p4}/respond`,editor,{decision:'accept'})).statusCode,409);
 const p5=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[1]})).json().proposalId;
 await admin.query("UPDATE event_host_proposals SET created_at=now()-interval '9 days',expires_at=now()-interval '1 day' WHERE id=$1",[p5]);
 assert.equal((await req('GET',`${ep}/host-proposal`,owner)).json().proposal,null);
 assert.equal((await req('POST',`${ep}/host-proposals/${p5}/respond`,editor,{decision:'accept'})).statusCode,409);
 const p6=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[1]})).json().proposalId;assert.notEqual(p5,p6);
 // Two simultaneous acceptances of one proposal yield one success, never two writes.
 const race=await Promise.all([req('POST',`${ep}/host-proposals/${p6}/respond`,editor,{decision:'accept'}),req('POST',`${ep}/host-proposals/${p6}/respond`,editor,{decision:'accept'})]);assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,409]);
 assert.equal((await req('GET',ep,owner)).json().event.host_id,ids[1]);
 // Revoking the original requester's authority invalidates the outstanding proposal.
 const staleIssuer=(await req('POST',`${ep}/host-proposals`,editor,{hostId:ids[0]})).json().proposalId;
 const issuerBlock=await admin.connect();let issuerCommitted=false;try {
   await issuerBlock.query('BEGIN');await issuerBlock.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[community,ids[1]]);
   const pending=req('POST',`${ep}/host-proposals/${staleIssuer}/respond`,owner,{decision:'accept'});
   await new Promise(resolve=>setTimeout(resolve,100));await issuerBlock.query('COMMIT');issuerCommitted=true;
   assert.equal((await pending).statusCode,409);
 }finally{if(!issuerCommitted)await issuerBlock.query('ROLLBACK');issuerBlock.release()}
 assert.equal((await req('GET',`${ep}/host-proposal`,owner)).json().proposal,null);
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[community,ids[1]]);
 assert.equal((await req('POST',`${ep}/host-proposals/${staleIssuer}/respond`,owner,{decision:'accept'})).statusCode,409);
 // Scoped trip viewer can be proposed and can accept, but cannot host a community-wide event.
 assert.equal((await req('POST',`${tp}/host-proposals`,owner,{hostId:ids[2]})).statusCode,404);
 const tr=await req('POST',`${tp}/host-proposals`,tripeditor,{hostId:ids[5]});assert.equal(tr.statusCode,200,tr.body);const trp=tr.json().proposalId;
 assert.equal((await req('POST',`${tp}/host-proposals/${trp}/respond`,tripviewer,{decision:'accept'})).statusCode,200);
 assert.equal((await req('PUT',`${tp}/hosting`,tripviewer,{overnight:'no',overnightCapacity:null})).statusCode,200);
 assert.equal((await req('GET',tp,tripviewer)).json().event.host_id,ids[5]);assert.equal((await req('GET',tp,owner)).json().event.host_active,true);
 await admin.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[trip,ids[5]]);
 assert.equal((await req('GET',tp,owner)).json().event.host_active,false);
 assert.equal((await req('PUT',`${tp}/hosting`,tripviewer,{overnight:'yes',overnightCapacity:1})).statusCode,404);
 assert.equal((await req('GET',tp,tripviewer)).statusCode,404);
 // Rejoining and even deleting/recreating the trip membership do not restore consent.
 await admin.query('UPDATE trip_members SET left_at=NULL WHERE trip_id=$1 AND user_id=$2',[trip,ids[5]]);
 let gone=(await req('GET',tp,owner)).json().event;assert.equal(gone.host_active,false);assert.equal(gone.overnight,'undecided');
 assert.equal((await req('PUT',`${tp}/hosting`,tripviewer,{overnight:'yes',overnightCapacity:1})).statusCode,403);
 await admin.query('DELETE FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,ids[5]]);
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'viewer')",[trip,community,ids[5]]);
 assert.equal((await req('GET',tp,owner)).json().event.host_active,false);
 const renewed=(await req('POST',`${tp}/host-proposals`,tripeditor,{hostId:ids[5]})).json().proposalId;
 assert.equal((await req('POST',`${tp}/host-proposals/${renewed}/respond`,tripviewer,{decision:'accept',clearPreviousLocation:true})).statusCode,200);
 assert.equal((await req('GET',tp,owner)).json().event.host_active,true);
 // Losing and regaining verified status is a new generation; old consent stays inactive.
 await admin.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[ids[5]]);
 await admin.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[ids[5]]);
 assert.equal((await req('GET',tp,owner)).json().event.host_active,false);
 await assert.rejects(()=>pool.query('SELECT * FROM event_host_consents'));
 await assert.rejects(()=>pool.query('SELECT * FROM event_host_proposal_generations'));
 await assert.rejects(()=>pool.query('SELECT * FROM event_host_proposals'));
 await assert.rejects(()=>pool.query('UPDATE events SET host_id=$1 WHERE id=$2',[ids[0],event]));
 // Membership removal wins over a blocked acceptance.
 const p7=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]})).json().proposalId;
 const block=await admin.connect();let committed=false;try{
   await block.query('BEGIN');await block.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[community,ids[2]]);
   const pending=req('POST',`${ep}/host-proposals/${p7}/respond`,viewer,{decision:'accept'});
   await new Promise(resolve=>setTimeout(resolve,100));await block.query('COMMIT');committed=true;assert.equal((await pending).statusCode,404);
 }finally{if(!committed)await block.query('ROLLBACK');block.release()}
 assert.equal((await req('GET',ep,owner)).json().event.host_id,ids[1]);
 // A pending proposal becomes permanently stale after leaving, even after rejoining.
 await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[community,ids[2]]);
 assert.equal((await req('GET',`${ep}/host-proposal`,owner)).json().proposal,null);
 assert.equal((await req('POST',`${ep}/host-proposals/${p7}/respond`,viewer,{decision:'accept',clearPreviousLocation:true})).statusCode,409);
 const p8=(await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]})).json().proposalId;assert.notEqual(p7,p8);
 assert.equal((await req('POST',`${ep}/host-proposals/${p8}/respond`,viewer,{decision:'accept',clearPreviousLocation:true})).statusCode,200);
 console.log('Live host proposals, consent, conditions, privacy, expiration and races passed');
}finally{await app.close();await pool.end();await admin.end()}
