// Isolated synthetic database only. Never run this test against a user's data.
import assert from 'node:assert/strict';import {randomBytes,randomUUID} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_event_edit_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Dedicated disposable event edit database required');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD}),app=await createApp({checkDatabase:async()=>{},security:{pool,config:sec}}),origin={origin:'https://test.invalid'};
const suffix=randomBytes(7).toString('hex'),emails=['owner','editor','viewer','outsider','triponly'].map(x=>`edit-${x}-${suffix}@example.test`),password='Synthetic-event-password-2026';
type Session={cookie:string;csrf:string;remote:string};async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let h=r.headers['set-cookie'];if(Array.isArray(h))h=h[0];return {cookie:String(h).split(';')[0]!,csrf:r.json().csrfToken,remote}}
async function req(method:'GET'|'POST'|'PUT'|'PATCH'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})})}
try{
 const hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});const ids=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) SELECT x,'Synthetic',$6,now() FROM unnest(ARRAY[$1,$2,$3,$4,$5]::text[]) x RETURNING id",[...emails,hash])).rows.map(x=>x.id);
 const sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`192.0.2.${100+i}`));const [owner,editor,viewer,outsider,triponly]=sessions as [Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Synthetic edit',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'owner','full'),($1,$3,'editor','full'),($1,$4,'viewer','full'),($1,$5,'editor','trip_only')",[group,ids[0],ids[1],ids[2],ids[4]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Synthetic trip',$2) RETURNING id",[group,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor')",[trip,group,ids[0],ids[4]]);
 const created=await req('POST',`/api/communities/${group}/events`,owner,{title:'Original',startsAt:'2033-06-01T12:00:00Z'});assert.equal(created.statusCode,201,created.body);const event=created.json().event,ep=`/api/events/${event.id}`;
 const body={expectedRevision:event.revision,title:'Moved',startsAt:'2033-06-02T12:00:00.000Z',timezone:'Europe/Moscow'};
 assert.equal((await app.inject({method:'PATCH',url:ep,headers:origin,payload:body})).statusCode,401);
 assert.equal((await app.inject({method:'PATCH',url:ep,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload:body})).statusCode,403);
 assert.equal((await req('PATCH',ep,viewer,body)).statusCode,403);assert.equal((await req('PATCH',ep,outsider,body)).statusCode,404);assert.equal((await req('PATCH',ep,triponly,body)).statusCode,404);
 assert.equal((await req('PATCH',ep,owner,{...body,timezone:'Fake/Zone'})).statusCode,400);assert.equal((await req('PATCH',ep,owner,{...body,title:' '})).statusCode,400);
 assert.equal((await req('POST',`${ep}/comments`,owner,{clientMessageId:randomUUID(),text:'Retained message'})).statusCode,201);
 const changed=await req('PATCH',ep,editor,body);assert.equal(changed.statusCode,200,changed.body);assert.equal(changed.headers['cache-control'],'no-store');assert.equal((await req('PATCH',ep,owner,body)).statusCode,409);
 let current=(await req('GET',ep,owner)).json().event;assert.equal(current.title,'Moved');assert.equal(new Date(current.starts_at).toISOString(),'2033-06-02T12:00:00.000Z');assert.equal((await admin.query('SELECT count(*)::int n FROM event_comments WHERE event_id=$1',[event.id])).rows[0].n,1);
 const held=await admin.connect();let committed=false;try{await held.query('BEGIN');await held.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);const pending=req('PATCH',ep,editor,{...body,expectedRevision:current.revision,title:'No authority'});await new Promise(r=>setTimeout(r,100));await held.query('COMMIT');committed=true;assert.equal((await pending).statusCode,403)}finally{if(!committed)await held.query('ROLLBACK');held.release()}
 const proposal=await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]});assert.equal(proposal.statusCode,200,proposal.body);const pendingBody={...body,expectedRevision:current.revision,title:'Changed with proposal'};const blocked=await req('PATCH',ep,owner,pendingBody);assert.equal(blocked.statusCode,409);assert.equal(blocked.json().error,'HOST_CONFIRMATION_REQUIRED');
 assert.equal((await req('DELETE',`${ep}/host-proposals/${proposal.json().proposalId}`,owner,{})).statusCode,200);assert.equal((await req('PATCH',ep,owner,pendingBody)).statusCode,200);
 // Two editors cannot overwrite one another after reading the same revision.
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 current=(await req('GET',ep,owner)).json().event;const base={...body,expectedRevision:current.revision};
 const race=await Promise.all([req('PATCH',ep,owner,{...base,title:'Winner A'}),req('PATCH',ep,editor,{...base,title:'Winner B'})]);assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,409]);
 // An expired proposal is no longer visible or actionable and must not block editing.
 current=(await req('GET',ep,owner)).json().event;const expired=await req('POST',`${ep}/host-proposals`,owner,{hostId:ids[2]});assert.equal(expired.statusCode,200);
 await admin.query("UPDATE event_host_proposals SET created_at=now()-interval '10 days',expires_at=now()-interval '1 day' WHERE id=$1",[expired.json().proposalId]);
 assert.equal((await req('PATCH',ep,owner,{...body,expectedRevision:current.revision,title:'After expiry'})).statusCode,200);
 assert.equal((await req('POST',`${ep}/host-proposals/${expired.json().proposalId}/respond`,viewer,{decision:'accept',clearPreviousLocation:false})).statusCode,409);
 const home=await req('POST',`/api/communities/${group}/events`,owner,{title:'Home',startsAt:'2033-06-03T12:00:00Z',venue:'home',overnight:'yes',overnightCapacity:2,location:'Synthetic address'});assert.equal(home.statusCode,201);const he=home.json().event;
 const h=await req('PATCH',`/api/events/${he.id}`,owner,{...body,expectedRevision:he.revision});assert.equal(h.statusCode,409);assert.equal(h.json().error,'HOST_CONFIRMATION_REQUIRED');assert.equal((await admin.query('SELECT count(*)::int n FROM event_host_consents WHERE event_id=$1',[he.id])).rows[0].n,1);
 // A draft for a home meeting changes nothing until its actual host accepts.
 const hp=`/api/events/${he.id}`,hb={expectedRevision:he.revision,title:'Home moved',startsAt:'2033-06-09T12:00:00Z',timezone:'Europe/Moscow'};
 assert.equal((await req('POST',`${hp}/change-proposals`,viewer,hb)).statusCode,403);assert.equal((await req('POST',`${hp}/change-proposals`,outsider,hb)).statusCode,404);
 let proposed=await req('POST',`${hp}/change-proposals`,editor,hb);assert.equal(proposed.statusCode,201,proposed.body);let pid=proposed.json().proposalId;
 assert.equal((await req('POST',`${hp}/change-proposals`,owner,hb)).json().error,'CHANGE_ALREADY_PENDING');assert.equal((await req('GET',hp,owner)).json().event.title,'Home');
 assert.equal((await req('GET',`${hp}/change-proposal`,viewer)).json().proposal.title,'Home moved');assert.equal((await req('GET',`${hp}/change-proposal`,outsider)).statusCode,404);
 assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,editor,{decision:'accept'})).statusCode,404);
 assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'decline'})).statusCode,200);assert.equal((await req('GET',hp,owner)).json().event.title,'Home');
 proposed=await req('POST',`${hp}/change-proposals`,editor,hb);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;
 assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,200);const homeMoved=(await req('GET',hp,owner)).json().event;assert.equal(homeMoved.title,'Home moved');assert.equal(homeMoved.host_active,true);assert.equal(homeMoved.overnight,'yes');assert.equal(homeMoved.location,'Synthetic address');
 assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,409);
 // Revoke and restore exactly the old consent values: the separate random generation prevents revival.
 const hp2={...hb,expectedRevision:homeMoved.revision,title:'Must not revive'};proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;
 const saved=(await admin.query('DELETE FROM event_host_consents WHERE event_id=$1 RETURNING *',[he.id])).rows[0];await admin.query('INSERT INTO event_host_consents(event_id,host_id,user_generation,community_generation,trip_generation,consented_at) VALUES($1,$2,$3,$4,$5,$6)',[saved.event_id,saved.host_id,saved.user_generation,saved.community_generation,saved.trip_generation,saved.consented_at]);
 assert.equal((await req('GET',`${hp}/change-proposal`,owner)).json().proposal,null);assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,409);
 // Issuer loses and regains permission: a fresh generation permanently invalidates the earlier draft.
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;
 await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,409);
 // Cancellation and expiry never change the event.
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;assert.equal((await req('DELETE',`${hp}/change-proposals/${pid}`,viewer,{})).statusCode,403);assert.equal((await req('DELETE',`${hp}/change-proposals/${pid}`,editor,{})).statusCode,200);
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;await admin.query("UPDATE event_change_proposals SET created_at=now()-interval '10 days',expires_at=now()-interval '1 day' WHERE id=$1",[pid]);assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,409);assert.equal((await req('GET',hp,owner)).json().event.title,'Home moved');
 // Changing host terms invalidates the exact event revision in the draft.
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;
 assert.equal((await req('PUT',`${hp}/hosting`,owner,{overnight:'no',overnightCapacity:null})).statusCode,200);assert.equal((await req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})).statusCode,409);
 hp2.expectedRevision=(await req('GET',hp,owner)).json().event.revision;
 const otherHost=await req('POST',`${hp}/host-proposals`,owner,{hostId:ids[2]});assert.equal(otherHost.statusCode,200);assert.equal((await req('POST',`${hp}/change-proposals`,editor,hp2)).json().error,'HOST_UNAVAILABLE');
 assert.equal((await req('DELETE',`${hp}/host-proposals/${otherHost.json().proposalId}`,owner,{})).statusCode,200);
 // A concurrent issuer downgrade that commits first prevents the host from accepting.
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;
 const locked=await admin.connect();let didCommit=false;try{await locked.query('BEGIN');await locked.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);const accepting=req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'});await new Promise(r=>setTimeout(r,100));await locked.query('COMMIT');didCommit=true;assert.equal((await accepting).statusCode,409)}finally{if(!didCommit)await locked.query('ROLLBACK');locked.release()}
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 proposed=await req('POST',`${hp}/change-proposals`,editor,hp2);assert.equal(proposed.statusCode,201,proposed.body);pid=proposed.json().proposalId;const answerRace=await Promise.all([req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'}),req('POST',`${hp}/change-proposals/${pid}/respond`,owner,{decision:'accept'})]);assert.deepEqual(answerRace.map(r=>r.statusCode).sort(),[200,409]);
 // A trip-only editor can request a change in that trip, but outsiders cannot read or accept it.
 const th=(await req('POST',`/api/trips/${trip}/events`,owner,{title:'Trip home',startsAt:'2033-06-03T12:00:00Z',venue:'home'})).json().event;const thp=`/api/events/${th.id}`,thb={...hb,expectedRevision:th.revision,title:'Trip home moved'};
 const tp=await req('POST',`${thp}/change-proposals`,triponly,thb);assert.equal(tp.statusCode,201,tp.body);assert.equal((await req('GET',`${thp}/change-proposal`,viewer)).statusCode,404);assert.equal((await req('POST',`${thp}/change-proposals/${tp.json().proposalId}/respond`,owner,{decision:'accept'})).statusCode,200);assert.equal((await req('GET',thp,triponly)).json().event.title,'Trip home moved');
 await assert.rejects(()=>pool.query('SELECT * FROM event_change_proposals'));await assert.rejects(()=>pool.query('SELECT * FROM event_host_consent_generations'));
 const te=(await req('POST',`/api/trips/${trip}/events`,triponly,{title:'Trip event',startsAt:'2033-06-02T12:00:00Z'})).json().event;const tpath=`/api/events/${te.id}`;assert.equal((await req('PATCH',tpath,viewer,{...body,expectedRevision:te.revision})).statusCode,404);assert.equal((await req('PATCH',tpath,triponly,{...body,expectedRevision:te.revision})).statusCode,200);
 await assert.rejects(()=>pool.query("UPDATE events SET title='unsafe' WHERE id=$1",[event.id]));console.log('Event editing: validation, authorization, conflicts, retained history, host re-consent, revocation, expiration and trip scope passed');
}finally{await app.close();await pool.end();await admin.end()}
