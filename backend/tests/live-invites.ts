// Opt-in only; creates disposable test users, trips and invitations.
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import pg from 'pg';
import argon2 from 'argon2';
import {createApp} from '../src/app.js';
import {readConfig,readSecurityConfig} from '../src/config.js';
import {createPool} from '../src/db.js';
import {hashToken} from '../src/security.js';
if(!['sobralis_auth_test','sobralis_invitations_test'].includes(process.env.DB_NAME||'')||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let x=r.headers['set-cookie'];if(Array.isArray(x))x=x[0];assert.equal(typeof x,'string');return {cookie:x!.split(';')[0]!,csrf:r.json().csrfToken,remote}}
async function req(method:'GET'|'POST'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})})}
async function createInvite(trip:string,owner:Session,role:'viewer'|'editor'='viewer',maxUses=1){const r=await req('POST',`/api/trips/${trip}/invites`,owner,{role,expiresInHours:24,maxUses});assert.equal(r.statusCode,201,r.body);const json=r.json(),token=new URL(json.inviteUrl).hash.slice('#trip-invite='.length);assert.ok(token);return {id:json.inviteId as string,token}}
try{
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=Array.from({length:7},(_,i)=>`inv-${i}-${suffix}@example.invalid`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at) VALUES($1,$8,'Owner',now()),($2,$8,'Viewer',now()),($3,$8,'A',now()),($4,$8,'B',now()),($5,$8,'Editor',now()),($6,$8,'Former',now()),($7,$8,'Old owner',now()) RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.1.0.${i+1}`));
 const owner=sessions[0]!,viewer=sessions[1]!,a=sessions[2]!,b=sessions[3]!,editor=sessions[4]!,former=sessions[5]!,oldOwner=sessions[6]!;
 const groups=await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test group',$1) RETURNING id",[ids[0]]);const group=groups.rows[0]!.id;
 await admin.query("INSERT INTO community_members(community_id,user_id,role,left_at) VALUES($1,$2,'owner',NULL),($1,$3,'viewer',NULL),($1,$4,'editor',NULL),($1,$5,'editor',now()),($1,$6,'owner',now())",[group,ids[0],ids[1],ids[4],ids[5],ids[6]]);
 const trips=await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Test trip',$2) RETURNING id",[group,ids[0]]);const trip=trips.rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role,left_at) VALUES($1,$2,$3,'owner',NULL),($1,$2,$4,'viewer',NULL),($1,$2,$5,'editor',now()),($1,$2,$6,'owner',NULL)",[trip,group,ids[0],ids[1],ids[5],ids[6]]);
 assert.equal((await req('POST',`/api/trips/${trip}/invites`,viewer,{role:'viewer',expiresInHours:24,maxUses:1})).statusCode,404);
 assert.equal((await req('POST',`/api/trips/${trip}/invites`,owner,{role:'owner',expiresInHours:24,maxUses:1})).statusCode,400);
 const invite=await createInvite(trip,owner);
 const listPath=`/api/trips/${trip}/invites`,listing=await req('GET',listPath,owner);assert.equal(listing.statusCode,200);assert.equal(listing.headers['cache-control'],'no-store');assert.equal(listing.json().invites[0].invite_id,invite.id);assert.doesNotMatch(listing.body,/token_hash/);assert.doesNotMatch(listing.body,new RegExp(invite.token));
 for(const s of [viewer,editor,a,former])assert.equal((await req('GET',listPath,s)).statusCode,404);
 assert.equal((await req('GET',listPath+'?cursor=bad',owner)).statusCode,400);assert.equal((await req('GET',listPath+'?cursor='+invite.id,owner)).json().invites.length,0);
 const record=await admin.query<{token_hash:string}>('SELECT token_hash FROM trip_invites WHERE id=$1',[invite.id]);assert.equal(record.rows[0]?.token_hash,hashToken(invite.token));assert.notEqual(record.rows[0]?.token_hash,invite.token);
 await assert.rejects(()=>pool.query('SELECT * FROM trip_invites'));
 const preview=await app.inject({method:'GET',url:`/api/invites/${invite.token}/preview`,remoteAddress:'10.2.0.1'});
 assert.equal(preview.statusCode,200,preview.body);assert.equal(preview.json().preview.tripTitle,'Test trip');assert.equal(preview.headers['cache-control'],'no-store');assert.equal(preview.headers['referrer-policy'],'no-referrer');
 const loginRequired=await app.inject({method:'POST',url:`/api/invites/${invite.token}/redeem`,headers:origin,payload:{}});assert.equal(loginRequired.statusCode,401);
 const existing=await req('POST',`/api/invites/${invite.token}/redeem`,owner,{});assert.equal(existing.json().status,'already_member');
 assert.equal((await admin.query<{uses_count:number}>('SELECT uses_count FROM trip_invites WHERE id=$1',[invite.id])).rows[0]?.uses_count,0);
 // The current client sends tokens in JSON; legacy URL clients retain the same
 // access controls, semantics and *shared* per-IP rate budget.
 const bodyToken=invite.token,bodyPreview=await app.inject({method:'POST',url:'/api/invites/preview',headers:origin,remoteAddress:'10.98.0.1',payload:{token:bodyToken}});
 assert.equal(bodyPreview.statusCode,200,bodyPreview.body);assert.equal(bodyPreview.headers['cache-control'],'no-store');assert.equal(bodyPreview.headers['referrer-policy'],'no-referrer');
 assert.equal((await app.inject({method:'POST',url:'/api/invites/preview',headers:{origin:'https://evil.invalid'},remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/api/invites/preview',headers:origin,remoteAddress:'10.98.0.2',payload:{token:bodyToken,extra:true}})).statusCode,404);
 assert.equal((await app.inject({method:'POST',url:'/api/invites/redeem',headers:origin,remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:'/api/invites/redeem',headers:{...origin,cookie:owner.cookie},remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,403);
 assert.equal((await req('POST','/api/invites/redeem',owner,{token:bodyToken,extra:true})).statusCode,400);
 for(let n=0;n<30;n++){const r=n%2?await app.inject({method:'GET',url:`/api/invites/${bodyToken}/preview`,remoteAddress:'10.98.0.3'}):await app.inject({method:'POST',url:'/api/invites/preview',headers:origin,remoteAddress:'10.98.0.3',payload:{token:bodyToken}});assert.equal(r.statusCode,200,r.body)}
 assert.equal((await app.inject({method:'POST',url:'/api/invites/preview',headers:origin,remoteAddress:'10.98.0.3',payload:{token:bodyToken}})).statusCode,429);
 for(let n=0;n<10;n++){const r=await app.inject({method:'POST',url:n%2?`/api/invites/${bodyToken}/redeem`:'/api/invites/redeem',headers:origin,remoteAddress:'10.98.0.4',payload:n%2?{}:{token:bodyToken}});assert.equal(r.statusCode,401,r.body)}
 assert.equal((await app.inject({method:'POST',url:'/api/invites/redeem',headers:origin,remoteAddress:'10.98.0.4',payload:{token:bodyToken}})).statusCode,429);
 const race=await Promise.all([req('POST','/api/invites/redeem',a,{token:invite.token}),req('POST',`/api/invites/${invite.token}/redeem`,b,{})]);
 assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,404]);const winner=race[0]!.statusCode===200?a:b,winnerId=race[0]!.statusCode===200?ids[2]:ids[3];
 assert.equal((await req('POST',`/api/invites/${invite.token}/redeem`,winner,{})).json().status,'already_member');
 assert.equal((await admin.query<{uses_count:number}>('SELECT uses_count FROM trip_invites WHERE id=$1',[invite.id])).rows[0]?.uses_count,1);
 assert.equal((await app.inject({method:'GET',url:`/api/invites/${invite.token}/preview`})).statusCode,404);
 const member=await admin.query<{role:string}>('SELECT role FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,winnerId]);assert.equal(member.rows[0]?.role,'viewer');
 assert.equal((await req('GET',`/api/trips/${trip}`,winner)).statusCode,200);
 assert.equal((await req('GET',`/api/communities/${group}/schedules?from=2026-12-01&to=2026-12-31`,winner)).statusCode,404);
 const hiddenGroups=await req('GET','/api/communities',winner);
 assert.equal(hiddenGroups.json().communities.some((x:{id:string})=>x.id===group),false);
 const scope=await admin.query<{membership_scope:string}>('SELECT membership_scope FROM community_members WHERE community_id=$1 AND user_id=$2',[group,winnerId]);
 assert.equal(scope.rows[0]?.membership_scope,'trip_only');

 const existingEditorInvite=await createInvite(trip,owner,'viewer',2);
 assert.equal((await req('POST',`/api/invites/${existingEditorInvite.token}/redeem`,editor,{})).statusCode,200);
 const roles=await admin.query<{role:string}>('SELECT role FROM community_members WHERE community_id=$1 AND user_id=$2',[group,ids[4]]);assert.equal(roles.rows[0]?.role,'editor');
 assert.equal((await req('GET',`/api/communities/${group}/schedules?from=2026-12-01&to=2026-12-31`,editor)).statusCode,200);
 const editorTrip=await admin.query<{role:string}>('SELECT role FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,ids[4]]);assert.equal(editorTrip.rows[0]?.role,'viewer');
 const rejoin=await createInvite(trip,owner,'viewer');
 assert.equal((await req('POST',`/api/invites/${rejoin.token}/redeem`,former,{})).statusCode,200);
 const revived=await admin.query<{role:string;left_at:Date|null}>('SELECT role,left_at FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,ids[5]]);assert.equal(revived.rows[0]?.role,'viewer');assert.equal(revived.rows[0]?.left_at,null);
 const oldOwnerInvite=await createInvite(trip,owner,'viewer');
 assert.equal((await req('POST',`/api/invites/${oldOwnerInvite.token}/redeem`,oldOwner,{})).statusCode,200);
 const formerOwner=await admin.query<{role:string}>('SELECT role FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,ids[6]]);
 assert.equal(formerOwner.rows[0]?.role,'viewer');

 const adminRoleInvite=await createInvite(trip,owner,'editor',2);
 await admin.query("UPDATE trip_members SET role='editor' WHERE trip_id=$1 AND user_id=$2",[trip,ids[0]]);
 assert.equal((await app.inject({method:'GET',url:`/api/invites/${adminRoleInvite.token}/preview`})).statusCode,404);
 assert.equal((await req('POST',`/api/invites/${adminRoleInvite.token}/redeem`,viewer,{})).statusCode,404);
 await admin.query("UPDATE trip_members SET role='owner' WHERE trip_id=$1 AND user_id=$2",[trip,ids[0]]);
 assert.equal((await req('DELETE',`/api/trips/${trip}/invites/${adminRoleInvite.id}`,viewer,{})).statusCode,404);
 assert.equal((await req('DELETE',`/api/trips/${trip}/invites/${adminRoleInvite.id}`,owner,{})).statusCode,200);
 assert.equal((await app.inject({method:'GET',url:`/api/invites/${adminRoleInvite.token}/preview`})).statusCode,404);
 const expired=await createInvite(trip,owner);
 await admin.query("UPDATE trip_invites SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1",[expired.id]);
 assert.equal((await app.inject({method:'GET',url:`/api/invites/${expired.token}/preview`})).statusCode,404);
 assert.equal((await req('POST',`/api/invites/${expired.token}/redeem`,viewer,{})).statusCode,404);
 await admin.query(`INSERT INTO trip_invites(trip_id,community_id,created_by,token_hash,granted_role,max_uses,expires_at) SELECT $1,$2,$3,encode(sha256(gen_random_uuid()::text::bytea),'hex'),'viewer',1,now()+interval '1 day' FROM generate_series(1,55)`,[trip,group,ids[0]]);
 const first=await req('GET',listPath,owner),cursor=first.json().nextCursor;assert.ok(cursor);assert.equal(first.json().invites.length,50);const second=await req('GET',listPath+'?cursor='+cursor,owner);assert.ok(second.json().invites.length>0);assert.ok(second.json().invites.every((x:{invite_id:string})=>!first.json().invites.some((y:{invite_id:string})=>x.invite_id===y.invite_id)));
 const untrusted=await req('POST',`/api/invites/${existingEditorInvite.token}/redeem`,a,{userId:ids[0]});assert.equal(untrusted.statusCode,400);
 console.log('Live invite permissions, preview, capacity, revocation, expiry and race tests passed');
}finally{await app.close();await pool.end();await admin.end()}
