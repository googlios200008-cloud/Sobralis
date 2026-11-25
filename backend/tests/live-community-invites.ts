// Opt-in; disposable PostgreSQL only.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';import {hashToken} from '../src/security.js';
if(!['sobralis_auth_test','sobralis_invitations_test'].includes(process.env.DB_NAME||'')||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test'),pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-community-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST'|'DELETE'|'PUT',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
async function invite(group:string,s:Session,role:'editor'|'viewer'='editor',maxUses=1){const r=await req('POST',`/api/communities/${group}/invites`,s,{role,expiresInHours:24,maxUses});assert.equal(r.statusCode,201,r.body);return {id:r.json().inviteId as string,token:new URL(r.json().inviteUrl).hash.split('=')[1]!};}
try {
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','a','b','scoped','former'].map(x=>`ci-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at) SELECT x,$8,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6,$7]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),ss:Session[]=[];for(let i=0;i<emails.length;i++)ss.push(await login(emails[i]!,`10.80.0.${i+1}`));const [owner,editor,viewer,a,b,scoped,former]=ss as [Session,Session,Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Group',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'owner','full',now())`,[group,ids[0],ids[1],ids[2],ids[5],ids[6]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Trip',$2) RETURNING id",[group,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner')",[trip,group,ids[6]]);
 const path=`/api/communities/${group}/invites`,payload={role:'editor',expiresInHours:24,maxUses:1};
 assert.equal((await req('POST',path,editor,payload)).statusCode,404);assert.equal((await req('POST',path,viewer,payload)).statusCode,404);
 assert.equal((await req('POST',path,owner,{...payload,role:'owner'})).statusCode,400);
 assert.equal((await req('GET',`/api/communities/${group}/members`,scoped)).statusCode,404);
 const members=await req('GET',`/api/communities/${group}/members`,viewer);assert.equal(members.statusCode,200,members.body);assert.equal(members.json().members.length,3);assert.doesNotMatch(members.body,/@example/);
 const i=await invite(group,owner);
 const listing=await req('GET',path,owner);assert.equal(listing.statusCode,200,listing.body);assert.equal(listing.headers['cache-control'],'no-store');assert.equal(listing.json().invites.length,1);assert.equal(listing.json().invites[0].invite_id,i.id);assert.doesNotMatch(listing.body,new RegExp(i.token));assert.doesNotMatch(listing.body,/token_hash/);
 for(const s of [editor,viewer,scoped,former,a])assert.equal((await req('GET',path,s)).statusCode,404);
 assert.equal((await req('GET',path+'?cursor=bad',owner)).statusCode,400);
 assert.equal((await req('GET',path+'?cursor='+i.id,owner)).json().invites.length,0);
 assert.equal((await admin.query<{token_hash:string}>('SELECT token_hash FROM community_invites WHERE id=$1',[i.id])).rows[0]?.token_hash,hashToken(i.token));
 await assert.rejects(()=>pool.query('SELECT * FROM community_invites'));
 const preview=await app.inject({method:'GET',url:`/api/community-invites/${i.token}/preview`});assert.equal(preview.statusCode,200,preview.body);assert.equal(preview.json().preview.communityName,'Group');assert.equal(preview.headers['cache-control'],'no-store');
 // The current client sends tokens in JSON; legacy URL clients retain the same
 // access controls, semantics and *shared* per-IP rate budget.
 const bodyToken=i.token,bodyPreview=await app.inject({method:'POST',url:'/api/community-invites/preview',headers:origin,remoteAddress:'10.98.0.1',payload:{token:bodyToken}});
 assert.equal(bodyPreview.statusCode,200,bodyPreview.body);assert.equal(bodyPreview.headers['cache-control'],'no-store');assert.equal(bodyPreview.headers['referrer-policy'],'no-referrer');
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/preview',headers:{origin:'https://evil.invalid'},remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/preview',headers:origin,remoteAddress:'10.98.0.2',payload:{token:bodyToken,extra:true}})).statusCode,404);
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/redeem',headers:origin,remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/redeem',headers:{...origin,cookie:owner.cookie},remoteAddress:'10.98.0.2',payload:{token:bodyToken}})).statusCode,403);
 assert.equal((await req('POST','/api/community-invites/redeem',owner,{token:bodyToken,extra:true})).statusCode,400);
 for(let n=0;n<30;n++){const r=n%2?await app.inject({method:'GET',url:`/api/community-invites/${bodyToken}/preview`,remoteAddress:'10.98.0.3'}):await app.inject({method:'POST',url:'/api/community-invites/preview',headers:origin,remoteAddress:'10.98.0.3',payload:{token:bodyToken}});assert.equal(r.statusCode,200,r.body)}
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/preview',headers:origin,remoteAddress:'10.98.0.3',payload:{token:bodyToken}})).statusCode,429);
 for(let n=0;n<10;n++){const r=await app.inject({method:'POST',url:n%2?`/api/community-invites/${bodyToken}/redeem`:'/api/community-invites/redeem',headers:origin,remoteAddress:'10.98.0.4',payload:n%2?{}:{token:bodyToken}});assert.equal(r.statusCode,401,r.body)}
 assert.equal((await app.inject({method:'POST',url:'/api/community-invites/redeem',headers:origin,remoteAddress:'10.98.0.4',payload:{token:bodyToken}})).statusCode,429);
 const race=await Promise.all([req('POST','/api/community-invites/redeem',a,{token:i.token}),req('POST',`/api/community-invites/${i.token}/redeem`,b,{})]);assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,404]);const winner=race[0]!.statusCode===200?a:b;
 assert.equal((await req('POST',`/api/community-invites/${i.token}/redeem`,winner,{})).json().status,'already_member');
 assert.equal((await admin.query<{uses_count:number}>('SELECT uses_count FROM community_invites WHERE id=$1',[i.id])).rows[0]?.uses_count,1);
 assert.equal((await req('GET',`/api/communities/${group}/members`,winner)).statusCode,200);
 const scopeInvite=await invite(group,owner,'viewer');assert.equal((await req('POST',`/api/community-invites/${scopeInvite.token}/redeem`,scoped,{})).statusCode,200);
 const upgraded=(await admin.query<{role:string;membership_scope:string}>('SELECT role,membership_scope FROM community_members WHERE community_id=$1 AND user_id=$2',[group,ids[5]])).rows[0]!;assert.deepEqual(upgraded,{role:'viewer',membership_scope:'full'});
 const oldInvite=await invite(group,owner,'viewer');assert.equal((await req('POST',`/api/community-invites/${oldInvite.token}/redeem`,former,{})).statusCode,200);
 const formerRow=(await admin.query<{role:string;left_at:Date|null}>('SELECT role,left_at FROM community_members WHERE community_id=$1 AND user_id=$2',[group,ids[6]])).rows[0]!;assert.deepEqual(formerRow,{role:'viewer',left_at:null});
 assert.ok((await admin.query<{left_at:Date|null}>('SELECT left_at FROM trip_members WHERE trip_id=$1 AND user_id=$2',[trip,ids[6]])).rows[0]!.left_at);
 assert.equal((await req('GET',`/api/trips/${trip}`,former)).statusCode,404);
 const revoked=await invite(group,owner);assert.equal((await req('DELETE',`${path}/${revoked.id}`,owner,{})).statusCode,200);assert.equal((await req('POST',`/api/community-invites/${revoked.token}/redeem`,editor,{})).statusCode,404);
 const noPromotion=await invite(group,owner,'editor');assert.equal((await req('POST',`/api/community-invites/${noPromotion.token}/redeem`,viewer,{})).json().status,'already_member');
 assert.equal((await admin.query<{role:string}>('SELECT role FROM community_members WHERE community_id=$1 AND user_id=$2',[group,ids[2]])).rows[0]?.role,'viewer');
 assert.equal((await admin.query<{uses_count:number}>('SELECT uses_count FROM community_invites WHERE id=$1',[noPromotion.id])).rows[0]?.uses_count,0);
 const revRace=await invite(group,owner);const results=await Promise.all([req('DELETE',`${path}/${revRace.id}`,owner,{}),req('POST',`/api/community-invites/${revRace.token}/redeem`,a,{})]);assert.equal(results[0]!.statusCode,200,results[0]!.body);assert.ok([200,404].includes(results[1]!.statusCode),results[1]!.body);
 const expired=await invite(group,owner);await admin.query("UPDATE community_invites SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1",[expired.id]);assert.equal((await app.inject({method:'GET',url:`/api/community-invites/${expired.token}/preview`})).statusCode,404);
 await admin.query(`INSERT INTO community_invites(community_id,created_by,token_hash,granted_role,max_uses,expires_at) SELECT $1,$2,encode(sha256(gen_random_uuid()::text::bytea),'hex'),'viewer',1,now()+interval '1 day' FROM generate_series(1,55)`,[group,ids[0]]);
 const first=await req('GET',path,owner),cursor=first.json().nextCursor;assert.ok(cursor);assert.equal(first.json().invites.length,50);const second=await req('GET',path+'?cursor='+cursor,owner);assert.ok(second.json().invites.length>0);assert.ok(second.json().invites.every((x:{invite_id:string})=>!first.json().invites.some((y:{invite_id:string})=>x.invite_id===y.invite_id)));
 const noOwner=await invite(group,owner);await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[0]]);assert.equal((await app.inject({method:'GET',url:`/api/community-invites/${noOwner.token}/preview`})).statusCode,404);assert.equal((await req('GET',path,owner)).statusCode,404);
 console.log('Live full-community invitation scopes, privacy, re-entry and races passed');
}finally{await app.close();await pool.end();await admin.end()}
