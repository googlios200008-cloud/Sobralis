// Explicitly opt-in integration test. It only runs against a database named
// sobralis_auth_test, and creates disposable data. Never point at production.
import assert from 'node:assert/strict';
import { randomBytes, createHash } from 'node:crypto';
import pg from 'pg';
import argon2 from 'argon2';
import { createApp } from '../src/app.js';
import { readConfig, readSecurityConfig } from '../src/config.js';
import { createPool } from '../src/db.js';

if (process.env.DB_NAME !== 'sobralis_auth_test' || process.env.RUN_LIVE_AUTH_TEST !== 'yes') throw new Error('Live test requires disposable sobralis_auth_test database and explicit opt-in');
const config = readConfig(process.env);
const security = readSecurityConfig({
  PUBLIC_ORIGIN:'https://test.invalid', CSRF_SECRET:'test-only-secret-'.repeat(4), REGISTRATION_ENABLED:'true',
  DATA_CONSENT_VERSION:'test-v1', DATA_CONSENT_URL:'/legal/consent-test', TERMS_VERSION:'test-v1', TERMS_URL:'/legal/terms-test',
}, 'test');
const appPool = createPool(config);
const admin = new pg.Pool({host:config.DB_HOST,port:config.DB_PORT,database:config.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const delivered:{to:string;link:string}[]=[];
const mailer={async sendVerification(to:string,link:string){delivered.push({to,link})},async sendPasswordReset(){}};
const app = await createApp({checkDatabase:async()=>{await appPool.query('SELECT 1')},security:{pool:appPool,config:security,mailer}});
const origin = {'origin':'https://test.invalid'};
const suffix = randomBytes(5).toString('hex');
const emails = ['owner','editor','viewer','outsider'].map(s => `${s}-${suffix}@example.test`);
const password='only-a-test-password-2026';
function cookieOf(response:{headers:Record<string,unknown>}){ const header=response.headers['set-cookie']; const value=Array.isArray(header)?header[0]:header; assert.equal(typeof value,'string');return value.split(';')[0]!; }
async function login(email:string,oldCookie?:string){let r=await app.inject({method:'POST',url:'/api/auth/login',headers:{...origin,...(oldCookie?{cookie:oldCookie}:{})},payload:{email,password}});assert.equal(r.statusCode,200,r.body);return {cookie:cookieOf(r),csrf:r.json().csrfToken,header:String(r.headers['set-cookie'])};}
async function req(method:'GET'|'POST'|'PATCH'|'PUT',url:string,cookie:string,csrf?:string,payload?:unknown){const headers:Record<string,string>={cookie,...origin};if(csrf)headers['x-csrf-token']=csrf;return app.inject({method,url,headers,...(payload===undefined?{}:{payload})});}
try {
  const publicConfig=await app.inject({method:'GET',url:'/api/auth/registration-config'});assert.equal(publicConfig.statusCode,200);assert.equal(publicConfig.headers['cache-control'],'no-store');assert.deepEqual(publicConfig.json(),{enabled:true,documents:{dataConsent:{version:'test-v1',url:'/legal/consent-test'},terms:{version:'test-v1',url:'/legal/terms-test'}}});
  const noOrigin=await app.inject({method:'POST',url:'/api/auth/register',payload:{}}); assert.equal(noOrigin.statusCode,403);
  const base={email:emails[0],displayName:'Test Owner',dataConsentAccepted:true,termsAccepted:true};
  const noConsent=await app.inject({method:'POST',url:'/api/auth/register',headers:origin,payload:{...base,dataConsentAccepted:false}}); assert.equal(noConsent.statusCode,400);
  const created=await app.inject({method:'POST',url:'/api/auth/register',headers:origin,payload:base}); assert.equal(created.statusCode,202,created.body);
  const duplicate=await app.inject({method:'POST',url:'/api/auth/register',headers:origin,payload:base}); assert.equal(duplicate.statusCode,202);
  const limited=await app.inject({method:'POST',url:'/api/auth/register',headers:origin,payload:base}); assert.equal(limited.statusCode,429);
  assert.equal(delivered.length,1);assert.equal(delivered[0]?.to,emails[0]);
  const token=new URL(delivered[0]!.link).hash.slice(1);assert.equal(token.length,43);
  const preLogin=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:'10.9.0.1',payload:{email:emails[0],password}});assert.equal(preLogin.statusCode,401);
  const resend=await app.inject({method:'POST',url:'/api/auth/resend-verification',headers:origin,remoteAddress:'10.9.0.2',payload:{email:emails[0]}});assert.equal(resend.statusCode,202);assert.equal(delivered.length,1);
  const versions={dataConsentVersion:'test-v1',termsVersion:'test-v1'};
  const badOrigin=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:{origin:'https://attacker.invalid'},remoteAddress:'10.9.0.7',payload:{token,password,dataConsentAccepted:true,termsAccepted:true,...versions}});assert.equal(badOrigin.statusCode,403);
  const badVersion=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.8',payload:{token,password,dataConsentAccepted:true,termsAccepted:true,...versions,termsVersion:'obsolete'}});assert.equal(badVersion.statusCode,400);
  const badConsent=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.3',payload:{token,password,dataConsentAccepted:false,termsAccepted:true,...versions}});assert.equal(badConsent.statusCode,400);
  const verifyData={token,password,dataConsentAccepted:true,termsAccepted:true,...versions};
  const race=await Promise.all([app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.4',payload:verifyData}),app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.5',payload:verifyData})]);
  assert.deepEqual(race.map(r=>r.statusCode).sort(),[200,400]);
  const replay=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.6',payload:verifyData});assert.equal(replay.statusCode,400);
  // A failed transport leaves the account unverified, without returning a distinct response.
  const failedMailer={async sendVerification(){throw new Error('test smtp failure')},async sendPasswordReset(){throw new Error('test smtp failure')}};
  const failedApp=await createApp({checkDatabase:async()=>{},security:{pool:appPool,config:security,mailer:failedMailer}});
  const failedEmail=`failed-${suffix}@example.test`;
  try {
    const savedError=console.error;console.error=()=>{};
    try { const failed=await failedApp.inject({method:'POST',url:'/api/auth/register',headers:origin,remoteAddress:'10.10.0.1',payload:{...base,email:failedEmail}});assert.equal(failed.statusCode,202); }
    finally {console.error=savedError;}
    const status=await admin.query<{email_verified_at:Date|null}>('SELECT email_verified_at FROM users WHERE email=$1',[failedEmail]);assert.equal(status.rows[0]?.email_verified_at,null);
    const failedLogin=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:'10.10.0.2',payload:{email:failedEmail,password}});assert.equal(failedLogin.statusCode,401);
  } finally {await failedApp.close();}
  const ownerRow=await admin.query<{id:string;password_hash:string;account_role:string}>('SELECT id,password_hash,account_role FROM users WHERE email=$1',[emails[0]]);
  assert.equal(ownerRow.rows.length,1);assert.match(ownerRow.rows[0]!.password_hash,/^\$argon2id\$/);assert.equal(ownerRow.rows[0]!.account_role,'user');
  const ownerId=ownerRow.rows[0]!.id;
  await assert.rejects(()=>appPool.query('SELECT * FROM email_verification_tokens'));
  const unknown=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.10',payload:{...verifyData,token:'A'.repeat(43)}});assert.equal(unknown.statusCode,400);
  const pendingEmail=`pending-${suffix}@example.test`;
  const pending=await app.inject({method:'POST',url:'/api/auth/register',headers:origin,remoteAddress:'10.9.0.11',payload:{...base,email:pendingEmail}});assert.equal(pending.statusCode,202);
  const oldToken=new URL(delivered.at(-1)!.link).hash.slice(1);
  await admin.query("UPDATE email_verification_tokens SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE user_id=(SELECT id FROM users WHERE email=$1)",[pendingEmail]);
  const expired=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.12',payload:{...verifyData,token:oldToken}});assert.equal(expired.statusCode,400);
  const beforeResend=delivered.length;
  const retry=await app.inject({method:'POST',url:'/api/auth/resend-verification',headers:origin,remoteAddress:'10.9.0.13',payload:{email:pendingEmail}});assert.equal(retry.statusCode,202);assert.equal(delivered.length,beforeResend+1);
  const freshToken=new URL(delivered.at(-1)!.link).hash.slice(1);
  assert.notEqual(freshToken,oldToken);
  const confirmed=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.9.0.14',payload:{...verifyData,token:freshToken}});assert.equal(confirmed.statusCode,200);
  const revokeEmail=`revoke-${suffix}@example.test`;
  assert.equal((await app.inject({method:'POST',url:'/api/auth/register',headers:origin,remoteAddress:'10.10.1.1',payload:{...base,email:revokeEmail}})).statusCode,202);
  const revokedToken=new URL(delivered.at(-1)!.link).hash.slice(1);
  await admin.query("UPDATE email_verification_tokens SET created_at=now()-interval '11 minutes' WHERE user_id=(SELECT id FROM users WHERE email=$1)",[revokeEmail]);
  const beforeRace=delivered.length;
  const resendRace=await Promise.all(['10.10.1.2','10.10.1.3'].map(remoteAddress=>app.inject({method:'POST',url:'/api/auth/resend-verification',headers:origin,remoteAddress,payload:{email:revokeEmail}})));
  assert.ok(resendRace.every(r=>r.statusCode===202));assert.equal(delivered.length,beforeRace+1);
  const revoked=await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.10.1.4',payload:{...verifyData,token:revokedToken}});assert.equal(revoked.statusCode,400);
  const alreadyVerified=await app.inject({method:'POST',url:'/api/auth/resend-verification',headers:origin,remoteAddress:'10.9.0.15',payload:{email:pendingEmail}});assert.equal(alreadyVerified.statusCode,202);assert.equal(delivered.length,beforeRace+1);
  await assert.rejects(() => appPool.query("UPDATE users SET account_role='admin' WHERE id=$1",[ownerId]));
  await assert.rejects(() => appPool.query('DELETE FROM user_consents WHERE user_id=$1',[ownerId]));
  await assert.rejects(() => appPool.query("INSERT INTO community_members(community_id,user_id,role) VALUES(gen_random_uuid(),$1,'owner')",[ownerId]));
  const consents=await admin.query<{consent_type:string}>('SELECT consent_type FROM user_consents WHERE user_id=$1',[ownerId]);assert.equal(consents.rowCount,2);
  const passHash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
  const legacyEmail=`legacy-${suffix}@example.test`;
  const legacy=(await admin.query<{id:string}>('INSERT INTO users(email,password_hash,display_name) VALUES($1,$2,$3) RETURNING id',[legacyEmail,passHash,'Legacy'])).rows[0]!.id;
  const legacyToken=randomBytes(32).toString('base64url');
  await admin.query("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",[legacy,createHash('sha256').update(legacyToken).digest('hex')]);
  const legacyCookie=`__Host-sobralis_session=${legacyToken}`;
  assert.equal((await req('GET','/api/auth/me',legacyCookie)).statusCode,401);
  const legacyResend=await app.inject({method:'POST',url:'/api/auth/resend-verification',headers:origin,remoteAddress:'10.11.0.1',payload:{email:legacyEmail}});assert.equal(legacyResend.statusCode,202);
  const legacyVerify=new URL(delivered.at(-1)!.link).hash.slice(1);
  assert.equal((await app.inject({method:'POST',url:'/api/auth/verify-email',headers:origin,remoteAddress:'10.11.0.2',payload:{...verifyData,token:legacyVerify}})).statusCode,200);
  assert.equal((await req('GET','/api/auth/me',legacyCookie)).statusCode,401);
  assert.ok((await admin.query('SELECT revoked_at FROM user_sessions WHERE user_id=$1',[legacy])).rows[0].revoked_at);

  const others=await admin.query<{id:string}>('INSERT INTO users(email,password_hash,display_name,email_verified_at) VALUES ($1,$4,$5,now()),($2,$4,$6,now()),($3,$4,$7,now()) RETURNING id',[emails[1],emails[2],emails[3],passHash,'Editor','Viewer','Outsider']);
  const editorId=others.rows[0]!.id,viewerId=others.rows[1]!.id;
  const community=await admin.query<{id:string}>('INSERT INTO communities(name,created_by) VALUES ($1,$2) RETURNING id',['Test Community',ownerId]);const communityId=community.rows[0]!.id;
  await admin.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'editor'),($1,$4,'viewer')",[communityId,ownerId,editorId,viewerId]);
  const trip=await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Test trip',$2) RETURNING id",[communityId,ownerId]);const tripId=trip.rows[0]!.id;
  await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor'),($1,$2,$5,'viewer')",[tripId,communityId,ownerId,editorId,viewerId]);
  const owner=await login(emails[0]!);const editor=await login(emails[1]!);const viewer=await login(emails[2]!);const outsider=await login(emails[3]!);
  await admin.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[editorId]);
  assert.equal((await req('GET','/api/auth/me',editor.cookie)).statusCode,401);
  const blocked=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:'10.9.0.9',payload:{email:emails[1],password}});assert.equal(blocked.statusCode,401);
  await admin.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[editorId]);
  assert.match(owner.header,/HttpOnly/i);assert.match(owner.header,/Secure/i);assert.match(owner.header,/SameSite=Strict/i);assert.match(owner.header,/Path=\//i);
  const ownCommunities=await req('GET','/api/communities',owner.cookie);
  assert.equal(ownCommunities.statusCode,200);assert.equal(ownCommunities.json().communities.some((c:{id:string})=>c.id===communityId),true);
  const otherCommunities=await req('GET','/api/communities',outsider.cookie);
  assert.equal(otherCommunities.json().communities.some((c:{id:string})=>c.id===communityId),false);
  assert.equal((await req('POST','/api/communities',owner.cookie,undefined,{name:'no csrf'})).statusCode,403);
  const newCommunity=await req('POST','/api/communities',owner.cookie,owner.csrf,{name:'Fresh community'});
  assert.equal(newCommunity.statusCode,201,newCommunity.body);assert.equal(newCommunity.json().community.role,'owner');
  const newCommunityId=newCommunity.json().community.id;
  assert.equal((await req('GET',`/api/communities/${newCommunityId}/schedules?from=2026-12-01&to=2026-12-31`,outsider.cookie)).statusCode,404);
  const schedulePath=`/api/communities/${communityId}/schedules/2026-12-01`;
  assert.equal((await req('PUT',schedulePath,owner.cookie,owner.csrf,{status:'free'})).statusCode,200);
  assert.equal((await req('PUT',schedulePath,editor.cookie,editor.csrf,{status:'work'})).statusCode,200);
  assert.equal((await req('PUT',schedulePath,viewer.cookie,viewer.csrf,{status:'free'})).statusCode,403);
  assert.equal((await req('PUT',schedulePath,outsider.cookie,outsider.csrf,{status:'busy'})).statusCode,404);
  assert.equal((await req('PUT',schedulePath,editor.cookie,editor.csrf,{status:'free',user_id:ownerId})).statusCode,400);
  assert.equal((await req('PUT',`/api/communities/${communityId}/schedules/2026-02-30`,editor.cookie,editor.csrf,{status:'work'})).statusCode,400);
  const readSchedules=await req('GET',`/api/communities/${communityId}/schedules?from=2026-12-01&to=2026-12-31`,viewer.cookie);
  assert.equal(readSchedules.statusCode,200,readSchedules.body);assert.equal(readSchedules.json().entries.length,2);
  assert.equal(readSchedules.json().entries.every((e:{local_date:string}) => e.local_date === '2026-12-01'),true);
  assert.equal((await req('GET',`/api/communities/${communityId}/schedules?from=2026-01-01&to=2026-12-31`,viewer.cookie)).statusCode,400);
  await assert.rejects(() => appPool.query('SELECT * FROM events'));
  await assert.rejects(() => appPool.query('SELECT * FROM conversation_messages'));
  await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[communityId,editorId]);
  assert.equal((await req('GET',`/api/communities/${communityId}/schedules?from=2026-12-01&to=2026-12-31`,editor.cookie)).statusCode,404);
  assert.equal((await req('GET',`/api/trips/${tripId}`,editor.cookie)).statusCode,404);
  await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[communityId,editorId]);

  const raw=owner.cookie.split('=')[1]!;const hashRows=await admin.query<{token_hash:string}>('SELECT token_hash FROM user_sessions WHERE user_id=$1',[ownerId]);assert.notEqual(hashRows.rows[0]!.token_hash,raw);
  assert.equal((await app.inject({method:'GET',url:`/api/trips/${tripId}`})).statusCode,401);
  assert.equal((await req('GET',`/api/trips/${tripId}`,outsider.cookie)).statusCode,404);
  assert.equal((await req('GET',`/api/trips/${tripId}`,owner.cookie)).statusCode,200);
  assert.equal((await req('GET',`/api/trips/${tripId}`,viewer.cookie)).statusCode,200);
  await admin.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[tripId,viewerId]);
  assert.equal((await req('GET',`/api/trips/${tripId}`,viewer.cookie)).statusCode,404);
  await admin.query('UPDATE trip_members SET left_at=NULL WHERE trip_id=$1 AND user_id=$2',[tripId,viewerId]);
  const tripRevision=(await req('GET',`/api/trips/${tripId}`,owner.cookie)).json().trip.revision;const tripEdit={expectedRevision:tripRevision,startsOn:null,endsOn:null};
  assert.equal((await req('PATCH',`/api/trips/${tripId}`,viewer.cookie,viewer.csrf,{...tripEdit,title:'Not allowed'})).statusCode,403);
  assert.equal((await app.inject({method:'PATCH',url:`/api/trips/${tripId}`,headers:{origin:'https://attacker.invalid',cookie:editor.cookie,'x-csrf-token':editor.csrf},payload:{title:'Cross site'}})).statusCode,403);
  assert.equal((await req('PATCH',`/api/trips/${tripId}`,editor.cookie,'wrong',{title:'No csrf'})).statusCode,403);
  assert.equal((await req('PATCH',`/api/trips/${tripId}`,editor.cookie,editor.csrf,{...tripEdit,title:'Spoof',user_id:ownerId})).statusCode,400);
  assert.equal((await req('PATCH',`/api/trips/${tripId}`,editor.cookie,editor.csrf,{...tripEdit,title:'Edited'})).statusCode,200);
  assert.equal((await req('GET',`/api/trips/${tripId}`,owner.cookie)).json().trip.title,'Edited');
  const owner2=await login(emails[0]!,owner.cookie);
  assert.equal((await req('GET','/api/auth/me',owner.cookie)).statusCode,401);
  assert.equal((await req('GET','/api/auth/me',owner2.cookie)).statusCode,200);
  assert.equal((await req('POST','/api/auth/logout',owner2.cookie,undefined,{})).statusCode,403);
  assert.equal((await req('POST','/api/auth/logout',owner2.cookie,owner2.csrf,{})).statusCode,200);
  assert.equal((await req('GET','/api/auth/me',owner2.cookie)).statusCode,401);
  await admin.query("UPDATE user_sessions SET created_at=now()-interval '3 hours', expires_at=now()-interval '1 hour' WHERE user_id=$1",[viewerId]);
  assert.equal((await req('GET','/api/auth/me',viewer.cookie)).statusCode,401);
  await admin.query('DELETE FROM trip_members WHERE trip_id=$1 AND user_id=$2',[tripId,editorId]);
  assert.equal((await req('GET',`/api/trips/${tripId}`,editor.cookie)).statusCode,404);
  for (let i=0;i<3;i++) {
    const bad=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,payload:{email:emails[0],password:'incorrect'}});
    assert.equal(bad.statusCode,401);
  }
  const limitedLogin=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,payload:{email:emails[0],password:'incorrect'}});
  assert.equal(limitedLogin.statusCode,429);
  await admin.query('UPDATE trips SET deleted_at=now() WHERE id=$1',[tripId]);
  assert.equal((await req('GET',`/api/trips/${tripId}`,outsider.cookie)).statusCode,404);
  console.log('Live auth, sessions, community schedules, permissions, CSRF and IDOR tests passed');
} finally { await app.close(); await appPool.end(); await admin.end(); }
