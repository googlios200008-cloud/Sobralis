// Opt-in only; creates test users and grants in a disposable DB.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import pg from 'pg';
import argon2 from 'argon2';
import { createApp } from '../src/app.js';
import { readConfig, readSecurityConfig } from '../src/config.js';
import { createPool } from '../src/db.js';
import { hashToken } from '../src/security.js';

if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD||!process.env.TEST_MIGRATOR_PASSWORD)throw new Error('Requires disposable sobralis_auth_test and explicit opt-in');
const config=readConfig(process.env), security=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-only-secret-'.repeat(4)},'test');
const pool=createPool(config), adminDb=new pg.Pool({host:config.DB_HOST,port:config.DB_PORT,database:config.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:security}});
const origin={origin:'https://test.invalid'}, password='test-password-only-2026',suffix=randomBytes(5).toString('hex');
const cli=(...args:string[])=>execFileSync(process.execPath,[join(process.cwd(),'dist','admin.js'),...args],{encoding:'utf8',env:{...process.env,DB_USER:'sobralis_migrator',DB_PASSWORD:process.env.TEST_MIGRATOR_PASSWORD!},stdio:['ignore','pipe','pipe']}).trim();
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{let r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let header=r.headers['set-cookie'];let cookie=Array.isArray(header)?header[0]:header;assert.equal(typeof cookie,'string');return {cookie:cookie!.split(';')[0]!,csrf:r.json().csrfToken,remote}}
async function req(method:'GET'|'POST',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})})}
function parsePromo(text:string){const id=text.match(/^PROMO_ID=(.+)$/m)?.[1],code=text.match(/^PROMO_CODE=(.+)$/m)?.[1];assert.ok(id&&code);return {id,code}}
try{
 const hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=Array.from({length:5},(_,i)=>`tier-${i}-${suffix}@example.invalid`);
 const inserted=await adminDb.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,account_role,email_verified_at) VALUES
 ($1,$6,'Admin','admin',now()),($2,$6,'A','user',now()),($3,$6,'B','user',now()),($4,$6,'C','user',now()),($5,$6,'D','user',now()) RETURNING id`,[...emails,hash]);
 const ids=inserted.rows.map(x=>x.id), admin=ids[0]!;
 const sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.0.0.${i+1}`));
 const a=sessions[1]!,b=sessions[2]!,friend=sessions[3]!,other=sessions[4]!;
 assert.equal((await app.inject({method:'GET',url:'/api/entitlements'})).statusCode,401);
 let free=await req('GET','/api/entitlements',a);assert.equal(free.json().tier,'FREE');
 assert.equal((await req('GET','/api/feature-access/CUSTOM_THEMES',a)).json().error,'UPGRADE_REQUIRED');
 assert.equal((await req('GET','/api/feature-access/BASIC_PLANNING',a)).statusCode,200);
 assert.throws(()=>cli('grant-friends',ids[1]!,ids[2]!)); // ordinary user is not an admin

 const expiry=new Date(Date.now()+86400000).toISOString();
 const promo=parsePromo(cli('create-promo',admin,'PRO','10','1',expiry));
 const stored=await adminDb.query<{code_hash:string}>('SELECT code_hash FROM promo_codes WHERE id=$1',[promo.id]);
 assert.equal(stored.rows[0]?.code_hash,hashToken(promo.code));assert.notEqual(stored.rows[0]?.code_hash,promo.code);
 const race=await Promise.all([req('POST','/api/promos/redeem',a,{code:promo.code}),req('POST','/api/promos/redeem',b,{code:promo.code})]);
 assert.deepEqual(race.map(x=>x.statusCode).sort(),[200,400]);
 const winner=race[0]!.statusCode===200?a:b, winnerId=race[0]!.statusCode===200?ids[1]!:ids[2]!;
 assert.equal((await req('POST','/api/promos/redeem',winner,{code:promo.code})).statusCode,400);
 const count=await adminDb.query<{uses_count:number}>('SELECT uses_count FROM promo_codes WHERE id=$1',[promo.id]);assert.equal(count.rows[0]?.uses_count,1);
 assert.equal((await req('GET','/api/feature-access/CUSTOM_THEMES',winner)).statusCode,200);
 const badSpoof=await req('POST','/api/promos/redeem',other,{code:promo.code,userId:ids[1]});assert.equal(badSpoof.statusCode,400);

 cli('grant-friends',admin,ids[3]!);
 let view=await req('GET','/api/entitlements',friend);assert.equal(view.json().tier,'FRIENDS_UNLIMITED');assert.equal(view.json().expiresAt,null);
 cli('grant-pro',admin,ids[3]!,'5');view=await req('GET','/api/entitlements',friend);assert.equal(view.json().tier,'FRIENDS_UNLIMITED');
 await adminDb.query("INSERT INTO feature_catalog(feature_key) VALUES('FUTURE_PAID_TEST') ON CONFLICT DO NOTHING");
 await adminDb.query("INSERT INTO tier_features(tier,feature_key) VALUES('PRO','FUTURE_PAID_TEST') ON CONFLICT DO NOTHING");
 assert.equal((await req('GET','/api/feature-access/FUTURE_PAID_TEST',friend)).statusCode,200);
 cli('set-flag',admin,'FUTURE_PAID_TEST','off');assert.equal((await req('GET','/api/feature-access/FUTURE_PAID_TEST',friend)).statusCode,404);
 cli('set-flag',admin,'FUTURE_PAID_TEST','on');
 const unusedPromo=parsePromo(cli('create-promo',admin,'PRO','5','2',expiry));
 const notConsumed=await req('POST','/api/promos/redeem',friend,{code:unusedPromo.code});assert.equal(notConsumed.statusCode,409);
 assert.equal((await adminDb.query<{uses_count:number}>('SELECT uses_count FROM promo_codes WHERE id=$1',[unusedPromo.id])).rows[0]?.uses_count,0);
 cli('set-free',admin,ids[3]!,'--confirm');assert.equal((await req('GET','/api/entitlements',friend)).json().tier,'FREE');

 const vip=parsePromo(cli('create-promo',admin,'FRIENDS_UNLIMITED','0','1',expiry));
 assert.equal((await req('POST','/api/promos/redeem',other,{code:vip.code})).statusCode,200);
 assert.equal((await req('GET','/api/entitlements',other)).json().tier,'FRIENDS_UNLIMITED');
 assert.throws(()=>cli('set-free',admin,ids[4]!,'--confirm')); // never silently revoke a promo/payment grant
 const grants=JSON.parse(cli('list-access',admin,ids[4]!)) as {id:string;source:string}[];
 const grant=grants.find(x=>x.source==='promo');assert.ok(grant);
 cli('revoke-grant',admin,ids[4]!,grant.id,'--confirm');
 assert.equal((await req('GET','/api/entitlements',other)).json().tier,'FREE');
 cli('disable-promo',admin,unusedPromo.id);
 assert.equal((await req('POST','/api/promos/redeem',a,{code:unusedPromo.code})).statusCode,400);

 const extra=parsePromo(cli('create-promo',admin,'PRO','5','1',expiry));
 const before=await adminDb.query<{expires_at:Date}>("SELECT max(expires_at) AS expires_at FROM subscriptions WHERE user_id=$1 AND tier='PRO' AND revoked_at IS NULL",[winnerId]);
 assert.equal((await req('POST','/api/promos/redeem',winner,{code:extra.code})).statusCode,200);
 const rows=await adminDb.query<{starts_at:Date}>("SELECT starts_at FROM subscriptions WHERE promo_code_id=$1",[extra.id]);
 assert.equal(rows.rows[0]!.starts_at.getTime(),before.rows[0]!.expires_at.getTime());
 const repeatable=parsePromo(cli('create-promo',admin,'PRO','3','2',expiry));
 assert.equal((await req('POST','/api/promos/redeem',friend,{code:repeatable.code})).statusCode,200);
 assert.equal((await req('POST','/api/promos/redeem',friend,{code:repeatable.code})).statusCode,400);
 assert.equal((await adminDb.query<{uses_count:number}>('SELECT uses_count FROM promo_codes WHERE id=$1',[repeatable.id])).rows[0]?.uses_count,1);
 const expiredCode=randomBytes(32).toString('base64url');
 await adminDb.query("INSERT INTO promo_codes(code_hash,grant_tier,duration_days,max_uses,expires_at,created_at,created_by) VALUES($1,'PRO',3,1,now()-interval '1 day',now()-interval '2 days',$2)",[hashToken(expiredCode),admin]);
 assert.equal((await req('POST','/api/promos/redeem',sessions[0]!,{code:expiredCode})).statusCode,400);
 for(let i=0;i<4;i++)assert.equal((await req('POST','/api/promos/redeem',sessions[0]!,{code:randomBytes(32).toString('base64url')})).statusCode,400);
 assert.equal((await req('POST','/api/promos/redeem',sessions[0]!,{code:randomBytes(32).toString('base64url')})).statusCode,429);
 await assert.rejects(()=>adminDb.query("INSERT INTO promo_codes(code_hash,grant_tier,duration_days,max_uses,expires_at,created_by) VALUES($1,'PRO',NULL,1,now()+interval '1 day',$2)",[hashToken(randomBytes(32).toString('base64url')),admin]));
 const audit=await adminDb.query<{metadata:string}>('SELECT metadata::text AS metadata FROM administrative_actions');
 assert.equal(audit.rows.some(x=>x.metadata.includes(promo.code)||x.metadata.includes(vip.code)),false);
 const noDirect=await adminDb.query<{can_read:boolean}>("SELECT has_table_privilege('sobralis_runtime','promo_codes','SELECT') AS can_read");assert.equal(noDirect.rows[0]?.can_read,false);
 console.log('Live entitlements, admin controls, flags, promo races and expiry semantics passed');
}finally{await app.close();await pool.end();await adminDb.end()}
