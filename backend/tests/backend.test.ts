import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import type pg from 'pg';
import { createApp } from '../src/app.js';
import { readConfig, readSecurityConfig } from '../src/config.js';
import { hashToken, csrfForToken, equalCsrf, isCalendarDate } from '../src/security.js';
import { createMailer } from '../src/mail.js';
import { readMigrations, applyMigrations, type Migration } from '../src/migration-lib.js';

const env = { DB_HOST: 'db', DB_NAME: 'sobralis', DB_USER: 'sobralis_runtime', DB_PASSWORD: 'x'.repeat(48) };
test('configuration rejects weak or example passwords without exposing them in errors', () => {
  assert.equal(readConfig(env).PORT, 8080);
  assert.throws(() => readConfig({...env, DB_PASSWORD: 'tiny'}), e => e instanceof Error && e.message.includes('DB_PASSWORD') && !e.message.includes('tiny'));
  assert.throws(() => readConfig({...env, DB_PASSWORD: 'REPLACE_WITH_64_RANDOM_HEX_CHARACTERS'}));
});
test('health, readiness, headers and unimplemented routes have safe behavior', async () => {
  let healthy = true;
  const app = await createApp({ checkDatabase: async () => { if (!healthy) throw Error('secret in database error'); } });
  try {
    const health = await app.inject({ method: 'GET', url: '/health' });
    assert.equal(health.statusCode, 200);
    assert.equal(health.headers['cache-control'], 'no-store');
    assert.equal(health.headers['x-content-type-options'], 'nosniff');
    assert.match(String(health.headers['content-security-policy']), /default-src 'none'/);
    assert.equal((await app.inject({ method: 'GET', url: '/ready' })).statusCode, 200);
    healthy = false;
    const failure = await app.inject({ method: 'GET', url: '/ready' });
    assert.equal(failure.statusCode, 503);
    assert.doesNotMatch(failure.body, /secret|database error/);
    const missingApi = await app.inject({ method: 'GET', url: '/api/users' });
    assert.equal(missingApi.statusCode, 503);
    assert.equal(missingApi.headers['cache-control'], 'no-store');
    assert.doesNotMatch(missingApi.body, /secret|database error/);
    assert.equal((await app.inject({ method: 'POST', url: '/api/trips' })).statusCode, 503);
    healthy = true;
    assert.equal((await app.inject({ method: 'GET', url: '/api/users' })).statusCode, 404);
  } finally { await app.close(); }
});

test('disabled registration config is non-sensitive and no-store', async () => {
  const security=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
  const app=await createApp({checkDatabase:async()=>{},security:{pool:{} as pg.Pool,config:security}});
  try{const response=await app.inject({method:'GET',url:'/api/auth/registration-config'});assert.equal(response.statusCode,200);assert.equal(response.headers['cache-control'],'no-store');assert.deepEqual(response.json(),{enabled:false});}
  finally{await app.close()}
});

async function inMemoryMigration(migrations: Migration[], callback: (db: PGlite, run: (items: Migration[]) => Promise<void>) => Promise<void>) {
  const db = new PGlite();
  await db.exec('CREATE ROLE sobralis_runtime;');
  // PGlite uses the PostgreSQL engine in-process; adapt pg's query interface.
  const adapter = { query: async (sql: string, params?: unknown[]) => {
    if (migrations.some(m => m.sql === sql)) { await db.exec(sql); return { rows: [] }; }
    return db.query(sql, params);
  }} as unknown as pg.PoolClient;
  const run = (items: Migration[]) => applyMigrations(adapter, items);
  try { await callback(db, run); } finally { await db.close(); }
}
test('migration runs once, is idempotent and rejects edited history', async () => {
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations);
    await run(migrations);
    const ledger = await db.query('SELECT name FROM schema_migrations');
    assert.equal(ledger.rows.length, migrations.length);
    assert.equal(ledger.rows[0]?.name, '0001_core.sql');
    await assert.rejects(() => run([{...migrations[0]!, checksum: 'altered'}, ...migrations.slice(1)]), /history differs/);
  });
});
test('foundational schema rejects invalid roles, duplicate emails and cross-community membership', async () => {
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations);
    const users = await db.query<{id:string}>("INSERT INTO users(email, display_name) VALUES ('test@example.ru','A'), ('next@example.ru','B') RETURNING id");
    const u1 = users.rows[0]!.id, u2 = users.rows[1]!.id;
    await assert.rejects(() => db.query("INSERT INTO users(email, display_name) VALUES ('TEST@example.ru','C')"));
    const communities = await db.query<{id:string}>("INSERT INTO communities(name, created_by) VALUES ('One',$1),('Two',$1) RETURNING id", [u1]);
    const c1=communities.rows[0]!.id, c2=communities.rows[1]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES ($1,$2,'owner'),($3,$4,'viewer')",[c1,u1,c2,u2]);
    await assert.rejects(() => db.query("INSERT INTO community_members(community_id,user_id,role) VALUES ($1,$2,'superuser')",[c1,u2]));
    const trips=await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES ($1,'Поездка',$2) RETURNING id",[c1,u1]);
    await assert.rejects(() => db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES ($1,$2,$3,'viewer')",[trips.rows[0]!.id,c1,u2]));
    await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES ($1,$2,$3,'owner')",[trips.rows[0]!.id,c1,u1]);
    const type=await db.query<{type:string}>("SELECT pg_typeof(created_at)::text AS type FROM trips LIMIT 1");
    assert.equal(type.rows[0]?.type, 'timestamp with time zone');
  });
});
test('a failing migration rolls back schema changes and ledger entry', async () => {
  const first = await readFile(join(process.cwd(), 'migrations/0001_core.sql'), 'utf8');
  const migrations:Migration[]=[{name:'0001_core.sql',sql:first,checksum:'a'},{name:'0002_bad.sql',sql:'CREATE TABLE should_rollback(id int); SELECT * FROM missing_table;',checksum:'b'}];
  await inMemoryMigration(migrations, async (db, run) => {
    await assert.rejects(() => run(migrations));
    const result = await db.query<{name:string|null}>("SELECT to_regclass('public.should_rollback')::text AS name");
    assert.equal(result.rows[0]?.name, null);
    const ledger = await db.query('SELECT name FROM schema_migrations');
    assert.equal(ledger.rows.length, 1);
  });
});
test('idle database error is handled without exposing connection details', async () => {
  const { createPool } = await import('../src/db.js');
  const pool = createPool(readConfig(env));
  const messages: string[] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => { messages.push(args.join(' ')); };
  try { pool.emit('error', new Error('super-secret-db-password')); } finally { console.error = original; await pool.end(); }
  assert.deepEqual(messages, ['Database connection interrupted']);
  assert.doesNotMatch(messages.join(' '), /super-secret/);
});
test('security settings require exact secure origin, separate documents and random secret', () => {
  const sec = { PUBLIC_ORIGIN: 'https://example.ru', CSRF_SECRET: 'z'.repeat(48) };
  assert.equal(readSecurityConfig(sec, 'production').REGISTRATION_ENABLED, 'false');
  assert.equal(readSecurityConfig(sec, 'production').PASSWORD_RESET_ENABLED, 'false');
  assert.throws(() => readSecurityConfig({...sec,PASSWORD_RESET_ENABLED:'true'},'production'));
  assert.throws(() => readSecurityConfig({...sec,PASSWORD_RESET_ENABLED:'true',DEMO_SHARED_LOGIN_LIMIT:'true',DB_NAME:'sobralis_demo'},'development'));
  assert.throws(() => readSecurityConfig({...sec,PASSWORD_RESET_ENABLED:'true',DEMO_SHARED_ACTION_LIMIT:'true',DB_NAME:'sobralis_demo'},'development'));
  assert.equal(readSecurityConfig(sec, 'production').DEMO_SHARED_LOGIN_LIMIT, 'false');
  assert.throws(() => readSecurityConfig({...sec, DEMO_SHARED_LOGIN_LIMIT:'true', DB_NAME:'sobralis_demo'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, DEMO_SHARED_LOGIN_LIMIT:'true', DB_NAME:'real_db'}, 'development'));
  assert.equal(readSecurityConfig({...sec, DEMO_SHARED_LOGIN_LIMIT:'true', DB_NAME:'sobralis_demo'}, 'development').DEMO_SHARED_LOGIN_LIMIT, 'true');
  assert.equal(readSecurityConfig(sec,'production').DEMO_SHARED_ACTION_LIMIT,'false');
  assert.throws(() => readSecurityConfig({...sec,DEMO_SHARED_ACTION_LIMIT:'true',DB_NAME:'sobralis_demo'},'production'));
  assert.throws(() => readSecurityConfig({...sec,DEMO_SHARED_ACTION_LIMIT:'true',DB_NAME:'real_db'},'development'));
  assert.throws(() => readSecurityConfig({...sec,DEMO_SHARED_ACTION_LIMIT:'true',DB_NAME:'sobralis_demo',REGISTRATION_ENABLED:'true'},'development'));
  assert.equal(readSecurityConfig({...sec,DEMO_SHARED_ACTION_LIMIT:'true',DB_NAME:'sobralis_demo'},'development').DEMO_SHARED_ACTION_LIMIT,'true');
  assert.throws(() => readSecurityConfig({...sec, PUBLIC_ORIGIN:'http://example.ru'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, PUBLIC_ORIGIN:'https://example.ru/path'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, REGISTRATION_ENABLED:'true'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, TRUSTED_PROXY_IP:'0.0.0.0/0'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, REGISTRATION_ENABLED:'true', DATA_CONSENT_VERSION:'v1', DATA_CONSENT_URL:'/legal/consent', TERMS_VERSION:'v1', TERMS_URL:'/legal/terms'}, 'production'));
  assert.throws(() => readSecurityConfig({...sec, CSRF_SECRET:'REPLACE_WITH_random_long_secret'}, 'production'));
});
test('password recovery cannot be enabled without a mailer', async () => {
 const config=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'z'.repeat(48),PASSWORD_RESET_ENABLED:'true'},'test');
 await assert.rejects(()=>createApp({checkDatabase:async()=>{},security:{pool:{} as pg.Pool,config}}),/transport is required/);
});
test('session hashes and CSRF proofs do not reveal the session token', () => {
  const token = 'A'.repeat(43), key = 'k'.repeat(48), proof = csrfForToken(key, token);
  assert.equal(hashToken(token).length, 64);
  assert.notEqual(hashToken(token), token);
  assert.notEqual(proof, token);
  assert.equal(equalCsrf(proof, proof), true);
  assert.equal(equalCsrf(proof, 'B'.repeat(43)), false);
  assert.equal(equalCsrf(proof, 'short'), false);
});
test('calendar dates preserve local day and reject invalid dates', () => {
  assert.equal(isCalendarDate('2028-02-29'), true);
  assert.equal(isCalendarDate('2027-02-29'), false);
  assert.equal(isCalendarDate('2026-13-01'), false);
  assert.equal(isCalendarDate('2026-01-01T00:00:00Z'), false);
  assert.equal(isCalendarDate('1899-12-31'), false);
});
test('runtime cannot access event and conversation tables before their authorization exists', async () => {
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations);
    const result = await db.query<{events_allowed:boolean; messages_allowed:boolean}>(
      "SELECT has_table_privilege('sobralis_runtime','events','SELECT') AS events_allowed, has_table_privilege('sobralis_runtime','conversation_messages','SELECT') AS messages_allowed");
    assert.equal(result.rows[0]?.events_allowed, false);
    assert.equal(result.rows[0]?.messages_allowed, false);
  });
});
test('poll and conversation foreign keys enforce community and participant consistency', async () => {
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations);
    const users = await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES ('one@test.invalid','One'),('two@test.invalid','Two') RETURNING id");
    const a=users.rows[0]!.id, b=users.rows[1]!.id;
    const communities=await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES ('One',$1),('Two',$2) RETURNING id",[a,b]);
    const c1=communities.rows[0]!.id,c2=communities.rows[1]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($3,$4,'owner')",[c1,a,c2,b]);
    const events=await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Test',now(),'Europe/Moscow') RETURNING id",[c1,a]);
    const polls=await db.query<{id:string}>("INSERT INTO event_polls(event_id,community_id,question) VALUES($1,$2,'Question'),($1,$2,'Another') RETURNING id",[events.rows[0]!.id,c1]);
    const options=await db.query<{id:string}>("INSERT INTO event_poll_options(poll_id,label,position) VALUES($1,'Yes',0) RETURNING id",[polls.rows[0]!.id]);
    await assert.rejects(()=>db.query('INSERT INTO event_poll_votes(poll_id,community_id,user_id,option_id) VALUES($1,$2,$3,$4)',[polls.rows[1]!.id,c1,a,options.rows[0]!.id]));
    await assert.rejects(()=>db.query('INSERT INTO event_poll_votes(poll_id,community_id,user_id,option_id) VALUES($1,$2,$3,$4)',[polls.rows[0]!.id,c1,b,options.rows[0]!.id]));
    const chat=await db.query<{id:string}>("INSERT INTO conversations(community_id,kind) VALUES($1,'direct') RETURNING id",[c1]);
    await db.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3)',[chat.rows[0]!.id,c1,a]);
    await assert.rejects(()=>db.query("INSERT INTO conversation_messages(conversation_id,community_id,author_id,body) VALUES($1,$2,$3,'no')",[chat.rows[0]!.id,c1,b]));
  });
});
test('incremental migration preserves existing users, trips and memberships', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations.slice(0,2));
    const u=await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES('keep@test.invalid','Keep') RETURNING id");
    const c=await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep group',$1) RETURNING id",[u.rows[0]!.id]);
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c.rows[0]!.id,u.rows[0]!.id]);
    const trip=await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Keep trip',$2) RETURNING id",[c.rows[0]!.id,u.rows[0]!.id]);
    await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner')",[trip.rows[0]!.id,c.rows[0]!.id,u.rows[0]!.id]);
    await run(migrations);
    const after=await db.query<{title:string;left_at:Date|null}>("SELECT t.title, tm.left_at FROM trips t JOIN trip_members tm ON tm.trip_id=t.id WHERE t.id=$1",[trip.rows[0]!.id]);
    assert.equal(after.rows[0]?.title,'Keep trip');assert.equal(after.rows[0]?.left_at,null);
  });
});
test('entitlements resolve FREE, PRO, unlimited inheritance and flags without downgrading', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations, async (db,run)=>{
    await run(migrations);
    const users=await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES('features@test.invalid','Test') RETURNING id");const id=users.rows[0]!.id;
    type Row={feature_key:string;is_enabled:boolean;is_allowed:boolean;effective_tier:string;tier_expires_at:Date|null};
    const resolve=()=>db.query<Row>('SELECT * FROM public.resolve_user_features($1)',[id]);
    let r=await resolve();assert.equal(r.rows[0]?.effective_tier,'FREE');assert.equal(r.rows.find(x=>x.feature_key==='CUSTOM_THEMES')?.is_allowed,false);
    await db.query("INSERT INTO subscriptions(user_id,tier,source,expires_at) VALUES($1,'PRO','admin',now()+interval '10 days')",[id]);
    r=await resolve();assert.equal(r.rows[0]?.effective_tier,'PRO');assert.equal(r.rows.find(x=>x.feature_key==='CUSTOM_THEMES')?.is_allowed,true);
    await db.query("INSERT INTO subscriptions(user_id,tier,source,expires_at) VALUES($1,'FRIENDS_UNLIMITED','admin',NULL)",[id]);
    await db.query("INSERT INTO feature_catalog(feature_key) VALUES('NEW_PRO_FEATURE')");
    await db.query("INSERT INTO tier_features(tier,feature_key) VALUES('PRO','NEW_PRO_FEATURE')");
    r=await resolve();assert.equal(r.rows[0]?.effective_tier,'FRIENDS_UNLIMITED');assert.equal(r.rows[0]?.tier_expires_at,null);assert.equal(r.rows.find(x=>x.feature_key==='NEW_PRO_FEATURE')?.is_allowed,true);
    await db.query("UPDATE feature_catalog SET enabled=false WHERE feature_key='NEW_PRO_FEATURE'");
    r=await resolve();assert.equal(r.rows.find(x=>x.feature_key==='NEW_PRO_FEATURE')?.is_allowed,false);
    await assert.rejects(()=>db.query("INSERT INTO subscriptions(user_id,tier,source,expires_at) VALUES($1,'FRIENDS_UNLIMITED','admin',now()+interval '1 day')",[id]));
    const priv=await db.query<{has_read:boolean}>("SELECT has_table_privilege('sobralis_runtime','subscriptions','SELECT') AS has_read");assert.equal(priv.rows[0]?.has_read,false);
  });
});
test('entitlements migration preserves existing schedules and leaves users FREE', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations, async (db,run)=>{
    await run(migrations.slice(0,3));
    const u=await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES('keep-calendar@test.invalid','Keep') RETURNING id");
    const c=await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep group',$1) RETURNING id",[u.rows[0]!.id]);
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c.rows[0]!.id,u.rows[0]!.id]);
    await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2026-12-05','free')",[c.rows[0]!.id,u.rows[0]!.id]);
    await run(migrations);
    const entry=await db.query<{status:string}>("SELECT status FROM schedule_entries WHERE community_id=$1 AND user_id=$2",[c.rows[0]!.id,u.rows[0]!.id]);
    assert.equal(entry.rows[0]?.status,'free');
    const feature=await db.query<{effective_tier:string}>("SELECT effective_tier FROM public.resolve_user_features($1) LIMIT 1",[u.rows[0]!.id]);
    assert.equal(feature.rows[0]?.effective_tier,'FREE');
  });
});
test('invite migration keeps previous subscriptions and grants no direct table access', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,4));
    const u=await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES('invite-keep@test.invalid','Test') RETURNING id");
    await db.query("INSERT INTO subscriptions(user_id,tier,source) VALUES($1,'FRIENDS_UNLIMITED','admin')",[u.rows[0]!.id]);
    const c=await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Existing',$1) RETURNING id",[u.rows[0]!.id]);
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c.rows[0]!.id,u.rows[0]!.id]);
    await run(migrations);
    const scope=await db.query<{membership_scope:string}>('SELECT membership_scope FROM community_members WHERE community_id=$1 AND user_id=$2',[c.rows[0]!.id,u.rows[0]!.id]);
    assert.equal(scope.rows[0]?.membership_scope,'full');
    const result=await db.query<{effective_tier:string}>("SELECT effective_tier FROM public.resolve_user_features($1) LIMIT 1",[u.rows[0]!.id]);
    assert.equal(result.rows[0]?.effective_tier,'FRIENDS_UNLIMITED');
    const privilege=await db.query<{allowed:boolean}>("SELECT has_table_privilege('sobralis_runtime','trip_invites','SELECT') AS allowed");assert.equal(privilege.rows[0]?.allowed,false);
  });
});
test('SMTP remains disabled by default and rejects incomplete configurations', () => {
  assert.equal(createMailer({}),null);
  assert.throws(()=>createMailer({EMAIL_MODE:'smtp',SMTP_HOST:'smtp.example.ru'}));
  assert.throws(()=>createMailer({EMAIL_MODE:'smtp',SMTP_HOST:'https://example.ru',SMTP_USER:'user',SMTP_PASSWORD:'secret',SMTP_FROM:'team@example.ru'}));
});
test('verification migration preserves existing grants and never silently marks emails verified', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,5));
    const u=await db.query<{id:string}>("INSERT INTO users(email,display_name) VALUES('legacy@test.invalid','Test') RETURNING id");
    await db.query("INSERT INTO subscriptions(user_id,tier,source) VALUES($1,'FRIENDS_UNLIMITED','admin')",[u.rows[0]!.id]);
    await run(migrations);
    const after=await db.query<{email_verified_at:Date|null}>("SELECT email_verified_at FROM users WHERE id=$1",[u.rows[0]!.id]);assert.equal(after.rows[0]?.email_verified_at,null);
    const privilege=await db.query<{allowed:boolean}>("SELECT has_table_privilege('sobralis_runtime','email_verification_tokens','SELECT') AS allowed");assert.equal(privilege.rows[0]?.allowed,false);
  });
});

test('trip creation migration adds only a narrow privileged function', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations);
    const r=await db.query<{can_insert_trip:boolean;can_insert_member:boolean;can_execute:boolean}>(`SELECT
      has_table_privilege('sobralis_runtime','trips','INSERT') AS can_insert_trip,
      has_table_privilege('sobralis_runtime','trip_members','INSERT') AS can_insert_member,
      has_function_privilege('sobralis_runtime','public.create_trip_for_member(uuid,uuid,text,text)','EXECUTE') AS can_execute`);
    assert.deepEqual(r.rows[0],{can_insert_trip:false,can_insert_member:false,can_execute:true});
    await db.query('CREATE ROLE trip_untrusted NOLOGIN');
    const outsider=await db.query<{can_execute:boolean}>("SELECT has_function_privilege('trip_untrusted','public.create_trip_for_member(uuid,uuid,text,text)','EXECUTE') AS can_execute");
    assert.equal(outsider.rows[0]?.can_execute,false);
  });
});

test('trip creation migration preserves previous trips, roles and subscriptions', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,6));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('owner7@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const t=(await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Existing',$2) RETURNING id",[c,u])).rows[0]!.id;
    await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner')",[t,c,u]);
    await db.query("INSERT INTO subscriptions(user_id,tier,source) VALUES($1,'FRIENDS_UNLIMITED','admin')",[u]);
    await run(migrations);await run(migrations);
    const saved=await db.query<{title:string;role:string;tier:string}>("SELECT t.title,tm.role,s.tier FROM trips t JOIN trip_members tm ON tm.trip_id=t.id JOIN subscriptions s ON s.user_id=tm.user_id WHERE t.id=$1",[t]);
    assert.deepEqual(saved.rows[0],{title:'Existing',role:'owner',tier:'FRIENDS_UNLIMITED'});
  });
});

test('event migration preserves old events and does not grant direct access', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,7));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('event@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const e=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Old event','2027-01-01T00:00:00Z','Europe/Moscow') RETURNING id",[c,u])).rows[0]!.id;
    await run(migrations);await run(migrations);
    const saved=await db.query<{title:string;venue_type:string;host_id:string|null;overnight:string;food:string}>("SELECT title,venue_type,host_id,overnight,food FROM events WHERE id=$1",[e]);
    assert.deepEqual(saved.rows[0],{title:'Old event',venue_type:'other',host_id:null,overnight:'undecided',food:''});
    const access=await db.query<{read:boolean;write:boolean;poll:boolean}>("SELECT has_table_privilege('sobralis_runtime','events','SELECT') AS read,has_table_privilege('sobralis_runtime','events','INSERT') AS write,has_table_privilege('sobralis_runtime','event_polls','SELECT') AS poll");
    assert.deepEqual(access.rows[0],{read:false,write:false,poll:false});
    await assert.rejects(()=>db.query("UPDATE events SET venue_type='home',overnight='yes',host_id=$1,overnight_capacity=NULL WHERE id=$2",[u,e]));
    await assert.rejects(()=>db.query("UPDATE events SET overnight='yes',overnight_capacity=2 WHERE id=$1",[e]));
  });
});

test('host proposal migration preserves existing host, conditions and denies direct access', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,8));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('host@test.invalid','Host',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const e=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone,venue_type,host_id,overnight,overnight_capacity,location) VALUES($1,$2,'Old host event','2027-01-01T00:00:00Z','Europe/Moscow','home',$2,'yes',2,'Previous address') RETURNING id",[c,u])).rows[0]!.id;
    await run(migrations);await run(migrations);
    const saved=await db.query<{host_id:string;overnight:string;overnight_capacity:number;location:string}>("SELECT host_id,overnight,overnight_capacity,location FROM events WHERE id=$1",[e]);
    assert.deepEqual(saved.rows[0],{host_id:u,overnight:'yes',overnight_capacity:2,location:'Previous address'});
    const privileges=await db.query<{read:boolean;write:boolean;helper:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_host_proposals','SELECT') AS read,has_table_privilege('sobralis_runtime','event_host_proposals','INSERT') AS write,has_function_privilege('sobralis_runtime','public.lock_event_for_member(uuid,uuid)','EXECUTE') AS helper");
    assert.deepEqual(privileges.rows[0],{read:false,write:false,helper:false});
  });
});
test('poll API migration preserves existing polls and votes without table grants', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,9));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('poll@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const e=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Event','2027-01-01T00:00:00Z','Europe/Moscow') RETURNING id",[c,u])).rows[0]!.id;
    const p=(await db.query<{id:string}>("INSERT INTO event_polls(event_id,community_id,question) VALUES($1,$2,'Existing?') RETURNING id",[e,c])).rows[0]!.id;
    const o=(await db.query<{id:string}>("INSERT INTO event_poll_options(poll_id,label,position) VALUES($1,'Yes',0) RETURNING id",[p])).rows[0]!.id;
    await db.query("INSERT INTO event_poll_votes(poll_id,community_id,user_id,option_id) VALUES($1,$2,$3,$4)",[p,c,u,o]);
    await run(migrations);await run(migrations);
    const saved=await db.query<{question:string;label:string;user_id:string}>("SELECT p.question,o.label,v.user_id FROM event_polls p JOIN event_poll_options o ON o.poll_id=p.id JOIN event_poll_votes v ON v.option_id=o.id WHERE p.id=$1",[p]);
    assert.deepEqual(saved.rows[0],{question:'Existing?',label:'Yes',user_id:u});
    const access=await db.query<{poll:boolean;option:boolean;vote:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_polls','SELECT') AS poll,has_table_privilege('sobralis_runtime','event_poll_options','SELECT') AS option,has_table_privilege('sobralis_runtime','event_poll_votes','SELECT') AS vote");
    assert.deepEqual(access.rows[0],{poll:false,option:false,vote:false});
  });
});
test('event discussion migration retains prior polls and restricts direct message access', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,10));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('discussion@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const e=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Event','2027-01-01T00:00:00Z','Europe/Moscow') RETURNING id",[c,u])).rows[0]!.id;
    const p=(await db.query<{id:string}>("INSERT INTO event_polls(event_id,community_id,question) VALUES($1,$2,'Existing?') RETURNING id",[e,c])).rows[0]!.id;
    const o=(await db.query<{id:string}>("INSERT INTO event_poll_options(poll_id,label,position) VALUES($1,'Yes',0) RETURNING id",[p])).rows[0]!.id;
    await db.query("INSERT INTO event_poll_votes(poll_id,community_id,user_id,option_id) VALUES($1,$2,$3,$4)",[p,c,u,o]);
    await run(migrations);await run(migrations);
    const saved=await db.query<{question:string;label:string;user_id:string}>("SELECT p.question,o.label,v.user_id FROM event_polls p JOIN event_poll_options o ON o.poll_id=p.id JOIN event_poll_votes v ON v.option_id=o.id WHERE p.id=$1",[p]);
    assert.deepEqual(saved.rows[0],{question:'Existing?',label:'Yes',user_id:u});
    const rights=await db.query<{read:boolean;write:boolean;erase:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_comments','SELECT') AS read,has_table_privilege('sobralis_runtime','event_comments','INSERT') AS write,has_table_privilege('sobralis_runtime','event_comments','DELETE') AS erase");
    assert.deepEqual(rights.rows[0],{read:false,write:false,erase:false});
  });
});
test('direct migration preserves existing conversation history and keeps direct table privileges closed', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,11));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('direct-old@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    const conversation=(await db.query<{id:string}>("INSERT INTO conversations(community_id,kind) VALUES($1,'direct') RETURNING id",[c])).rows[0]!.id;
    await db.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3)',[conversation,c,u]);
    await db.query(`INSERT INTO conversation_messages(conversation_id,community_id,author_id,body,created_at) VALUES
      ($1,$2,$3,'later','2027-01-02T00:00:00Z'),($1,$2,$3,'earlier','2027-01-01T00:00:00Z')`,[conversation,c,u]);
    await run(migrations);await run(migrations);
    const history=await db.query<{body:string;client_message_id:string|null}>('SELECT body,client_message_id FROM conversation_messages WHERE conversation_id=$1 ORDER BY seq',[conversation]);
    assert.deepEqual(history.rows,[{body:'earlier',client_message_id:null},{body:'later',client_message_id:null}]);
    const mapping=await db.query<{count:number}>('SELECT count(*)::int AS count FROM direct_conversation_pairs');assert.equal(mapping.rows[0]?.count,0);
    const rights=await db.query<{read:boolean;write:boolean;pairs:boolean}>("SELECT has_table_privilege('sobralis_runtime','conversation_messages','SELECT') AS read,has_table_privilege('sobralis_runtime','conversation_messages','INSERT') AS write,has_table_privilege('sobralis_runtime','direct_conversation_pairs','SELECT') AS pairs");
    assert.deepEqual(rights.rows[0],{read:false,write:false,pairs:false});
  });
});

test('community invitation upgrade preserves schedules and messages without direct privileges', async () => {
  const migrations=await readMigrations(join(process.cwd(),'migrations'));
  await inMemoryMigration(migrations,async(db,run)=>{
    await run(migrations.slice(0,12));
    const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('ci-old@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
    const c=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Test',$1) RETURNING id",[u])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[c,u]);
    await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2030-01-02','free')",[c,u]);
    const conversation=(await db.query<{id:string}>("INSERT INTO conversations(community_id,kind) VALUES($1,'direct') RETURNING id",[c])).rows[0]!.id;
    await db.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3)',[conversation,c,u]);
    await db.query("INSERT INTO conversation_messages(conversation_id,community_id,author_id,body) VALUES($1,$2,$3,'old message')",[conversation,c,u]);
    await run(migrations);await run(migrations);
    const row=await db.query<{status:string;body:string}>("SELECT s.status,m.body FROM schedule_entries s JOIN conversation_messages m ON m.community_id=s.community_id WHERE s.community_id=$1",[c]);
    assert.deepEqual(row.rows[0],{status:'free',body:'old message'});
    const rights=await db.query<{i:boolean;r:boolean}>("SELECT has_table_privilege('sobralis_runtime','community_invites','SELECT') AS i,has_table_privilege('sobralis_runtime','community_invite_redemptions','INSERT') AS r");
    assert.deepEqual(rights.rows[0],{i:false,r:false});
  });
});
test('schedule delegation migration preserves existing schedules and grants no direct table access', async () => {
  const migrations = await readMigrations(join(process.cwd(), 'migrations'));
  await inMemoryMigration(migrations, async (db, run) => {
    await run(migrations.slice(0,13));
    const user = (await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('deleg-upgrade@example.test','Owner',now()) RETURNING id")).rows[0]!.id;
    const community = (await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Preserved',$1) RETURNING id",[user])).rows[0]!.id;
    await db.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'owner','full')",[community,user]);
    await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2030-01-02','free')",[community,user]);
    await run(migrations);await run(migrations);
    const status = await db.query<{status:string}>('SELECT status FROM schedule_entries WHERE community_id=$1',[community]);
    assert.equal(status.rows[0]?.status,'free');
    const rights = await db.query<{read:boolean;write:boolean}>("SELECT has_table_privilege('sobralis_runtime','schedule_delegations','SELECT') read, has_table_privilege('sobralis_runtime','schedule_delegation_audit','INSERT') write");
    assert.deepEqual(rights.rows[0],{read:false,write:false});
  });
});
test('demo-only action rate budget remains bounded and cannot be enabled for production', async () => {
  const base={PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'z'.repeat(48)};
  const normal=await createApp({checkDatabase:async()=>{},security:{pool:{} as pg.Pool,config:readSecurityConfig(base,'test')}});
  const demo=await createApp({checkDatabase:async()=>{},security:{pool:{} as pg.Pool,config:readSecurityConfig({...base,DB_NAME:'sobralis_demo',DEMO_SHARED_ACTION_LIMIT:'true'},'development')}});
  try{
    const run=async(app:typeof normal)=>{let statuses:number[]=[];for(let i=0;i<11;i++)statuses.push((await app.inject({method:'POST',url:'/api/communities',headers:{origin:base.PUBLIC_ORIGIN},remoteAddress:'10.190.0.1',payload:{}})).statusCode);return statuses};
    assert.equal((await run(normal)).at(-1),429);
    assert.equal((await run(demo)).at(-1),401);
    assert.throws(()=>readSecurityConfig({...base,DB_NAME:'sobralis_demo',DEMO_SHARED_ACTION_LIMIT:'true'},'production'));
  }finally{await normal.close();await demo.close()}
});
test('invitation management upgrade preserves old data and never grants direct token access', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,14));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('inv-owner@test.invalid','Owner',now()),('inv-other@test.invalid','Editor',now()) RETURNING id");
  const [owner,editor]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Kept',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'editor')",[group,owner,editor]);
  const original=(await db.query<{id:string}>("INSERT INTO community_invites(community_id,created_by,token_hash,granted_role,max_uses,expires_at) VALUES($1,$2,$3,'editor',3,now()+interval '1 day') RETURNING id",[group,owner,'a'.repeat(64)])).rows[0]!.id;
  await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2030-01-02','free')",[group,owner]);
  await run(migrations);await run(migrations);
  const result=await db.query('SELECT * FROM public.list_community_invites_for_owner($1,$2,NULL)',[owner,group]);
  assert.equal(result.rows.length,1);assert.equal((result.rows[0] as {invite_id:string}).invite_id,original);
  assert.equal('token_hash' in result.rows[0]!,false);
  assert.equal((await db.query('SELECT * FROM public.list_community_invites_for_owner($1,$2,NULL)',[editor,group])).rows.length,0);
  assert.equal((await db.query('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows.length,1);
  const rights=await db.query<{read:boolean}>("SELECT has_table_privilege('sobralis_runtime','community_invites','SELECT') read");assert.equal(rights.rows[0]?.read,false);
 });
});
test('schedule range upgrade preserves preexisting data and narrows public grants', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,15));
  const owner=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('range-owner@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Range',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[group,owner]);
  await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2030-01-02','free')",[group,owner]);
  await run(migrations);await run(migrations);
  assert.equal((await db.query<{status:string}>('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows[0]?.status,'free');
  const rights=await db.query<{public_exec:boolean;runtime_exec:boolean}>("SELECT has_function_privilege('public','public.write_schedule_range(uuid,uuid,uuid,date,date,text)','EXECUTE') public_exec,has_function_privilege('sobralis_runtime','public.write_schedule_range(uuid,uuid,uuid,date,date,text)','EXECUTE') runtime_exec");
  assert.deepEqual(rights.rows[0],{public_exec:false,runtime_exec:true});
 });
});
test('trip invitation management upgrade retains existing data and hides token hashes', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,16));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('triplistowner@test.invalid','Owner',now()),('triplistviewer@test.invalid','Viewer',now()) RETURNING id");
  const [owner,viewer]=users.rows.map(x=>x.id),group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Retain',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const trip=(await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Saved trip',$2) RETURNING id",[group,owner])).rows[0]!.id;
  await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'viewer')",[trip,group,owner,viewer]);
  const inv=(await db.query<{id:string}>("INSERT INTO trip_invites(trip_id,community_id,created_by,token_hash,granted_role,max_uses,expires_at) VALUES($1,$2,$3,$4,'viewer',3,now()+interval '1 day') RETURNING id",[trip,group,owner,'b'.repeat(64)])).rows[0]!.id;
  await run(migrations);await run(migrations);
  const result=await db.query('SELECT * FROM public.list_trip_invites_for_owner($1,$2,NULL)',[owner,trip]);assert.equal(result.rows.length,1);assert.equal((result.rows[0] as {invite_id:string}).invite_id,inv);assert.equal('token_hash' in result.rows[0]!,false);
  assert.equal((await db.query('SELECT * FROM public.list_trip_invites_for_owner($1,$2,NULL)',[viewer,trip])).rows.length,0);
  const rights=await db.query<{read:boolean}>("SELECT has_table_privilege('sobralis_runtime','trip_invites','SELECT') read");assert.equal(rights.rows[0]?.read,false);
 });
});

test('host-consent upgrade preserves history, hides stale conditions and cannot revive consent after rejoining', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,17));
  const user=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('legacyhost@example.test','Host',now()) RETURNING id")).rows[0]!.id;
  const viewer=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('legacyviewer@example.test','Viewer',now()) RETURNING id")).rows[0]!.id;
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('History',$1) RETURNING id",[user])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,user,viewer]);
  const id=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone,venue_type,host_id,overnight,overnight_capacity,location) VALUES($1,$2,'Legacy',now(),'Europe/Moscow','home',$2,'yes',4,'Private address') RETURNING id",[group,user])).rows[0]!.id;
  const oldProposal=(await db.query<{proposal_id:string}>('SELECT * FROM propose_event_host($1,$2,$3)',[user,id,viewer])).rows[0]!.proposal_id;
  await run(migrations);await run(migrations);
  assert.equal((await db.query('SELECT * FROM get_pending_event_host($1,$2)',[user,id])).rows.length,0);
  assert.equal((await db.query<{result:string}>("SELECT respond_event_host($1,$2,$3,'accept',true) result",[viewer,id,oldProposal])).rows[0]!.result,'stale');
  const raw=(await db.query<{overnight:string;location:string}>('SELECT overnight,location FROM events WHERE id=$1',[id])).rows[0]!;assert.equal(raw.overnight,'yes');assert.equal(raw.location,'Private address');
  const masked=(await db.query<{overnight:string;location:string;overnight_capacity:number|null}>('SELECT overnight,overnight_capacity,location FROM get_event_for_member($1,$2)',[user,id])).rows[0]!;
  assert.deepEqual(masked,{overnight:'undecided',overnight_capacity:null,location:''});
  assert.equal((await db.query<{active:boolean}>('SELECT event_host_currently_active($1,$2) active',[user,id])).rows[0]!.active,false);
  const proposal=(await db.query<{proposal_id:string}>('SELECT * FROM propose_event_host($1,$2,$1)',[user,id])).rows[0]!.proposal_id;
  assert.equal((await db.query<{result:string}>("SELECT respond_event_host($1,$2,$3,'accept',true) result",[user,id,proposal])).rows[0]!.result,'accepted');
  assert.equal((await db.query<{active:boolean}>('SELECT event_host_currently_active($1,$2) active',[user,id])).rows[0]!.active,true);
  await db.query("SELECT set_event_host_conditions($1,$2,'yes',2)",[user,id]);
  await db.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,user]);
  await db.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[group,user]);
  assert.equal((await db.query<{active:boolean}>('SELECT event_host_currently_active($1,$2) active',[user,id])).rows[0]!.active,false);
  assert.equal((await db.query<{result:string}>("SELECT set_event_host_conditions($1,$2,'no',NULL) result",[user,id])).rows[0]!.result,'forbidden');
  const visible=(await db.query<{overnight:string}>("SELECT overnight FROM list_events_for_member($1,'community',$2,NULL)",[user,group])).rows[0]!;assert.equal(visible.overnight,'undecided');
  const access=(await db.query<{consents:boolean;proposals:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_host_consents','SELECT') consents,has_table_privilege('sobralis_runtime','event_host_proposal_generations','SELECT') proposals")).rows[0]!;
  assert.deepEqual(access,{consents:false,proposals:false});
 });
});

test('trip membership upgrade retains history, other trips and forbids owner removal', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,18));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('tripowner@example.test','Owner',now()),('tripguest@example.test','Guest',now()) RETURNING id");
  const [owner,guest]=users.rows.map(x=>x.id),group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,guest]);
  const trips=await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'One',$2),($1,'Two',$2) RETURNING id",[group,owner]);
  const [one,two]=trips.rows.map(x=>x.id);
  for(const id of [one,two])await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'viewer')",[id,group,owner,guest]);
  const event=(await db.query<{id:string}>("INSERT INTO events(community_id,trip_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,$3,'Keep event',now(),'Europe/Moscow') RETURNING id",[group,one,owner])).rows[0]!.id;
  await run(migrations);await run(migrations);
  assert.equal((await db.query('SELECT id FROM events WHERE id=$1',[event])).rows.length,1);
  assert.equal((await db.query<{result:string}>('SELECT remove_trip_member($1,$2,$1) result',[owner,one])).rows[0]!.result,'owner_restricted');
  assert.equal((await db.query<{result:string}>('SELECT remove_trip_member($1,$2,$3) result',[guest,one,owner])).rows[0]!.result,'not_found');
  assert.equal((await db.query<{result:string}>('SELECT remove_trip_member($1,$2,$3) result',[owner,one,guest])).rows[0]!.result,'removed');
  assert.equal((await db.query('SELECT * FROM trip_members WHERE trip_id=$1 AND user_id=$2 AND left_at IS NULL',[one,guest])).rows.length,0);
  assert.equal((await db.query('SELECT * FROM trip_members WHERE trip_id=$1 AND user_id=$2 AND left_at IS NULL',[two,guest])).rows.length,1);
  assert.equal((await db.query('SELECT * FROM community_members WHERE community_id=$1 AND user_id=$2 AND left_at IS NULL',[group,guest])).rows.length,1);
  assert.equal((await db.query('SELECT id FROM events WHERE id=$1',[event])).rows.length,1);
  assert.equal((await db.query<{canwrite:boolean}>("SELECT has_table_privilege('sobralis_runtime','trip_members','UPDATE') canwrite")).rows[0]!.canwrite,false);
 });
});

test('password recovery upgrade keeps existing data and narrows session issuance', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,20));
  const user=(await db.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('recovery-upgrade@example.test','Keep','$argon2id$old',now()) RETURNING id")).rows[0]!.id;
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep',$1) RETURNING id",[user])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[group,user]);
  await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2031-05-02','free')",[group,user]);
  await db.query("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 day')",[user,'a'.repeat(64)]);
  await run(migrations);await run(migrations);
  assert.equal((await db.query('SELECT id FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL',[user])).rows.length,1);
  assert.equal((await db.query('SELECT id FROM communities WHERE id=$1',[group])).rows.length,1);
  assert.equal((await db.query('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows.length,1);
  const rights=(await db.query<{read:boolean;insert:boolean;public_exec:boolean}>("SELECT has_table_privilege('sobralis_runtime','password_reset_tokens','SELECT') read,has_column_privilege('sobralis_runtime','user_sessions','user_id','INSERT') insert,has_function_privilege('public','public.consume_password_reset(text,text)','EXECUTE') public_exec")).rows[0];
  assert.deepEqual(rights,{read:false,insert:false,public_exec:false});
  assert.equal((await db.query<{issued:boolean}>('SELECT issue_password_reset($1,$2) issued',['recovery-upgrade@example.test','b'.repeat(64)])).rows[0]!.issued,true);
  assert.equal((await db.query<{changed:boolean}>('SELECT consume_password_reset($1,$2) changed',['b'.repeat(64),'$argon2id$new'])).rows[0]!.changed,true);
  assert.equal((await db.query('SELECT id FROM user_sessions WHERE user_id=$1 AND revoked_at IS NULL',[user])).rows.length,0);
  const generation=(await db.query<{recovery_generation:string}>('SELECT recovery_generation FROM users WHERE id=$1',[user])).rows[0]!.recovery_generation;
  assert.equal((await db.query<{issued:boolean}>('SELECT issue_verified_session($1,$2,$3,$4,$5,NULL) issued',[user,'recovery-upgrade@example.test',generation,'$argon2id$old','c'.repeat(64)])).rows[0]!.issued,false);
  assert.equal((await db.query('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows.length,1);
 });
});

test('recovery generation upgrade invalidates legacy links and cannot revive them', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,21));
  const user=(await db.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('generation@test.invalid','Test','$argon2id$old',now()) RETURNING id")).rows[0]!.id;
  assert.equal((await db.query<{issued:boolean}>('SELECT issue_password_reset($1,$2) issued',['generation@test.invalid','a'.repeat(64)])).rows[0]!.issued,true);
  await run(migrations);assert.equal((await db.query<{valid:boolean}>('SELECT check_password_reset($1) valid',['a'.repeat(64)])).rows[0]!.valid,false);
  await db.query("UPDATE password_reset_tokens SET created_at=now()-interval '11 minutes' WHERE user_id=$1",[user]);
  assert.equal((await db.query<{issued:boolean}>('SELECT issue_password_reset($1,$2) issued',['generation@test.invalid','b'.repeat(64)])).rows[0]!.issued,true);
  await db.query('UPDATE users SET email_verified_at=NULL WHERE id=$1',[user]);await db.query('UPDATE users SET email_verified_at=now() WHERE id=$1',[user]);
  assert.equal((await db.query<{valid:boolean}>('SELECT check_password_reset($1) valid',['b'.repeat(64)])).rows[0]!.valid,false);
  assert.equal((await db.query<{ok:boolean}>('SELECT consume_password_reset($1,$2) ok',['b'.repeat(64),'$argon2id$new'])).rows[0]!.ok,false);
 });
});

test('event cancellation upgrade preserves data and rejects stale revisions', async()=>{
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,23));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('cancelowner@test.invalid','Owner',now()),('cancelviewer@test.invalid','Viewer',now()),('canceloutsider@test.invalid','Other',now()) RETURNING id");const [owner,viewer,outsider]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep events',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const event=(await db.query<{id:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Keep',now(),'Europe/Moscow') RETURNING id",[group,owner])).rows[0]!.id;
  const poll=(await db.query<{id:string}>("INSERT INTO event_polls(event_id,community_id,question) VALUES($1,$2,'Keep vote') RETURNING id",[event,group])).rows[0]!.id;
  const msg=(await db.query<{id:string}>("INSERT INTO event_comments(event_id,community_id,author_id,client_message_id,body) VALUES($1,$2,$3,gen_random_uuid(),'Keep message') RETURNING id",[event,group,owner])).rows[0]!.id;
  await run(migrations);await run(migrations);
  let revision=(await db.query<{revision:string}>('SELECT revision FROM events WHERE id=$1',[event])).rows[0]!.revision;
  assert.equal((await db.query<{r:string}>('SELECT cancel_event_for_member($1,$2,$3) r',[outsider,event,revision])).rows[0]!.r,'not_found');
  assert.equal((await db.query<{r:string}>('SELECT cancel_event_for_member($1,$2,$3) r',[viewer,event,revision])).rows[0]!.r,'forbidden');
  await db.query("UPDATE events SET title='Modified' WHERE id=$1",[event]);assert.equal((await db.query<{r:string}>('SELECT cancel_event_for_member($1,$2,$3) r',[owner,event,revision])).rows[0]!.r,'conflict');
  revision=(await db.query<{revision:string}>('SELECT revision FROM events WHERE id=$1',[event])).rows[0]!.revision;
  assert.equal((await db.query<{r:string}>('SELECT cancel_event_for_member($1,$2,$3) r',[owner,event,revision])).rows[0]!.r,'cancelled');
  assert.equal((await db.query('SELECT * FROM get_event_for_member($1,$2)',[owner,event])).rows.length,0);
  assert.equal((await db.query('SELECT id FROM event_polls WHERE id=$1',[poll])).rows.length,1);assert.equal((await db.query('SELECT id FROM event_comments WHERE id=$1',[msg])).rows.length,1);
  assert.equal((await db.query<{r:string}>('SELECT cancel_event_for_member($1,$2,$3) r',[owner,event,revision])).rows[0]!.r,'not_found');
  const rights=(await db.query<{upd:boolean;pub:boolean}>("SELECT has_table_privilege('sobralis_runtime','events','UPDATE') upd,has_function_privilege('public','public.cancel_event_for_member(uuid,uuid,uuid)','EXECUTE') pub")).rows[0];assert.deepEqual(rights,{upd:false,pub:false});
 });
});

test('event editing upgrade preserves records and protects host consent', async()=>{
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,24));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('editowner@test.invalid','Owner',now()),('editviewer@test.invalid','Viewer',now()),('editoutsider@test.invalid','Other',now()) RETURNING id");const [owner,viewer,outsider]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep edits',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const event=(await db.query<{id:string;revision:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,'Keep','2030-01-02T12:00Z','Europe/Moscow') RETURNING id,revision",[group,owner])).rows[0]!;
  const comment=(await db.query<{id:string}>("INSERT INTO event_comments(event_id,community_id,author_id,client_message_id,body) VALUES($1,$2,$3,gen_random_uuid(),'Keep') RETURNING id",[event.id,group,owner])).rows[0]!.id;
  await run(migrations);await run(migrations);
  const edit=async(actor:string,revision:string,title='New',when='2030-01-03T12:00Z',zone='Europe/Moscow')=>(await db.query<{r:string}>('SELECT edit_event_for_member($1,$2,$3,$4,$5,$6) r',[actor,event.id,revision,title,when,zone])).rows[0]!.r;
  assert.equal(await edit(outsider!,event.revision),'not_found');assert.equal(await edit(viewer!,event.revision),'forbidden');
  assert.equal(await edit(owner!,event.revision,'','2030-01-02T12:00Z'),'invalid');assert.equal(await edit(owner!,event.revision,'New','2030-01-02T12:00Z','Invalid/Zone'),'invalid');
  assert.equal(await edit(owner!,event.revision),'updated');assert.equal(await edit(owner!,event.revision),'conflict');
  const updated=(await db.query<{title:string;revision:string}>('SELECT title,revision FROM events WHERE id=$1',[event.id])).rows[0]!;assert.equal(updated.title,'New');assert.notEqual(updated.revision,event.revision);assert.equal((await db.query('SELECT id FROM event_comments WHERE id=$1',[comment])).rows.length,1);
  await db.query("INSERT INTO event_host_proposals(event_id,proposed_by,proposed_host) VALUES($1,$2,$3)",[event.id,owner,viewer]);assert.equal(await edit(owner!,updated.revision,'Other'),'host_confirmation_required');
  await db.query("UPDATE event_host_proposals SET status='cancelled',responded_at=now() WHERE event_id=$1",[event.id]);
  await db.query("UPDATE events SET venue_type='home',host_id=$2 WHERE id=$1",[event.id,owner]);const home=(await db.query<{revision:string}>('SELECT revision FROM events WHERE id=$1',[event.id])).rows[0]!.revision;
  assert.equal(await edit(owner!,home,'Other'),'host_confirmation_required');
  const rights=(await db.query<{upd:boolean;pub:boolean}>("SELECT has_table_privilege('sobralis_runtime','events','UPDATE') upd,has_function_privilege('public','public.edit_event_for_member(uuid,uuid,uuid,text,timestamptz,text)','EXECUTE') pub")).rows[0];assert.deepEqual(rights,{upd:false,pub:false});
 });
});

test('host change consent upgrade preserves existing consent and requires explicit fresh agreement', async()=>{
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,25));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('consentowner@test.invalid','Owner',now()),('consentviewer@test.invalid','Viewer',now()) RETURNING id");const [owner,viewer]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep consent',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const event=(await db.query<{id:string;revision:string}>("INSERT INTO events(community_id,organizer_id,title,starts_at,timezone,venue_type,host_id,location) VALUES($1,$2,'Before','2030-01-02T12:00Z','Europe/Moscow','home',$2,'Keep address') RETURNING id,revision",[group,owner])).rows[0]!;
  const before=(await db.query('SELECT * FROM event_host_consents WHERE event_id=$1',[event.id])).rows[0];await run(migrations);await run(migrations);
  assert.deepEqual((await db.query('SELECT * FROM event_host_consents WHERE event_id=$1',[event.id])).rows[0],before);assert.equal((await db.query<{active:boolean}>('SELECT host_consent_valid($1) active',[event.id])).rows[0]!.active,true);
  const propose=(actor:string,revision:string)=>(db.query<{result:string;proposal_id:string}>('SELECT * FROM propose_event_change($1,$2,$3,$4,$5,$6)',[actor,event.id,revision,'After','2030-01-03T12:00Z','Europe/Moscow']));
  assert.equal((await propose(viewer!,event.revision)).rows[0]!.result,'forbidden');const p=(await propose(owner!,event.revision)).rows[0]!;assert.equal(p.result,'created');assert.equal((await db.query<{title:string}>('SELECT title FROM events WHERE id=$1',[event.id])).rows[0]!.title,'Before');
  assert.equal((await db.query<{r:string}>("SELECT respond_event_change($1,$2,$3,'accept') r",[viewer,event.id,p.proposal_id])).rows[0]!.r,'not_found');assert.equal((await db.query<{r:string}>("SELECT respond_event_change($1,$2,$3,'accept') r",[owner,event.id,p.proposal_id])).rows[0]!.r,'accepted');
  const after=(await db.query<{title:string;location:string}>('SELECT title,location FROM events WHERE id=$1',[event.id])).rows[0]!;assert.deepEqual(after,{title:'After',location:'Keep address'});assert.equal((await db.query<{active:boolean}>('SELECT host_consent_valid($1) active',[event.id])).rows[0]!.active,true);
  const rights=(await db.query<{direct:boolean;public_exec:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_change_proposals','SELECT') direct,has_function_privilege('public','public.respond_event_change(uuid,uuid,uuid,text)','EXECUTE') public_exec")).rows[0]!;assert.deepEqual(rights,{direct:false,public_exec:false});
 });
});

test('trip detail upgrade preserves existing trips and rejects unsafe direct edits',async()=>{
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,26));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('tripeditowner@test.invalid','Owner',now()),('tripeditviewer@test.invalid','Viewer',now()),('tripeditother@test.invalid','Other',now()) RETURNING id");const [owner,viewer,other]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep trip',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const trip=(await db.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Existing',$2) RETURNING id",[group,owner])).rows[0]!.id;
  await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'viewer')",[trip,group,owner,viewer]);
  const event=(await db.query<{id:string}>("INSERT INTO events(community_id,trip_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,$3,'Event','2030-01-02T12:00Z','Europe/Moscow') RETURNING id",[group,trip,owner])).rows[0]!.id;
  await run(migrations);await run(migrations);let row=(await db.query<{revision:string;title:string;starts_on:string|null}>('SELECT revision,title,starts_on FROM trips WHERE id=$1',[trip])).rows[0]!;assert.equal(row.title,'Existing');assert.equal(row.starts_on,null);
  const edit=async(actor:string,revision:string,title='Changed',start:string|null='2030-01-01',end:string|null='2030-01-05')=>(await db.query<{r:string}>('SELECT edit_trip_for_member($1,$2,$3,$4,$5,$6) r',[actor,trip,revision,title,start,end])).rows[0]!.r;
  assert.equal(await edit(other!,row.revision),'not_found');assert.equal(await edit(viewer!,row.revision),'forbidden');assert.equal(await edit(owner!,row.revision,'Changed','2030-01-04','2030-01-01'),'invalid');assert.equal(await edit(owner!,row.revision,'Changed','2030-01-01',null),'invalid');
  assert.equal(await edit(owner!,row.revision),'updated');assert.equal(await edit(owner!,row.revision),'conflict');row=(await db.query<{revision:string;title:string;starts_on:string|null}>('SELECT revision,title,starts_on::text FROM trips WHERE id=$1',[trip])).rows[0]!;assert.equal(row.title,'Changed');assert.equal(row.starts_on,'2030-01-01');assert.equal((await db.query('SELECT id FROM events WHERE id=$1',[event])).rows.length,1);
  const rights=(await db.query<{upd:boolean;old_exec:boolean;public_exec:boolean}>("SELECT has_table_privilege('sobralis_runtime','trips','UPDATE') upd,has_function_privilege('sobralis_runtime','public.rename_trip_for_member(uuid,uuid,text)','EXECUTE') old_exec,has_function_privilege('public','public.edit_trip_for_member(uuid,uuid,uuid,text,date,date)','EXECUTE') public_exec")).rows[0]!;assert.deepEqual(rights,{upd:false,old_exec:false,public_exec:false});
 });
});

test('trip cancellation upgrade retains history and prevents accidental restoration',async()=>{
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,27));
  const users=await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('tripcancelowner@test.invalid','Owner',now()),('tripcancelviewer@test.invalid','Viewer',now()),('tripcancelother@test.invalid','Other',now()) RETURNING id");const [owner,viewer,other]=users.rows.map(x=>x.id);
  const group=(await db.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Retain trip',$1) RETURNING id",[owner])).rows[0]!.id;
  await db.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'viewer')",[group,owner,viewer]);
  const trip=(await db.query<{id:string;revision:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Before cancellation',$2) RETURNING id,revision",[group,owner])).rows[0]!;
  await db.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'viewer')",[trip.id,group,owner,viewer]);
  const event=(await db.query<{id:string}>("INSERT INTO events(community_id,trip_id,organizer_id,title,starts_at,timezone) VALUES($1,$2,$3,'Keep event','2030-01-02T12:00Z','Europe/Moscow') RETURNING id",[group,trip.id,owner])).rows[0]!.id;
  await db.query("INSERT INTO trip_invites(trip_id,community_id,token_hash,created_by,granted_role,max_uses,expires_at) VALUES($1,$2,$3,$4,'viewer',3,now()+interval '7 days')",[trip.id,group,'a'.repeat(64),owner]);
  await run(migrations);await run(migrations);const cancel=async(actor:string,revision:string)=>(await db.query<{r:string}>('SELECT cancel_trip_for_owner($1,$2,$3) r',[actor,trip.id,revision])).rows[0]!.r;
  assert.equal(await cancel(other!,trip.revision),'not_found');assert.equal(await cancel(viewer!,trip.revision),'forbidden');await db.query("UPDATE trips SET title='Changed' WHERE id=$1",[trip.id]);assert.equal(await cancel(owner!,trip.revision),'conflict');
  const revision=(await db.query<{revision:string}>('SELECT revision FROM trips WHERE id=$1',[trip.id])).rows[0]!.revision;assert.equal(await cancel(owner!,revision),'cancelled');assert.equal(await cancel(owner!,revision),'not_found');
  assert.equal((await db.query('SELECT * FROM get_event_for_member($1,$2)',[owner,event])).rows.length,0);assert.equal((await db.query('SELECT * FROM preview_trip_invite($1)',['a'.repeat(64)])).rows.length,0);
  assert.equal((await db.query('SELECT id FROM events WHERE id=$1',[event])).rows.length,1);assert.equal((await db.query('SELECT id FROM trip_invites WHERE trip_id=$1',[trip.id])).rows.length,1);assert.equal((await db.query('SELECT user_id FROM trip_members WHERE trip_id=$1',[trip.id])).rows.length,2);
  await assert.rejects(()=>db.query('UPDATE trips SET deleted_at=NULL WHERE id=$1',[trip.id]),/cannot be restored/);await assert.rejects(()=>db.query('UPDATE trips SET deleted_at=NULL,cancelled_by_app=false WHERE id=$1',[trip.id]),/cannot be restored/);
  const rights=(await db.query<{upd:boolean;table_read:boolean;public_exec:boolean}>("SELECT has_table_privilege('sobralis_runtime','trips','UPDATE') upd,has_table_privilege('sobralis_runtime','trip_cancellations','SELECT') table_read,has_function_privilege('public','public.cancel_trip_for_owner(uuid,uuid,uuid)','EXECUTE') public_exec")).rows[0]!;assert.deepEqual(rights,{upd:false,table_read:false,public_exec:false});
 });
});

test('community creation retry migration preserves data and deduplicates scoped requests', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,28));
  const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('once-upgrade@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
  const original=(await db.query<{id:string}>("SELECT id FROM create_community_for_owner('Existing',$1)",[u])).rows[0]!.id;
  await db.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2033-01-01','free')",[original,u]);
  await run(migrations);await run(migrations);
  const key='11111111-1111-4111-8111-111111111111';
  const first=(await db.query<{status:string;id:string;role:string}>("SELECT * FROM create_community_once($1,$2,'Once')",[u,key])).rows[0]!;
  const again=(await db.query<{status:string;id:string;role:string}>("SELECT * FROM create_community_once($1,$2,'Once')",[u,key])).rows[0]!;
  assert.equal(first.status,'ok');assert.equal(first.role,'owner');assert.equal(first.id,again.id);
  assert.equal((await db.query<{status:string}>("SELECT status FROM create_community_once($1,$2,'Different')",[u,key])).rows[0]!.status,'conflict');
  assert.equal((await db.query("SELECT * FROM schedule_entries WHERE community_id=$1",[original])).rows.length,1);
  assert.equal((await db.query<{has:boolean}>("SELECT has_table_privilege('sobralis_runtime','community_creation_requests','SELECT') has")).rows[0]!.has,false);
  await db.query("UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2",[first.id,u]);
  assert.equal((await db.query<{status:string}>("SELECT status FROM create_community_once($1,$2,'Once')",[u,key])).rows[0]!.status,'unavailable');
 });
});


test('trip creation retry migration retains prior data and restricts replay', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,29));
  const u=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('trip-once-upgrade@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
  const group=(await db.query<{id:string}>("SELECT id FROM create_community_for_owner('Existing',$1)",[u])).rows[0]!.id;
  const old=(await db.query<{trip_id:string}>("SELECT * FROM create_trip_for_member($1,$2,'Existing trip','Europe/Moscow')",[group,u])).rows[0]!.trip_id;
  await run(migrations);await run(migrations);
  const key='22222222-2222-4222-8222-222222222222';
  const q="SELECT * FROM create_trip_once($1,$2,$3,'New trip','Europe/Moscow')";
  const first=(await db.query<{result:string;trip_id:string;role:string}>(q,[group,u,key])).rows[0]!;
  const again=(await db.query<{result:string;trip_id:string}>(q,[group,u,key])).rows[0]!;
  assert.equal(first.result,'created');assert.equal(first.role,'owner');assert.equal(first.trip_id,again.trip_id);
  assert.equal((await db.query<{result:string}>("SELECT * FROM create_trip_once($1,$2,$3,'Changed','Europe/Moscow')",[group,u,key])).rows[0]!.result,'conflict');
  assert.equal((await db.query("SELECT id FROM trips WHERE id=$1",[old])).rows.length,1);
  assert.equal((await db.query<{has:boolean}>("SELECT has_table_privilege('sobralis_runtime','trip_creation_requests','SELECT') has")).rows[0]!.has,false);
  await db.query("UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2",[group,u]);
  assert.equal((await db.query<{result:string}>(q,[group,u,key])).rows[0]!.result,'not_found');
 });
});

test('runtime schema check migration preserves data and exposes only fingerprints', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,30));
  const user=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('readiness@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
  const original=(await db.query<{id:string}>("SELECT id FROM create_community_for_owner('Before readiness',$1)",[user])).rows[0]!.id;
  await run(migrations);await run(migrations);
  const fingerprints=await db.query<{name:string;checksum:string}>('SELECT * FROM public.runtime_schema_state()');
  assert.deepEqual(fingerprints.rows,migrations.map(({name,checksum})=>({name,checksum})));
  assert.equal((await db.query('SELECT id FROM communities WHERE id=$1',[original])).rows.length,1);
  assert.equal((await db.query<{has:boolean}>("SELECT has_table_privilege('sobralis_runtime','schema_migrations','SELECT') has")).rows[0]!.has,false);
  assert.equal((await db.query<{has:boolean}>("SELECT has_function_privilege('sobralis_runtime','public.runtime_schema_state()','EXECUTE') has")).rows[0]!.has,true);
  assert.equal((await db.query<{has:boolean}>("SELECT has_function_privilege('public','public.runtime_schema_state()','EXECUTE') has")).rows[0]!.has,false);
 });
});


test('event creation retry migration retains existing events and hides its ledger', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,31));
  const actor=(await db.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('event-once-upgrade@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
  const group=(await db.query<{id:string}>("SELECT id FROM create_community_for_owner('Existing',$1)",[actor])).rows[0]!.id;
  const old=(await db.query<{event:{id:string}}>("SELECT * FROM create_event_for_member($1,'community',$2,'Old event','','','2035-05-05T12:00:00Z','Europe/Moscow','other','undecided',NULL,'undecided','undecided','')",[actor,group])).rows[0]!.event.id;
  await run(migrations);await run(migrations);
  const key='33333333-3333-4333-8333-333333333333',q="SELECT * FROM create_event_once($1,$2,'community',$3,'New event','','','2035-05-05T12:00:00Z','Europe/Moscow','other','undecided',NULL,'undecided','undecided','')";
  const first=(await db.query<{result:string;event:{id:string}}>(q,[actor,key,group])).rows[0]!,again=(await db.query<{result:string;event:{id:string}}>(q,[actor,key,group])).rows[0]!;
  assert.equal(first.result,'created');assert.equal(first.event.id,again.event.id);assert.equal((await db.query('SELECT id FROM events WHERE id=$1',[old])).rows.length,1);
  assert.equal((await db.query<{has:boolean}>("SELECT has_table_privilege('sobralis_runtime','event_creation_requests','SELECT') has")).rows[0]!.has,false);
  assert.equal((await db.query<{has:boolean}>("SELECT has_function_privilege('public','public.create_event_once(uuid,uuid,text,uuid,text,text,text,timestamptz,text,text,text,integer,text,text,text)','EXECUTE') has")).rows[0]!.has,false);
  await db.query('UPDATE events SET deleted_at=now() WHERE id=$1',[first.event.id]);assert.equal((await db.query<{result:string}>(q,[actor,key,group])).rows[0]!.result,'not_found');
 });
});

test('session revocation migration preserves pre-existing sessions and recovery links', async () => {
 const migrations=await readMigrations(join(process.cwd(),'migrations'));
 await inMemoryMigration(migrations,async(db,run)=>{
  await run(migrations.slice(0,32));
  const user=(await db.query<{id:string;recovery_generation:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('session-upgrade@example.test','Synthetic','$argon2id$synthetic',now()) RETURNING id,recovery_generation")).rows[0]!;
  const token='a'.repeat(64),reset='b'.repeat(64);
  await db.query("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",[user.id,token]);
  assert.equal((await db.query<{issued:boolean}>('SELECT public.issue_password_reset($1,$2) issued',['session-upgrade@example.test',reset])).rows[0]!.issued,true);
  await run(migrations);await run(migrations);
  assert.equal((await db.query<{recovery_generation:string}>('SELECT recovery_generation FROM users WHERE id=$1',[user.id])).rows[0]!.recovery_generation,user.recovery_generation);
  assert.equal((await db.query<{revoked_at:null}>('SELECT revoked_at FROM user_sessions WHERE token_hash=$1',[token])).rows[0]!.revoked_at,null);
  assert.equal((await db.query<{valid:boolean}>('SELECT public.check_password_reset($1) valid',[reset])).rows[0]!.valid,true);
  assert.equal((await db.query<{has:boolean}>("SELECT has_function_privilege('public','public.revoke_other_sessions(uuid,text,text,uuid)','EXECUTE') has")).rows[0]!.has,false);
  assert.equal((await db.query<{has:boolean}>("SELECT has_function_privilege('sobralis_runtime','public.revoke_other_sessions(uuid,text,text,uuid)','EXECUTE') has")).rows[0]!.has,true);
 });
});
