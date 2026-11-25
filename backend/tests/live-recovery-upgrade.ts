// This changes the target database. It requires a specifically named EMPTY,
// disposable database, test credentials and an explicit opt-in. Never use it
// against the demo or real user databases.
import assert from 'node:assert/strict';import {join} from 'node:path';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';import {readMigrations,applyMigrations} from '../src/migration-lib.js';import {createApp} from '../src/app.js';import {hashToken} from '../src/security.js';
if(process.env.DB_NAME!=='sobralis_recovery_upgrade_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_RUNTIME_PASSWORD)throw Error('Requires explicitly opted-in EMPTY sobralis_recovery_upgrade_test');
const cfg=readConfig(process.env),migrator=createPool(cfg),runtime=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_runtime',password:process.env.TEST_RUNTIME_PASSWORD});
const migrations=await readMigrations(join(process.cwd(),'migrations')),client=await migrator.connect(),old='Synthetic-upgrade-old-password',next='Synthetic-upgrade-new-password';
try{
 const tables=await client.query<{n:string}>("SELECT count(*)::text n FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')");if(tables.rows[0]?.n!=='0')throw Error('Upgrade database must be empty');
 await applyMigrations(client,migrations.slice(0,20));
 const hash=await argon2.hash(old,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const user=(await client.query<{id:string}>("INSERT INTO users(email,display_name,password_hash,email_verified_at) VALUES('synthetic-upgrade@example.test','Keep user',$1,now()) RETURNING id",[hash])).rows[0]!.id;
 const group=(await client.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Keep group',$1) RETURNING id",[user])).rows[0]!.id;
 await client.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[group,user]);await client.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2033-06-02','busy')",[group,user]);
 const trip=(await client.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Keep trip',$2) RETURNING id",[group,user])).rows[0]!.id;await client.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner')",[trip,group,user]);
 const session=randomBytes(32).toString('base64url');await client.query("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",[user,hashToken(session)]);
 await applyMigrations(client,migrations);await applyMigrations(client,migrations);
 assert.equal((await client.query('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows[0].status,'busy');assert.equal((await client.query('SELECT title FROM trips WHERE id=$1',[trip])).rows[0].title,'Keep trip');assert.equal((await client.query('SELECT count(*)::int n FROM schema_migrations')).rows[0].n,29);
 let resetLink='';const mailer={async sendVerification(){},async sendPasswordReset(_to:string,link:string){resetLink=link}},security=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5),PASSWORD_RESET_ENABLED:'true'},'test');
 const app=await createApp({checkDatabase:async()=>{},security:{pool:runtime,config:security,mailer}}),cookie=`__Host-sobralis_session=${session}`;
 try{
  assert.equal((await app.inject({method:'GET',url:'/api/auth/me',headers:{cookie}})).statusCode,200);
  const login=await app.inject({method:'POST',url:'/api/auth/login',headers:{origin:'https://test.invalid'},payload:{email:'synthetic-upgrade@example.test',password:old}});assert.equal(login.statusCode,200);
  const requested=await app.inject({method:'POST',url:'/api/auth/request-password-reset',headers:{origin:'https://test.invalid'},payload:{email:'synthetic-upgrade@example.test'}});assert.equal(requested.statusCode,202);assert.ok(resetLink);
  const changed=await app.inject({method:'POST',url:'/api/auth/reset-password',headers:{origin:'https://test.invalid'},payload:{token:new URL(resetLink).hash.slice(1),password:next}});assert.equal(changed.statusCode,200);
  assert.equal((await app.inject({method:'GET',url:'/api/auth/me',headers:{cookie}})).statusCode,401);assert.equal((await client.query('SELECT status FROM schedule_entries WHERE community_id=$1',[group])).rows[0].status,'busy');assert.equal((await client.query('SELECT title FROM trips WHERE id=$1',[trip])).rows[0].title,'Keep trip');
 }finally{await app.close()}
 console.log('Recovery upgrade from schema 20: old data/session preserved, login and reset verified');
}finally{client.release();await migrator.end();await runtime.end()}
