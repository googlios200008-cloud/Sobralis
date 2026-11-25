// Tests an incremental 0012 -> 0013 migration against an EMPTY disposable PostgreSQL database.
import assert from 'node:assert/strict';import pg from 'pg';import {join} from 'node:path';import {readMigrations,applyMigrations} from '../src/migration-lib.js';
if(process.env.RUN_LIVE_AUTH_TEST!=='yes'||process.env.DB_NAME!=='sobralis_upgrade_test'||!process.env.TEST_ADMIN_PASSWORD||!process.env.TEST_MIGRATOR_PASSWORD)throw Error('Requires empty disposable sobralis_upgrade_test and explicit opt-in');
const connection={host:process.env.DB_HOST,port:Number(process.env.DB_PORT),database:process.env.DB_NAME};
const admin=new pg.Pool({...connection,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD}),migrator=new pg.Pool({...connection,user:'sobralis_migrator',password:process.env.TEST_MIGRATOR_PASSWORD});
try{const has=(await admin.query<{t:string|null}>("SELECT to_regclass('public.schema_migrations')::text t")).rows[0]?.t;if(has)throw Error('Database must be empty');
 const ms=await readMigrations(join(process.cwd(),'migrations')),client=await migrator.connect();try{
 await applyMigrations(client,ms.slice(0,12));
 const user=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES('upgrade@test.invalid','Owner',now()) RETURNING id")).rows[0]!.id;
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Upgrade',$1) RETURNING id",[user])).rows[0]!.id;
 await admin.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'owner')",[group,user]);
 await admin.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) VALUES($1,$2,'2030-01-02','free')",[group,user]);
 const conv=(await admin.query<{id:string}>("INSERT INTO conversations(community_id,kind) VALUES($1,'direct') RETURNING id",[group])).rows[0]!.id;
 await admin.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3)',[conv,group,user]);
 await admin.query("INSERT INTO conversation_messages(conversation_id,community_id,author_id,body) VALUES($1,$2,$3,'preserved')",[conv,group,user]);
 await applyMigrations(client,ms);await applyMigrations(client,ms);
 const row=await admin.query<{status:string;body:string}>("SELECT s.status,m.body FROM schedule_entries s JOIN conversation_messages m ON m.community_id=s.community_id WHERE s.community_id=$1",[group]);assert.deepEqual(row.rows[0],{status:'free',body:'preserved'});
 const rights=await admin.query<{read:boolean;write:boolean}>("SELECT has_table_privilege('sobralis_runtime','community_invites','SELECT') read,has_table_privilege('sobralis_runtime','community_invite_redemptions','INSERT') write");assert.deepEqual(rights.rows[0],{read:false,write:false});
 console.log('PostgreSQL 0012 to 0013 upgrade preserved schedules and messages; direct grants denied');
 }finally{client.release()}
}finally{await admin.end();await migrator.end()}
