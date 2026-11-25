// Disposable demo only. A transaction avoids partial seeding; never modify a nonempty DB.
import pg from 'pg';
import argon2 from 'argon2';
if(process.env.ALLOW_DEMO_SEED!=='yes'||process.env.DB_NAME!=='sobralis_demo'||!process.env.TEST_ADMIN_PASSWORD)throw Error('Disposable demo database and explicit opt-in required');
const pool=new pg.Pool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT),database:'sobralis_demo',user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
try{
 const client=await pool.connect();try{
  await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock($1)',[184093103]);
  const count=await client.query<{n:string}>('SELECT count(*)::text n FROM users');
  if(count.rows[0]?.n!=='0'){await client.query('COMMIT');console.log('Demo database already contains users; no data changed');}
  else{
   const password=await argon2.hash('DemoPassword2026!',{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
   const users=await client.query<{id:string}>("INSERT INTO users(email,password_hash,display_name,email_verified_at) VALUES('anna@example.test',$1,'Анна',now()),('max@example.test',$1,'Макс',now()) RETURNING id",[password]);
   const [a,b]=users.rows.map(x=>x.id),g=(await client.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Наши люди',$1) RETURNING id",[a])).rows[0]!.id;
   await client.query("INSERT INTO community_members(community_id,user_id,role,membership_scope) VALUES($1,$2,'owner','full'),($1,$3,'editor','full')",[g,a,b]);
   await client.query("INSERT INTO schedule_entries(community_id,user_id,local_date,status) SELECT $1,u,d::date,'free' FROM unnest(ARRAY[$2,$3]::uuid[]) u CROSS JOIN generate_series(current_date,current_date+interval '28 days',interval '1 day') d WHERE extract(isodow from d) IN (6,7)",[g,a,b]);
   await client.query('COMMIT');console.log('Seeded disposable synthetic demo');
  }
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}finally{await pool.end()}
