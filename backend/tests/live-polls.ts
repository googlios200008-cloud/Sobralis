// Explicitly opt-in and disposable data only.
import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-polls-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST'|'PUT',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try{
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','tripeditor','tripviewer','left'].map(x=>`poll-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$8,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6,$7]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.50.0.${i+1}`));
 const [owner,editor,viewer,outsider,tripeditor,tripviewer,left]=sessions as [Session,Session,Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'viewer','trip_only',NULL),($1,$7,'editor','full',now())`,[group,ids[0],ids[1],ids[2],ids[4],ids[5],ids[6]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Trip',$2) RETURNING id",[group,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor'),($1,$2,$5,'viewer')",[trip,group,ids[0],ids[4],ids[5]]);
 const ce=await req('POST',`/api/communities/${group}/events`,owner,{title:'Community',startsAt:'2027-01-02T15:00:00Z'});assert.equal(ce.statusCode,201,ce.body);const event=ce.json().event.id,ep=`/api/events/${event}/polls`;
 const te=await req('POST',`/api/trips/${trip}/events`,owner,{title:'Trip',startsAt:'2027-01-02T15:00:00Z'});assert.equal(te.statusCode,201,te.body);const tripEvent=te.json().event.id,tp=`/api/events/${tripEvent}/polls`;
 const body={question:'Что будем есть?',options:['Пицца','Роллы','Шашлык']};
 assert.equal((await app.inject({method:'POST',url:ep,headers:origin,payload:body})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:ep,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload:body})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:ep,headers:{...origin,cookie:owner.cookie},payload:body})).statusCode,403);
 assert.equal((await req('POST',ep,viewer,body)).statusCode,403);
 for(const s of [outsider,tripeditor,tripviewer,left])assert.equal((await req('POST',ep,s,body)).statusCode,404);
 for(const bad of [{...body,options:['one']},{...body,options:Array.from({length:11},(_,i)=>`v${i}`)},{...body,options:['one',' ONE ']},{...body,options:['one','']},{...body,question:' '},{...body,question:'bad\0text'},{...body,userId:ids[1]}])assert.equal((await req('POST',ep,owner,bad)).statusCode,400);
 const made=await req('POST',ep,owner,body);assert.equal(made.statusCode,201,made.body);const poll=made.json().pollId,vote=`/api/polls/${poll}/vote`;
 const tripMade=await req('POST',tp,tripeditor,{question:'Ночёвка?',options:['Да','Нет']});assert.equal(tripMade.statusCode,201,tripMade.body);const tripPoll=tripMade.json().pollId;
 assert.equal((await req('GET',ep,outsider)).statusCode,404);assert.equal((await req('GET',ep,tripeditor)).statusCode,404);
 assert.equal((await req('GET',tp,viewer)).statusCode,404);assert.equal((await req('GET',tp,tripviewer)).statusCode,200);
 let list=await req('GET',ep,viewer);assert.equal(list.statusCode,200,list.body);assert.equal(list.headers['cache-control'],'no-store');let p=list.json().polls[0];assert.equal(p.question,body.question);assert.deepEqual(p.options.map((o:{label:string})=>o.label),body.options);assert.deepEqual(p.options.map((o:{votes:number})=>o.votes),[0,0,0]);assert.equal(p.my_option_id,null);
 const [a,b,c]=p.options.map((o:{id:string})=>o.id) as [string,string,string];
 assert.equal((await req('PUT',vote,viewer,{optionId:a})).statusCode,403);
 for(const s of [outsider,tripeditor,tripviewer,left])assert.equal((await req('PUT',vote,s,{optionId:a})).statusCode,404);
 assert.equal((await req('PUT',vote,owner,{optionId:a,userId:ids[1]})).statusCode,400);
 const tripOption=(await req('GET',tp,tripeditor)).json().polls[0].options[0].id;
 assert.equal((await req('PUT',vote,owner,{optionId:tripOption})).statusCode,400);
 assert.equal((await req('PUT',`/api/polls/${tripPoll}/vote`,tripviewer,{optionId:tripOption})).statusCode,403);
 assert.equal((await req('PUT',`/api/polls/${tripPoll}/vote`,tripeditor,{optionId:tripOption})).statusCode,200);
 const v1=await req('PUT',vote,owner,{optionId:a});assert.equal(v1.statusCode,200,v1.body);assert.equal(v1.headers['cache-control'],'no-store');
 assert.equal((await req('PUT',vote,editor,{optionId:a})).statusCode,200);
 p=(await req('GET',ep,owner)).json().polls[0];assert.deepEqual(p.options.map((o:{votes:number})=>o.votes),[2,0,0]);assert.equal(p.my_option_id,a);assert.deepEqual(new Set(p.options[0].voters.map((v:{id:string})=>v.id)),new Set([ids[0],ids[1]]));assert.ok(p.options[0].voters.every((v:Record<string,unknown>)=>Object.keys(v).sort().join(',')==='displayName,id'));assert.doesNotMatch(JSON.stringify(p),/@example/);
 assert.equal((await req('PUT',vote,owner,{optionId:b})).statusCode,200);p=(await req('GET',ep,editor)).json().polls[0];assert.deepEqual(p.options.map((o:{votes:number})=>o.votes),[1,1,0]);assert.equal(p.my_option_id,a);
 assert.equal((await req('PUT',vote,editor,{optionId:null})).statusCode,200);assert.equal((await req('PUT',vote,editor,{optionId:null})).statusCode,200);
 p=(await req('GET',ep,editor)).json().polls[0];assert.deepEqual(p.options.map((o:{votes:number})=>o.votes),[0,1,0]);assert.equal(p.my_option_id,null);
 // Concurrent votes remain a single choice per actor.
 const race=await Promise.all([req('PUT',vote,owner,{optionId:a}),req('PUT',vote,owner,{optionId:c})]);assert.ok(race.every(r=>r.statusCode===200));
 const persisted=await admin.query<{count:string}>("SELECT count(*) FROM event_poll_votes WHERE poll_id=$1 AND user_id=$2",[poll,ids[0]]);assert.equal(Number(persisted.rows[0]!.count),1);
 p=(await req('GET',ep,owner)).json().polls[0];assert.equal(p.options.reduce((n:number,o:{votes:number})=>n+o.votes,0),1);assert.ok([a,c].includes(p.my_option_id));
 await assert.rejects(()=>pool.query('SELECT * FROM event_poll_votes'));await assert.rejects(()=>pool.query('SELECT * FROM event_polls'));await assert.rejects(()=>pool.query('SELECT * FROM event_poll_options'));
 // Leaving suppresses a retained vote from counts until re-entry.
 assert.equal((await req('PUT',vote,editor,{optionId:a})).statusCode,200);
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
 p=(await req('GET',ep,owner)).json().polls[0];assert.equal(p.options.reduce((n:number,o:{votes:number})=>n+o.votes,0),1);assert.equal((await req('GET',ep,editor)).statusCode,404);
 await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
 p=(await req('GET',ep,owner)).json().polls[0];assert.equal(p.options.reduce((n:number,o:{votes:number})=>n+o.votes,0),2);
 await admin.query(`INSERT INTO event_polls(event_id,community_id,question) SELECT $1,$2,'Bulk '||n FROM generate_series(1,52) n`,[event,group]);
 let cursor:string|null=null;const all:string[]=[];let pages=0;do{const r=await req('GET',ep+(cursor?`?cursor=${cursor}`:''),viewer);assert.equal(r.statusCode,200,r.body);all.push(...r.json().polls.map((x:{id:string})=>x.id));cursor=r.json().nextCursor;pages++;assert.ok(pages<4);}while(cursor);
 assert.equal(all.length,53);assert.equal(new Set(all).size,53);assert.equal(pages,2);
 // Removal under an open transaction must win before vote authorization.
 const block=await admin.connect();let committed=false;try{await block.query('BEGIN');await block.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
  const pending=req('PUT',vote,editor,{optionId:b});await new Promise(resolve=>setTimeout(resolve,100));await block.query('COMMIT');committed=true;assert.equal((await pending).statusCode,404);
 }finally{if(!committed)await block.query('ROLLBACK');block.release()}
 // Bound returned voter names while retaining the full count.
 await admin.query(`WITH people AS (
   INSERT INTO users(email,display_name,email_verified_at)
   SELECT 'bulk-'||n||'-'||$1||'@example.test','Bulk participant',now() FROM generate_series(1,51) n RETURNING id
 ), members AS (
   INSERT INTO community_members(community_id,user_id,role)
   SELECT $2,id,'editor' FROM people RETURNING user_id
 ) INSERT INTO event_poll_votes(poll_id,community_id,user_id,option_id)
   SELECT $3,$2,user_id,$4 FROM members`,[suffix,group,poll,a]);
 const bulkPage=await req('GET',ep,owner);assert.equal(bulkPage.statusCode,200);
 // UUID pagination can place the target poll on either page.
 let bigPoll=bulkPage.json().polls.find((x:{id:string})=>x.id===poll);
 if(!bigPoll){const next=await req('GET',ep+`?cursor=${bulkPage.json().nextCursor}`,owner);bigPoll=next.json().polls.find((x:{id:string})=>x.id===poll);}
 const bulkOption=bigPoll.options.find((x:{id:string})=>x.id===a);assert.ok(bulkOption.votes>=51);assert.equal(bulkOption.voters.length,50);assert.equal(bulkOption.votersTruncated,true);
 await admin.query('UPDATE event_polls SET deleted_at=now() WHERE id=$1',[tripPoll]);assert.equal((await req('PUT',`/api/polls/${tripPoll}/vote`,tripeditor,{optionId:tripOption})).statusCode,404);
 assert.equal((await req('GET',tp,tripeditor)).json().polls.length,0);
 await admin.query('UPDATE events SET deleted_at=now() WHERE id=$1',[event]);assert.equal((await req('GET',ep,owner)).statusCode,404);assert.equal((await req('PUT',vote,owner,{optionId:a})).statusCode,404);
 console.log('Live poll creation, scoped privacy, votes, pagination and concurrent revocation passed');
}finally{await app.close();await pool.end();await admin.end()}
