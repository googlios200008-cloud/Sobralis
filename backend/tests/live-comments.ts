// Opt-in test against disposable PostgreSQL only.
import assert from 'node:assert/strict';import {randomBytes,randomUUID} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-comments-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try {
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','tripeditor','tripviewer','left'].map(x=>`comment-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$8,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6,$7]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.60.0.${i+1}`));
 const [owner,editor,viewer,outsider,tripeditor,tripviewer,left]=sessions as [Session,Session,Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'viewer','trip_only',NULL),($1,$7,'editor','full',now())`,[group,ids[0],ids[1],ids[2],ids[4],ids[5],ids[6]]);
 const trip=(await admin.query<{id:string}>("INSERT INTO trips(community_id,title,created_by) VALUES($1,'Trip',$2) RETURNING id",[group,ids[0]])).rows[0]!.id;
 await admin.query("INSERT INTO trip_members(trip_id,community_id,user_id,role) VALUES($1,$2,$3,'owner'),($1,$2,$4,'editor'),($1,$2,$5,'viewer')",[trip,group,ids[0],ids[4],ids[5]]);
 const ce=await req('POST',`/api/communities/${group}/events`,owner,{title:'Community',startsAt:'2027-01-02T15:00:00Z'});assert.equal(ce.statusCode,201,ce.body);const event=ce.json().event.id,ep=`/api/events/${event}/comments`;
 const te=await req('POST',`/api/trips/${trip}/events`,owner,{title:'Trip',startsAt:'2027-01-02T15:00:00Z'});assert.equal(te.statusCode,201,te.body);const tripEvent=te.json().event.id,tp=`/api/events/${tripEvent}/comments`;
 const message={clientMessageId:randomUUID(),text:'Привет, друзья!'};
 assert.equal((await app.inject({method:'POST',url:ep,headers:origin,payload:message})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:ep,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload:message})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:ep,headers:{...origin,cookie:owner.cookie},payload:message})).statusCode,403);
 assert.equal((await req('POST',ep,viewer,message)).statusCode,403);
 for(const s of [outsider,tripeditor,tripviewer,left])assert.equal((await req('POST',ep,s,message)).statusCode,404);
 for(const bad of [{...message,authorId:ids[1]},{...message,clientMessageId:'wrong'},{...message,text:'  '},{...message,text:'bad\0text'},{...message,text:'x'.repeat(5001)}])assert.equal((await req('POST',ep,owner,bad)).statusCode,400);
 const concurrent=await Promise.all([req('POST',ep,owner,message),req('POST',ep,owner,message)]);
 assert.deepEqual(concurrent.map(r=>r.statusCode).sort(),[200,201]);assert.equal(concurrent[0]!.json().commentId,concurrent[1]!.json().commentId);const comment=concurrent[0]!.json().commentId;
 assert.equal((await req('POST',ep,owner,{...message,text:'Different text'})).statusCode,409);
 const another=await req('POST',ep,editor,{...message,text:'Это мой комментарий'});assert.equal(another.statusCode,201);const editorComment=another.json().commentId;
 const scoped=await req('POST',tp,tripeditor,{clientMessageId:randomUUID(),text:'Только поездке'});assert.equal(scoped.statusCode,201,scoped.body);const tripComment=scoped.json().commentId;
 assert.equal((await req('GET',ep,outsider)).statusCode,404);assert.equal((await req('GET',ep,tripviewer)).statusCode,404);
 assert.equal((await req('GET',tp,viewer)).statusCode,404);assert.equal((await req('GET',tp,tripviewer)).statusCode,200);
 assert.equal((await req('POST',tp,tripviewer,{clientMessageId:randomUUID(),text:'no'})).statusCode,403);
 let read=await req('GET',ep,viewer);assert.equal(read.statusCode,200,read.body);assert.equal(read.headers['cache-control'],'no-store');
 assert.equal(read.json().comments.length,2);assert.equal(read.json().comments[0].id,comment);assert.deepEqual(read.json().comments[0].author,{id:ids[0],displayName:'Test'});
 assert.equal(read.json().comments[0].body,message.text);assert.equal(read.json().comments[0].createdAt.endsWith('Z'),true);assert.equal(read.json().nextCursor,editorComment);assert.equal(read.json().hasMore,false);assert.doesNotMatch(read.body,/@example|clientMessageId|"seq"/);
 assert.equal((await req('GET',`${ep}?after=${tripComment}`,owner)).statusCode,400);
 assert.equal((await req('GET',`${ep}?after=${randomUUID()}`,owner)).statusCode,400);
 assert.equal((await req('DELETE',`${ep}/${editorComment}`,owner,{})).statusCode,403);
 assert.equal((await req('DELETE',`${ep}/${comment}`,outsider,{})).statusCode,404);
 await assert.rejects(()=>pool.query('SELECT * FROM event_comments'));await assert.rejects(()=>pool.query('SELECT * FROM conversation_messages'));
 // Downgraded viewer may remove their own earlier contribution but not add one.
 await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 assert.equal((await req('POST',ep,editor,{clientMessageId:randomUUID(),text:'blocked'})).statusCode,403);
 assert.equal((await req('DELETE',`${ep}/${editorComment}`,editor,{})).statusCode,200);
 assert.equal((await req('POST',ep,owner,message)).statusCode,200);
 const afterDeleted=await req('GET',`${ep}?after=${editorComment}`,owner);assert.equal(afterDeleted.statusCode,200);assert.equal(afterDeleted.json().comments.length,0);assert.equal(afterDeleted.json().nextCursor,editorComment);
 assert.equal((await req('DELETE',`${ep}/${comment}`,owner,{})).statusCode,200);
 assert.equal((await req('POST',ep,owner,message)).statusCode,409);
 assert.equal((await req('GET',ep,viewer)).json().comments.length,0);
 // A deleted account's attribution and message are masked but the row remains.
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 const redact=await req('POST',ep,editor,{clientMessageId:randomUUID(),text:'private contents'});assert.equal(redact.statusCode,201);
 await admin.query('UPDATE users SET deleted_at=now() WHERE id=$1',[ids[1]]);
 const masked=(await req('GET',ep,viewer)).json().comments[0];assert.equal(masked.body,'');assert.deepEqual(masked.author,{id:null,displayName:'Удалённый участник'});
 await admin.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[ids[1]]);
 // Cursor pagination uses per-event creation order, not timestamps supplied by client.
 await admin.query(`INSERT INTO event_comments(event_id,community_id,author_id,client_message_id,body)
 SELECT $1,$2,$3,gen_random_uuid(),'Bulk '||n FROM generate_series(1,52) n`,[event,group,ids[0]]);
 let cursor:string|null=null,hasMore=true;const seen:string[]=[];let pages=0;
 while(hasMore){const r=await req('GET',ep+(cursor?`?after=${cursor}`:''),viewer);assert.equal(r.statusCode,200,r.body);const data=r.json();seen.push(...data.comments.map((x:{id:string})=>x.id));cursor=data.nextCursor;hasMore=data.hasMore;pages++;assert.ok(pages<4);}
 assert.equal(seen.length,53);assert.equal(new Set(seen).size,53);assert.equal(pages,2);
 // A blocked insertion cannot commit after a later insertion for the same event.
 const beforeCursor=cursor!;const tx=await pool.connect();let committed=false;
 try{await tx.query('BEGIN');const first=await tx.query<{comment_id:string}>('SELECT * FROM public.create_event_comment($1,$2,$3,$4)',[ids[0],event,randomUUID(),'first']);
  const pending=req('POST',ep,owner,{clientMessageId:randomUUID(),text:'second'});
  await new Promise(resolve=>setTimeout(resolve,100));const during=await req('GET',`${ep}?after=${beforeCursor}`,viewer);assert.equal(during.json().comments.length,0);
  await tx.query('COMMIT');committed=true;const second=await pending;assert.equal(second.statusCode,201,second.body);
  const page=await req('GET',`${ep}?after=${beforeCursor}`,viewer);assert.deepEqual(page.json().comments.map((x:{id:string})=>x.id),[first.rows[0]!.comment_id,second.json().commentId]);
 }finally{if(!committed)await tx.query('ROLLBACK');tx.release()}
 // Revoked membership wins before a blocked write.
 const block=await admin.connect();let done=false;try{await block.query('BEGIN');await block.query('UPDATE trip_members SET left_at=now() WHERE trip_id=$1 AND user_id=$2',[trip,ids[4]]);
  const pending=req('POST',tp,tripeditor,{clientMessageId:randomUUID(),text:'Must not appear'});await new Promise(resolve=>setTimeout(resolve,100));await block.query('COMMIT');done=true;assert.equal((await pending).statusCode,404);
 }finally{if(!done)await block.query('ROLLBACK');block.release()}
 assert.equal((await req('GET',tp,tripeditor)).statusCode,404);
 assert.equal((await req('GET',tp,tripviewer)).json().comments.length,1);
 await admin.query('UPDATE events SET deleted_at=now() WHERE id=$1',[event]);assert.equal((await req('GET',ep,owner)).statusCode,404);
 assert.equal((await req('DELETE',`${ep}/${redact.json().commentId}`,editor,{})).statusCode,404);
 console.log('Live event discussions, access, deduplication, pagination and concurrency passed');
}finally{await app.close();await pool.end();await admin.end()}
