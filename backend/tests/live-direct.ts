// Explicitly opt-in; disposable data only.
import assert from 'node:assert/strict';import {randomBytes,randomUUID} from 'node:crypto';import pg from 'pg';import argon2 from 'argon2';
import {createApp} from '../src/app.js';import {readConfig,readSecurityConfig} from '../src/config.js';import {createPool} from '../src/db.js';
if(process.env.DB_NAME!=='sobralis_auth_test'||process.env.RUN_LIVE_AUTH_TEST!=='yes'||!process.env.TEST_ADMIN_PASSWORD)throw new Error('Requires disposable test DB and explicit opt-in');
const cfg=readConfig(process.env),sec=readSecurityConfig({PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)},'test');
const pool=createPool(cfg),admin=new pg.Pool({host:cfg.DB_HOST,port:cfg.DB_PORT,database:cfg.DB_NAME,user:'sobralis_admin',password:process.env.TEST_ADMIN_PASSWORD});
const app=await createApp({checkDatabase:async()=>{await pool.query('SELECT 1')},security:{pool,config:sec}}),origin={origin:'https://test.invalid'},password='test-only-direct-password-2026';
type Session={cookie:string;csrf:string;remote:string};
async function login(email:string,remote:string):Promise<Session>{const r=await app.inject({method:'POST',url:'/api/auth/login',headers:origin,remoteAddress:remote,payload:{email,password}});assert.equal(r.statusCode,200,r.body);let c=r.headers['set-cookie'];if(Array.isArray(c))c=c[0];assert.equal(typeof c,'string');return {cookie:c!.split(';')[0]!,csrf:r.json().csrfToken,remote};}
async function req(method:'GET'|'POST'|'DELETE',url:string,s:Session,payload?:unknown){return app.inject({method,url,headers:{...origin,cookie:s.cookie,'x-csrf-token':s.csrf},remoteAddress:s.remote,...(payload===undefined?{}:{payload})});}
try {
 const suffix=randomBytes(5).toString('hex'),hash=await argon2.hash(password,{type:argon2.argon2id,memoryCost:19456,timeCost:2,parallelism:1});
 const emails=['owner','editor','viewer','outsider','scoped','left'].map(x=>`direct-${x}-${suffix}@example.test`);
 const users=await admin.query<{id:string}>(`INSERT INTO users(email,password_hash,display_name,email_verified_at)
 SELECT x,$7,'Test',now() FROM unnest(ARRAY[$1,$2,$3,$4,$5,$6]::text[]) x RETURNING id`,[...emails,hash]);
 const ids=users.rows.map(x=>x.id),sessions:Session[]=[];for(let i=0;i<emails.length;i++)sessions.push(await login(emails[i]!,`10.70.0.${i+1}`));
 const [owner,editor,viewer,outsider,scoped,left]=sessions as [Session,Session,Session,Session,Session,Session];
 const group=(await admin.query<{id:string}>("INSERT INTO communities(name,created_by) VALUES('Community',$1) RETURNING id",[ids[0]])).rows[0]!.id;
 await admin.query(`INSERT INTO community_members(community_id,user_id,role,membership_scope,left_at) VALUES
 ($1,$2,'owner','full',NULL),($1,$3,'editor','full',NULL),($1,$4,'viewer','full',NULL),($1,$5,'editor','trip_only',NULL),($1,$6,'editor','full',now())`,[group,ids[0],ids[1],ids[2],ids[4],ids[5]]);
 const path=`/api/communities/${group}/direct-conversations`;
 assert.equal((await app.inject({method:'POST',url:path,headers:origin,payload:{recipientId:ids[1]}})).statusCode,401);
 assert.equal((await app.inject({method:'POST',url:path,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload:{recipientId:ids[1]}})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:path,headers:{...origin,cookie:owner.cookie},payload:{recipientId:ids[1]}})).statusCode,403);
 assert.equal((await req('POST',path,viewer,{recipientId:ids[0]})).statusCode,403);
 for(const s of [outsider,scoped,left])assert.equal((await req('POST',path,s,{recipientId:ids[0]})).statusCode,404);
 for(const id of [ids[3],ids[4],ids[5]])assert.equal((await req('POST',path,owner,{recipientId:id})).statusCode,404);
 assert.equal((await req('POST',path,owner,{recipientId:ids[0]})).statusCode,400);
 assert.equal((await req('POST',path,owner,{recipientId:ids[1],authorId:ids[0]})).statusCode,400);
 const creation=await Promise.all([req('POST',path,owner,{recipientId:ids[1]}),req('POST',path,editor,{recipientId:ids[0]})]);
 assert.deepEqual(creation.map(r=>r.statusCode).sort(),[200,201]);assert.equal(creation[0]!.json().conversationId,creation[1]!.json().conversationId);
 const conversation=creation[0]!.json().conversationId,mp=`/api/direct-conversations/${conversation}/messages`;
 assert.equal(Number((await admin.query<{count:string}>('SELECT count(*) FROM direct_conversation_pairs WHERE community_id=$1',[group])).rows[0]!.count),1);
 const ownerList=await req('GET','/api/direct-conversations',owner);assert.equal(ownerList.statusCode,200,ownerList.body);assert.equal(ownerList.headers['cache-control'],'no-store');assert.equal(ownerList.json().conversations[0].peer_id,ids[1]);assert.equal(ownerList.json().conversations[0].peer_available,true);
 assert.equal((await req('GET','/api/direct-conversations',editor)).json().conversations[0].peer_id,ids[0]);
 for(const s of [viewer,outsider,scoped,left]){assert.equal((await req('GET','/api/direct-conversations',s)).json().conversations.length,0);assert.equal((await req('GET',mp,s)).statusCode,404);}
 const payload={clientMessageId:randomUUID(),text:'Привет!'};
 assert.equal((await app.inject({method:'POST',url:mp,headers:{origin:'https://evil.invalid',cookie:owner.cookie,'x-csrf-token':owner.csrf},payload})).statusCode,403);
 assert.equal((await app.inject({method:'POST',url:mp,headers:{...origin,cookie:owner.cookie},payload})).statusCode,403);
 assert.equal((await req('POST',mp,viewer,payload)).statusCode,404);
 assert.equal((await req('POST',mp,owner,{...payload,authorId:ids[1]})).statusCode,400);
 assert.equal((await req('POST',mp,owner,{...payload,text:'x'.repeat(5001)})).statusCode,400);
 assert.equal((await req('POST',mp,owner,{...payload,text:'\0'})).statusCode,400);
 const sent=await Promise.all([req('POST',mp,owner,payload),req('POST',mp,owner,payload)]);
 assert.deepEqual(sent.map(r=>r.statusCode).sort(),[200,201]);assert.equal(sent[0]!.json().messageId,sent[1]!.json().messageId);const msg=sent[0]!.json().messageId;
 assert.equal((await req('POST',mp,owner,{...payload,text:'other'})).statusCode,409);
 const response=await req('POST',mp,editor,{clientMessageId:randomUUID(),text:'Здравствуй!'});assert.equal(response.statusCode,201,response.body);const otherMessage=response.json().messageId;
 const read=await req('GET',mp,editor);assert.equal(read.statusCode,200,read.body);assert.equal(read.headers['cache-control'],'no-store');assert.deepEqual(read.json().messages.map((x:{id:string})=>x.id),[msg,otherMessage]);assert.equal(read.json().messages[0].body,payload.text);assert.deepEqual(read.json().messages[0].author,{id:ids[0],displayName:'Test'});assert.doesNotMatch(read.body,/@example|clientMessageId|"seq"/);
 assert.equal((await req('GET',`${mp}?after=${randomUUID()}`,owner)).statusCode,400);
 assert.equal((await req('DELETE',`${mp}/${otherMessage}`,owner,{})).statusCode,403);
 await assert.rejects(()=>pool.query('SELECT * FROM direct_conversation_pairs'));await assert.rejects(()=>pool.query('SELECT * FROM conversation_messages'));
 // A viewer may read and remove an earlier own message, but not send or initiate.
 await admin.query("UPDATE community_members SET role='viewer' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 assert.equal((await req('POST',mp,editor,{clientMessageId:randomUUID(),text:'blocked'})).statusCode,403);
 assert.equal((await req('DELETE',`${mp}/${otherMessage}`,editor,{})).statusCode,200);
 assert.equal((await req('GET',`${mp}?after=${otherMessage}`,owner)).json().messages.length,0);
 await admin.query("UPDATE community_members SET role='editor' WHERE community_id=$1 AND user_id=$2",[group,ids[1]]);
 // Unavailable peer loses access and cannot receive new sends. Existing send retries remain safe.
 await admin.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
 assert.equal((await req('GET',mp,editor)).statusCode,404);
 assert.equal((await req('GET','/api/direct-conversations',owner)).json().conversations[0].peer_available,false);
 assert.equal((await req('POST',mp,owner,{clientMessageId:randomUUID(),text:'not delivered'})).statusCode,409);
 assert.equal((await req('POST',mp,owner,payload)).statusCode,200);
 await admin.query('UPDATE community_members SET left_at=NULL WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
 // Accidental third participant must close the private chat to everyone.
 await admin.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3)',[conversation,group,ids[2]]);
 assert.equal((await req('GET',mp,owner)).statusCode,404);assert.equal((await req('GET',mp,viewer)).statusCode,404);
 assert.equal((await req('POST',path,owner,{recipientId:ids[1]})).statusCode,404);
 await admin.query('DELETE FROM conversation_participants WHERE conversation_id=$1 AND user_id=$2',[conversation,ids[2]]);
 assert.equal((await req('GET',mp,owner)).statusCode,200);
 // Soft-deleted accounts are masked in peer metadata and message history.
 const fromPeer=await req('POST',mp,editor,{clientMessageId:randomUUID(),text:'Sensitive'});assert.equal(fromPeer.statusCode,201);
 await admin.query('UPDATE users SET deleted_at=now() WHERE id=$1',[ids[1]]);
 const masked=(await req('GET',mp,owner)).json().messages.find((x:{id:string})=>x.id===fromPeer.json().messageId);assert.equal(masked.body,'');assert.deepEqual(masked.author,{id:null,displayName:'Удалённый участник'});
 const unavailable=(await req('GET','/api/direct-conversations',owner)).json().conversations[0];assert.equal(unavailable.peer_id,null);assert.equal(unavailable.peer_available,false);
 await admin.query('UPDATE users SET deleted_at=NULL WHERE id=$1',[ids[1]]);
 // Multi-page timeline; UUID cursor remains usable after the referenced message is removed.
 await admin.query(`INSERT INTO conversation_messages(conversation_id,community_id,author_id,client_message_id,body)
 SELECT $1,$2,$3,gen_random_uuid(),'Bulk '||n FROM generate_series(1,52) n`,[conversation,group,ids[0]]);
 let cursor:string|null=null,hasMore=true;const all:string[]=[];let pages=0;while(hasMore){const r=await req('GET',mp+(cursor?`?after=${cursor}`:''),owner);assert.equal(r.statusCode,200,r.body);all.push(...r.json().messages.map((x:{id:string})=>x.id));cursor=r.json().nextCursor;hasMore=r.json().hasMore;pages++;assert.ok(pages<4);}
 assert.equal(all.length,54);assert.equal(new Set(all).size,54);assert.equal(pages,2);
 const oldCursor=cursor!;const tx=await pool.connect();let committed=false;
 try{await tx.query('BEGIN');const first=await tx.query<{message_id:string}>('SELECT * FROM public.send_direct_message($1,$2,$3,$4)',[ids[0],conversation,randomUUID(),'first']);
  const pending=req('POST',mp,owner,{clientMessageId:randomUUID(),text:'second'});await new Promise(resolve=>setTimeout(resolve,100));
  assert.equal((await req('GET',`${mp}?after=${oldCursor}`,editor)).json().messages.length,0);
  await tx.query('COMMIT');committed=true;const second=await pending;assert.equal(second.statusCode,201,second.body);
  assert.deepEqual((await req('GET',`${mp}?after=${oldCursor}`,editor)).json().messages.map((x:{id:string})=>x.id),[first.rows[0]!.message_id,second.json().messageId]);
 }finally{if(!committed)await tx.query('ROLLBACK');tx.release()}
 // Peer removal wins before the new message is sent.
 const block=await admin.connect();let done=false;try{await block.query('BEGIN');await block.query('UPDATE community_members SET left_at=now() WHERE community_id=$1 AND user_id=$2',[group,ids[1]]);
  const pending=req('POST',mp,owner,{clientMessageId:randomUUID(),text:'Must not deliver'});await new Promise(resolve=>setTimeout(resolve,100));await block.query('COMMIT');done=true;assert.equal((await pending).statusCode,409);
 }finally{if(!done)await block.query('ROLLBACK');block.release()}
 assert.equal(Number((await admin.query<{count:string}>("SELECT count(*) FROM conversation_messages WHERE conversation_id=$1 AND body='Must not deliver'",[conversation])).rows[0]!.count),0);
 // Deletion is private to the author; replay cannot resurrect the message.
 assert.equal((await req('DELETE',`${mp}/${msg}`,owner,{})).statusCode,200);
 assert.equal((await req('POST',mp,owner,payload)).statusCode,409);
 assert.equal((await req('GET',`${mp}?after=${msg}`,owner)).statusCode,200);
 // A viewer may be a recipient and read, but cannot send.
 const viewerChat=await req('POST',path,owner,{recipientId:ids[2]});assert.equal(viewerChat.statusCode,201,viewerChat.body);
 const viewerMessages=`/api/direct-conversations/${viewerChat.json().conversationId}/messages`;
 assert.equal((await req('GET',viewerMessages,viewer)).statusCode,200);
 assert.equal((await req('POST',viewerMessages,viewer,{clientMessageId:randomUUID(),text:'blocked'})).statusCode,403);
 assert.equal((await req('GET',`${viewerMessages}?after=${msg}`,owner)).statusCode,400);
 // More than one page of conversation metadata, without exposing other users' lists.
 for(let n=0;n<51;n++){
   const peer=(await admin.query<{id:string}>("INSERT INTO users(email,display_name,email_verified_at) VALUES($1,'Bulk',now()) RETURNING id",[`bulk-${n}-${suffix}@example.test`])).rows[0]!.id;
   await admin.query("INSERT INTO community_members(community_id,user_id,role) VALUES($1,$2,'viewer')",[group,peer]);
   const cid=(await admin.query<{id:string}>("INSERT INTO conversations(community_id,kind) VALUES($1,'direct') RETURNING id",[group])).rows[0]!.id;
   await admin.query('INSERT INTO conversation_participants(conversation_id,community_id,user_id) VALUES($1,$2,$3),($1,$2,$4)',[cid,group,ids[0],peer]);
   await admin.query('INSERT INTO direct_conversation_pairs(community_id,user_low,user_high,conversation_id) VALUES($1,LEAST($2::uuid,$3::uuid),GREATEST($2::uuid,$3::uuid),$4)',[group,ids[0],peer,cid]);
 }
 let listCursor:string|null=null;const listed:string[]=[];let listPages=0;do{
   const r=await req('GET','/api/direct-conversations'+(listCursor?`?cursor=${listCursor}`:''),owner);assert.equal(r.statusCode,200,r.body);
   listed.push(...r.json().conversations.map((x:{id:string})=>x.id));listCursor=r.json().nextCursor;listPages++;assert.ok(listPages<4);
 }while(listCursor);
 assert.equal(listed.length,53);assert.equal(new Set(listed).size,53);assert.equal(listPages,2);
 assert.equal((await req('GET','/api/direct-conversations',outsider)).json().conversations.length,0);
 await admin.query('UPDATE communities SET deleted_at=now() WHERE id=$1',[group]);assert.equal((await req('GET',mp,owner)).statusCode,404);
 console.log('Live direct conversations, pair isolation, idempotence and revocation races passed');
}finally{await app.close();await pool.end();await admin.end()}
