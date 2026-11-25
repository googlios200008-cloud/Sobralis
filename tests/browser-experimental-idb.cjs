'use strict';
// Synthetic origin, generated DB name and fresh browser profile only. This
// experiment is deliberately not connected to the shipping application.
const {chromium}=require('playwright'),fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const origin='https://idb-experiment.invalid',src=fs.readFileSync(path.join(__dirname,'../experiments/local-transactions/idb-store.js'));
(async()=>{const browser=await chromium.launch({args:['--no-sandbox']}),ctx=await browser.newContext();try{
 await ctx.route('**/*',r=>{const u=new URL(r.request().url());if(u.origin!==origin)return r.fulfill({status:404,body:''});if(u.pathname==='/idb-store.js')return r.fulfill({status:200,contentType:'text/javascript',body:src});return r.fulfill({status:200,contentType:'text/html',headers:{'Content-Security-Policy':"default-src 'self'; script-src 'self'; object-src 'none'"},body:'<!doctype html><title>Synthetic transaction test</title><script src="/idb-store.js"></script>'})});
 const name='sobralis-idb-experiment-'+crypto.randomUUID(),a=await ctx.newPage(),b=await ctx.newPage(),errors=[];for(const p of [a,b]){p.on('pageerror',e=>errors.push(e.message));await p.goto(origin);await p.evaluate(async n=>{window.store=await SobralisExperimentalTransactions.open(n)},name)}
 assert.equal(await a.evaluate(async()=>{try{await SobralisExperimentalTransactions.open('sobralis-real');return 'unexpected'}catch(e){return e.code}}),'EXPERIMENT_DATABASE_REQUIRED');
 await a.evaluate(()=>localStorage.setItem('sobralis-v2','legacy synthetic untouched'));assert.equal(await a.evaluate(()=>store.read()),null);
 assert.equal((await a.evaluate(()=>store.commit({epoch:crypto.randomUUID(),revision:1},'missing'))).status,'missing');
 const [i1,i2]=await Promise.all([a.evaluate(()=>store.initialize('legacy synthetic A')),b.evaluate(()=>store.initialize('legacy synthetic B'))]);assert.equal(Number(i1.created)+Number(i2.created),1);assert.deepEqual(i1.snapshot,i2.snapshot);assert.equal(i1.snapshot.revision,1);assert.equal((await a.evaluate(c=>store.restore(c),i1.snapshot)).status,'no_restore_point');assert.equal(await b.evaluate(()=>localStorage.getItem('sobralis-v2')),'legacy synthetic untouched');let current=i1.snapshot;
 // Two independent pages race with the same revision. The transaction engine
 // serializes them; exactly one commit succeeds, not both.
 for(let i=0;i<30;i++){
  const [x,y]=await Promise.all([a.evaluate(({current,i})=>store.commit(current,'first '+i),{current,i}),b.evaluate(({current,i})=>store.commit(current,'second '+i),{current,i})]);
  assert.deepEqual([x.status,y.status].sort(),['committed','conflict']);const winner=x.status==='committed'?x:y,loser=x.status==='conflict'?x:y;assert.deepEqual(loser.snapshot,winner.snapshot);assert.deepEqual(await a.evaluate(()=>store.read()),winner.snapshot);current=winner.snapshot;
 }
 let r=await a.evaluate(c=>store.commit(c,'imported synthetic',true),current);assert.equal(r.status,'committed');assert.equal(r.snapshot.previous,current.text);current=r.snapshot;
 const [restore,edit]=await Promise.all([a.evaluate(c=>store.restore(c),current),b.evaluate(c=>store.commit(c,'concurrent edit'),current)]);assert.deepEqual([restore.status,edit.status].sort(),['committed','conflict']);current=(restore.status==='committed'?restore:edit).snapshot;assert.deepEqual(await b.evaluate(()=>store.read()),current);
 // Restore and its single undo point swap in the same transaction.
 const beforeRestore=current;r=await a.evaluate(c=>store.restore(c),current);assert.equal(r.status,'committed');assert.equal(r.snapshot.text,beforeRestore.previous);assert.equal(r.snapshot.previous,beforeRestore.text);current=r.snapshot;
 // Simulated abort after scheduling put: no success is reported and neither
 // state nor restore point changes. Request success alone is insufficient.
 const aborted=await a.evaluate(async c=>{const old=IDBObjectStore.prototype.put;IDBObjectStore.prototype.put=function(...args){const req=old.apply(this,args);this.transaction.abort();return req};try{await store.commit(c,'must roll back',true);return 'unexpected'}catch(e){return e.code}finally{IDBObjectStore.prototype.put=old}},current);assert.equal(aborted,'TRANSACTION_FAILED');assert.deepEqual(await b.evaluate(()=>store.read()),current);
 // Synchronous browser storage failures must not leak implementation details
 // or change the current snapshot.
 const getError=await a.evaluate(async()=>{const old=IDBObjectStore.prototype.get;IDBObjectStore.prototype.get=function(){throw Error('synthetic secret')};try{await store.read();return 'unexpected'}catch(e){return e.message}finally{IDBObjectStore.prototype.get=old}});assert.equal(getError,'TRANSACTION_FAILED');assert.deepEqual(await a.evaluate(()=>store.read()),current);
 const openError=await a.evaluate(async()=>{const old=indexedDB.open;indexedDB.open=function(){throw Error('synthetic secret')};try{await SobralisExperimentalTransactions.open('sobralis-idb-experiment-unavailable');return 'unexpected'}catch(e){return e.message}finally{indexedDB.open=old}});assert.equal(openError,'STORAGE_UNAVAILABLE');
 assert.equal(await a.evaluate(async()=>{try{await store.commit({epoch:'bad',revision:1},'x');return 'unexpected'}catch(e){return e.code}}),'INVALID_INPUT');
 // The caller's mutable token is copied before the asynchronous read.
 r=await b.evaluate(async c=>{const token={epoch:c.epoch,revision:c.revision},pending=store.commit(token,'token copied');token.revision+=100;return pending},current);assert.equal(r.status,'committed');current=r.snapshot;
 // A safe-integer limit must not wrap the revision and revive stale tokens.
 await a.evaluate(async ({n,current})=>{const req=indexedDB.open(n,1);const db=await new Promise((ok,no)=>{req.onsuccess=()=>ok(req.result);req.onerror=()=>no(req.error)});await new Promise((ok,no)=>{const t=db.transaction('snapshots','readwrite');t.objectStore('snapshots').put({key:'state',...current,revision:Number.MAX_SAFE_INTEGER});t.oncomplete=ok;t.onabort=()=>no(t.error)});db.close()},{n:name,current});
 const max=await a.evaluate(()=>store.read());assert.equal((await a.evaluate(c=>store.commit(c,'overflow'),max)).status,'revision_exhausted');assert.equal((await b.evaluate(c=>store.restore(c),max)).status,'revision_exhausted');assert.deepEqual(await a.evaluate(()=>store.read()),max);
 // A corrupted row is never reset to an example or overwritten silently.
 await a.evaluate(async n=>{const req=indexedDB.open(n,1);const db=await new Promise((ok,no)=>{req.onsuccess=()=>ok(req.result);req.onerror=()=>no(req.error)});await new Promise((ok,no)=>{const t=db.transaction('snapshots','readwrite');t.objectStore('snapshots').put({key:'state',epoch:'bad',revision:1,text:'do not erase',previous:null});t.oncomplete=ok;t.onabort=()=>no(t.error)});db.close()},name);
 assert.equal(await b.evaluate(async()=>{try{await store.read();return 'unexpected'}catch(e){return e.code}}),'INVALID_STATE');assert.equal(await a.evaluate(async c=>{try{await store.commit(c,'replace');return 'unexpected'}catch(e){return e.code}},current),'INVALID_STATE');
 const raw=await a.evaluate(async n=>{const req=indexedDB.open(n,1);const db=await new Promise((ok,no)=>{req.onsuccess=()=>ok(req.result);req.onerror=()=>no(req.error)});const row=await new Promise((ok,no)=>{const t=db.transaction('snapshots','readonly'),q=t.objectStore('snapshots').get('state');q.onsuccess=()=>ok(q.result);q.onerror=()=>no(q.error)});db.close();return row},name);assert.equal(raw.text,'do not erase');
 await a.evaluate(()=>store.close());await b.evaluate(()=>store.close());assert.equal(await b.evaluate(async()=>{try{await store.read();return 'unexpected'}catch(e){return e.code}}),'STORAGE_UNAVAILABLE');await a.evaluate(n=>new Promise((ok,no)=>{const q=indexedDB.deleteDatabase(n);q.onsuccess=ok;q.onerror=()=>no(q.error);q.onblocked=()=>no(Error('blocked'))}),name);
 // Recreation receives a new epoch; a stale token cannot commit to it even if
 // both old and new revisions are one.
 await a.evaluate(async n=>{window.store=await SobralisExperimentalTransactions.open(n)},name);const fresh=await a.evaluate(()=>store.initialize('new synthetic'));assert.equal(fresh.snapshot.revision,1);assert.notEqual(fresh.snapshot.epoch,i1.snapshot.epoch);assert.equal((await a.evaluate(t=>store.commit(t,'stale overwrite'),i1.snapshot)).status,'conflict');assert.equal((await a.evaluate(()=>store.read())).text,'new synthetic');await a.evaluate(()=>store.close());
 await a.evaluate(n=>new Promise((ok,no)=>{const q=indexedDB.deleteDatabase(n);q.onsuccess=ok;q.onerror=()=>no(q.error);q.onblocked=()=>no(Error('blocked'))}),name);assert.deepEqual(errors,[]);
 console.log('Experimental IndexedDB: concurrent CAS, atomic restore, abort, corruption and epoch reuse passed in Chromium');
 }finally{await ctx.close();await browser.close()}})().catch(e=>{console.error(e);process.exitCode=1});
