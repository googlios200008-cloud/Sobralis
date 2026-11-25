import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { createServingReadiness } from '../src/serving-readiness.js';

// The readiness check is deliberately not cached: a later request must see a
// changed state. Parallel requests may share only an outstanding check.
test('API traffic fails closed on readiness failure, recovers, and shares in-flight checks', async () => {
  let healthy=true, calls=0, mutations=0;
  let release:(()=>void)|undefined;
  let gate:Promise<void>|undefined;
  const app=await createApp({checkDatabase:async()=>{calls++;await gate;if(!healthy)throw Error('secret checksum and database location')}});
  app.post('/api/check',async()=>{mutations++;return {ok:true}});
  try {
    const first=await app.inject({method:'POST',url:'/api/check'});assert.equal(first.statusCode,200);assert.equal(mutations,1);
    healthy=false;
    const blocked=await app.inject({method:'POST',url:'/api/check'});assert.equal(blocked.statusCode,503);assert.deepEqual(blocked.json(),{error:'UNAVAILABLE'});assert.doesNotMatch(blocked.body,/secret|checksum|database/);assert.equal(mutations,1);
    assert.equal((await app.inject({method:'GET',url:'/health'})).statusCode,200);
    assert.equal((await app.inject({method:'GET',url:'/ready'})).statusCode,503);
    healthy=true;assert.equal((await app.inject({method:'POST',url:'/api/check'})).statusCode,200);assert.equal(mutations,2);
    const before=calls;gate=new Promise<void>(r=>{release=r});
    const requests=Array.from({length:8},()=>app.inject({method:'POST',url:'/api/check'}));
    await new Promise<void>(r=>setImmediate(r));assert.equal(calls,before+1);release!();
    const responses=await Promise.all(requests);assert.ok(responses.every(r=>r.statusCode===200));assert.equal(mutations,10);
    gate=undefined;const prior=calls;await app.inject({method:'POST',url:'/api/check'});assert.equal(calls,prior+1);
  } finally {release?.();await app.close()}
});


test('a stuck check times out without launching unbounded replacement operations', async () => {
  let calls=0, release:(()=>void)|undefined;
  const blocked=new Promise<void>(r=>{release=r});
  const check=createServingReadiness(async()=>{calls++;if(calls===1)await blocked},25);
  const a=check(),b=check();assert.equal(a,b);await assert.rejects(a,/timed out/);assert.equal(calls,1);
  for(let i=0;i<10;i++)await assert.rejects(check(),/timed out/);
  assert.equal(calls,1);release!();await new Promise<void>(r=>setImmediate(r));
  await check();assert.equal(calls,2);
});
