import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/app.js';
import { readConfig } from '../src/config.js';
import { createSafeDiagnostics } from '../src/safe-diagnostics.js';

const env = { DB_HOST:'db', DB_NAME:'synthetic', DB_USER:'runtime', DB_PASSWORD:'x'.repeat(48) };
test('safe diagnostics is explicitly opt-in and invalid settings fail without echoing them', () => {
  assert.equal(readConfig(env).SAFE_DIAGNOSTICS,'false');
  assert.equal(readConfig({...env, SAFE_DIAGNOSTICS:'true'}).SAFE_DIAGNOSTICS,'true');
  assert.throws(() => readConfig({...env, SAFE_DIAGNOSTICS:'secret-invalid-value'}), e => e instanceof Error && e.message.includes('SAFE_DIAGNOSTICS') && !e.message.includes('secret-invalid-value'));
});

test('safe diagnostics emits only fixed fields and has a bounded per-process budget', () => {
  let now=1_700_000_000_000; const lines:string[]=[];
  const emit=createSafeDiagnostics(line=>lines.push(line),()=>now);
  const input={requestId:randomUUID(),method:'POST',url:'/api/events/token-secret?email=secret',status:500,durationMs:123.4};
  emit({...input,status:200,durationMs:5});assert.equal(lines.length,0);
  for(let i=0;i<23;i++)emit(input);
  assert.equal(lines.length,20);
  const first=JSON.parse(lines[0]!);
  assert.deepEqual(Object.keys(first).sort(),['at','category','durationMs','event','method','requestId','status','suppressed'].sort());
  assert.equal(first.category,'events');assert.equal(first.event,'server_error');assert.equal(first.durationMs,123);
  assert.doesNotMatch(lines.join('\n'),/token-secret|email|secret/);
  now+=60_000;emit({...input,requestId:'secret-invalid-id',method:'secret-method',url:'/api/unknown/secret',status:429,durationMs:Infinity});
  const next=JSON.parse(lines.at(-1)!);assert.equal(next.event,'rate_limited');assert.equal(next.suppressed,3);assert.equal(next.requestId,'invalid');assert.equal(next.method,'OTHER');assert.equal(next.category,'other');assert.equal(next.durationMs,0);
  emit({...input,status:200,durationMs:2_010});assert.equal(JSON.parse(lines.at(-1)!).event,'slow_response');
  assert.doesNotThrow(()=>createSafeDiagnostics(()=>{throw Error('secret sink failure')},()=>now)(input));
});

test('API generates independent correlation IDs and errors never leak input or exceptions into diagnostics', async () => {
  const lines:string[]=[];const app=await createApp({checkDatabase:async()=>{},safeDiagnostic:createSafeDiagnostics(line=>lines.push(line))});
  app.post('/api/events/:id',async()=>{throw Error('exception secret-throw')});
  app.get('/api/auth/limited',async(_request,reply)=>reply.code(429).send({error:'RATE_LIMITED'}));
  try {
    const bad=await app.inject({method:'POST',url:'/api/events/secret-in-path?token=secret-in-query',headers:{'x-request-id':'secret-user-id','cookie':'session=secret-cookie','content-type':'application/json'},payload:{password:'secret-password'}});
    assert.equal(bad.statusCode,500);assert.deepEqual(bad.json(),{error:'INTERNAL_ERROR'});assert.equal(bad.headers['cache-control'],'no-store');
    const id=String(bad.headers['x-request-id']);assert.match(id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);assert.notEqual(id,'secret-user-id');
    const limited=await app.inject({method:'GET',url:'/api/auth/limited'});assert.equal(limited.statusCode,429);assert.notEqual(limited.headers['x-request-id'],id);
    const rows=lines.map(x=>JSON.parse(x));assert.equal(rows.length,2);assert.equal(rows[0].requestId,id);assert.equal(rows[0].category,'events');assert.equal(rows[1].event,'rate_limited');
    assert.doesNotMatch(lines.join('\n'),/secret|password|cookie|token|session|throw/);
    const health=await app.inject({method:'GET',url:'/health'});assert.equal(health.headers['x-request-id'],undefined);assert.equal(lines.length,2);
  } finally { await app.close(); }
  const noSink=await createApp({checkDatabase:async()=>{}});
  try {const response=await noSink.inject({method:'GET',url:'/api/absent'});assert.equal(response.statusCode,404);assert.match(String(response.headers['x-request-id']),/^[0-9a-f-]{36}$/i)} finally {await noSink.close()}
  const brokenSink=await createApp({checkDatabase:async()=>{},safeDiagnostic:()=>{throw Error('sink')}});
  try {assert.equal((await brokenSink.inject({method:'GET',url:'/api/not-found'})).statusCode,404)} finally {await brokenSink.close()}
});
