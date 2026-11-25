import { test } from 'node:test';
import assert from 'node:assert/strict';
import type pg from 'pg';
import { createApp } from '../src/app.js';
import { readSecurityConfig } from '../src/config.js';
import { hashToken } from '../src/security.js';

const env={PUBLIC_ORIGIN:'https://test.invalid',CSRF_SECRET:'test-secret-'.repeat(5)};
const token='A'.repeat(43),headers={origin:'https://test.invalid'};
const paths=[
  {legacy:`/api/community-invites/${token}/preview`,body:'/api/community-invites/preview',kind:'community'},
  {legacy:`/api/invites/${token}/preview`,body:'/api/invites/preview',kind:'trip'},
];

test('production never registers token-in-URL invitation routes; body routes remain available',async()=>{
  const cfg=readSecurityConfig({...env,legacyInviteUrlsEnabled:'true',LEGACY_INVITE_URLS:'true'},'production');
  assert.equal(cfg.legacyInviteUrlsEnabled,false);
  let calls=0;
  const pool={query:async(sql:string,values:unknown[])=>{calls++;assert.deepEqual(values,[hashToken(token)]);assert.doesNotMatch(sql,new RegExp(token));
    return {rows:sql.includes('preview_community_invite')?[{community_name:'Group',granted_role:'viewer',expires_at:'2040-01-01T00:00:00Z'}]:[{trip_title:'Trip',community_name:'Group',granted_role:'viewer',expires_at:'2040-01-01T00:00:00Z'}]};
  }} as unknown as pg.Pool;
  const app=await createApp({checkDatabase:async()=>{},security:{pool,config:cfg}});
  try{
    for(const path of paths){
      const before=calls;
      for(const method of ['GET','HEAD'] as const){const r=await app.inject({method,url:path.legacy});assert.equal(r.statusCode,404);assert.doesNotMatch(r.body,new RegExp(token));}
      const legacyRedeem=path.legacy.replace('/preview','/redeem');const r=await app.inject({method:'POST',url:legacyRedeem,headers,payload:{}});assert.equal(r.statusCode,404);assert.doesNotMatch(r.body,new RegExp(token));assert.equal(calls,before);
      const body=await app.inject({method:'POST',url:path.body,headers,payload:{token}});assert.equal(body.statusCode,200,body.body);assert.equal(calls,before+1);assert.equal(body.headers['cache-control'],'no-store');assert.doesNotMatch(body.body,new RegExp(token));
      assert.equal((await app.inject({method:'POST',url:path.body,headers:{origin:'https://evil.invalid'},payload:{token}})).statusCode,403);
    }
  }finally{await app.close()}
});

test('test/development compatibility mode retains the old preview routes',async()=>{
  for(const mode of ['development','test'] as const){
    const cfg=readSecurityConfig(env,mode);assert.equal(cfg.legacyInviteUrlsEnabled,true);
    const pool={query:async(sql:string)=>({rows:sql.includes('preview_community_invite')?[{community_name:'Group',granted_role:'viewer',expires_at:'2040-01-01T00:00:00Z'}]:[{trip_title:'Trip',community_name:'Group',granted_role:'viewer',expires_at:'2040-01-01T00:00:00Z'}]})} as unknown as pg.Pool;
    const app=await createApp({checkDatabase:async()=>{},security:{pool,config:cfg}});
    try{for(const path of paths)assert.equal((await app.inject({method:'GET',url:path.legacy})).statusCode,200)}finally{await app.close()}
  }
});
