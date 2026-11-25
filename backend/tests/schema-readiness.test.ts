import {test} from 'node:test';
import assert from 'node:assert/strict';
import type {Pool} from 'pg';
import {assertReleaseSchema,createSchemaReadiness} from '../src/schema-readiness.js';

test('readiness rejects missing, changed, reordered, duplicated and newer migrations',()=>{
 const expected=[{name:'0001_a.sql',checksum:'a'},{name:'0002_b.sql',checksum:'b'}];
 assert.doesNotThrow(()=>assertReleaseSchema(expected,[...expected]));
 for(const actual of [[],expected.slice(0,1),[{name:'0001_a.sql',checksum:'tampered'},expected[1]!],[expected[1]!,expected[0]!],[expected[0]!,expected[0]!],[...expected,{name:'0003_new.sql',checksum:'c'}]])assert.throws(()=>assertReleaseSchema(expected,actual),/does not match/);
 assert.throws(()=>assertReleaseSchema([],[]));
});
test('readiness checks the restricted function and retains an immutable release fingerprint',async()=>{
 const expected=[{name:'0001_a.sql',checksum:'a'}];let rows=[{...expected[0]!}],sql='';
 const pool={query:async(text:string)=>{sql=text;return {rows}}} as unknown as Pool;
 const check=createSchemaReadiness(pool,expected);expected[0]!.checksum='changed by caller';await check();assert.match(sql,/public\.runtime_schema_state/);
 rows=[{name:'0001_a.sql',checksum:'wrong'}];await assert.rejects(check,/does not match/);
});
