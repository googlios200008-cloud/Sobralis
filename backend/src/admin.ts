// Operator-only CLI. No HTTP admin endpoint is exposed.
// Run only from a protected host/container with a dedicated migrator credential.
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { readConfig } from './config.js';
import { createPool } from './db.js';
import { hashToken } from './security.js';
import type { PoolClient } from 'pg';

const uuid = z.string().uuid();
const featureName=z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/);
const integer = (s: string|undefined, min: number, max: number):number => {
  if (!s || !/^[0-9]+$/.test(s)) throw new Error('Invalid integer');
  const n=Number(s);if (!Number.isSafeInteger(n)||n<min||n>max) throw new Error('Integer out of range');return n;
};
async function assertAdmin(client:PoolClient, id:string){
  const result=await client.query("SELECT id FROM users WHERE id=$1 AND account_role='admin' AND deleted_at IS NULL",[id]);
  if(!result.rowCount)throw new Error('Administrator not found');
}
async function lockUser(client:PoolClient,id:string){
  const result=await client.query('SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',[id]);
  if(!result.rowCount)throw new Error('User not found');
}
const usage='Usage: grant-friends ADMIN_UUID USER_UUID | grant-pro ADMIN_UUID USER_UUID DAYS | set-free ADMIN_UUID USER_UUID --confirm | list-access ADMIN_UUID USER_UUID | revoke-grant ADMIN_UUID USER_UUID GRANT_UUID --confirm | create-promo ADMIN_UUID PRO|FRIENDS_UNLIMITED DAYS MAX_USES EXPIRES_UTC | disable-promo ADMIN_UUID PROMO_UUID | set-flag ADMIN_UUID FEATURE_KEY on|off';
async function main(){
  const args=process.argv.slice(2), command=args[0];
  if(!command||!['grant-friends','grant-pro','set-free','list-access','revoke-grant','create-promo','disable-promo','set-flag'].includes(command)){console.error(usage);process.exitCode=2;return}
  const admin=uuid.parse(args[1]);
  const config=readConfig(process.env);
  if(config.DB_USER!=='sobralis_migrator')throw new Error('Restricted to the operator database role');
  const pool=createPool(config);
  let newCode:string|null=null, promoId:string|null=null, listing:unknown=null;
  try{
    const client=await pool.connect();
    try{
      await client.query('BEGIN');
      await assertAdmin(client,admin);
      if(command==='grant-friends' || command==='grant-pro' || command==='set-free' || command==='list-access' || command==='revoke-grant'){
        const target=uuid.parse(args[2]);await lockUser(client,target);
        if(command==='grant-friends'){
          if(args.length!==3)throw new Error('Invalid arguments');
          const existing=await client.query("SELECT id FROM subscriptions WHERE user_id=$1 AND tier='FRIENDS_UNLIMITED' AND revoked_at IS NULL AND starts_at<=now()",[target]);
          if(existing.rowCount)throw new Error('User already has unlimited access');
          await client.query("INSERT INTO subscriptions(user_id,tier,source) VALUES($1,'FRIENDS_UNLIMITED','admin')",[target]);
          await client.query("INSERT INTO administrative_actions(actor_user_id,target_user_id,action) VALUES($1,$2,'grant_friends')",[admin,target]);
        }else if(command==='grant-pro'){
          if(args.length!==4)throw new Error('Invalid arguments');const days=integer(args[3],1,3650);
          // Serialize with promo redemption; extend from the latest non-revoked PRO grant.
          await client.query(`INSERT INTO subscriptions(user_id,tier,source,starts_at,expires_at)
            SELECT $1,'PRO','admin',start_at,start_at+($2 * interval '24 hours')
            FROM (SELECT GREATEST(now(),COALESCE(MAX(expires_at),now())) AS start_at FROM subscriptions
                  WHERE user_id=$1 AND tier='PRO' AND revoked_at IS NULL AND expires_at>now()) s`,[target,days]);
          await client.query("INSERT INTO administrative_actions(actor_user_id,target_user_id,action,metadata) VALUES($1,$2,'grant_pro',jsonb_build_object('days',$3::int))",[admin,target,days]);
        }else if(command==='list-access'){
          if(args.length!==3)throw new Error('Invalid arguments');
          const result=await client.query('SELECT id,tier,source,starts_at,expires_at,revoked_at FROM subscriptions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[target]);
          listing=result.rows;
        }else if(command==='revoke-grant'){
          if(args.length!==5||args[4]!=='--confirm')throw new Error('Explicit confirmation required');
          const grantId=uuid.parse(args[3]);
          const result=await client.query("UPDATE subscriptions SET revoked_at=now() WHERE id=$1 AND user_id=$2 AND source IN ('admin','promo') AND revoked_at IS NULL",[grantId,target]);
          if(!result.rowCount)throw new Error('Grant not revocable');
          await client.query("INSERT INTO administrative_actions(actor_user_id,target_user_id,action,metadata) VALUES($1,$2,'revoke_grant',jsonb_build_object('grant_id',$3::text))",[admin,target,grantId]);
        }else{
          if(args.length!==4||args[3]!=='--confirm')throw new Error('Explicit confirmation required');
          // Do not silently cancel or bypass promos or future paid subscriptions.
          const other=await client.query("SELECT id FROM subscriptions WHERE user_id=$1 AND source<>'admin' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()) LIMIT 1",[target]);
          if(other.rowCount)throw new Error('External grants must be handled separately');
          await client.query("UPDATE subscriptions SET revoked_at=now() WHERE user_id=$1 AND source='admin' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())",[target]);
          await client.query("INSERT INTO administrative_actions(actor_user_id,target_user_id,action) VALUES($1,$2,'set_free')",[admin,target]);
        }
      }else if(command==='create-promo'){
        if(args.length!==6)throw new Error('Invalid arguments');
        const tier=z.enum(['PRO','FRIENDS_UNLIMITED']).parse(args[2]);
        const days=tier==='PRO'?integer(args[3],1,3650):(args[3]==='0'?null:(()=>{throw new Error('Unlimited duration must be 0')})());
        const uses=integer(args[4],1,10000), expiry=args[5];
        if(!expiry||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(expiry))throw new Error('Expiry must be a UTC ISO timestamp');
        const end=new Date(expiry), ms=end.getTime();
        const canonical=expiry.replace(/(?:\.(\d{1,3}))?Z$/, (_whole, fraction:string|undefined)=>'.'+(fraction??'').padEnd(3,'0')+'Z');
        if(!Number.isFinite(ms)||end.toISOString()!==canonical||ms<=Date.now()||ms>Date.now()+5*366*86400000)throw new Error('Invalid expiry');
        newCode=randomBytes(32).toString('base64url');
        const p=await client.query<{id:string}>(`INSERT INTO promo_codes(code_hash,grant_tier,duration_days,max_uses,expires_at,created_by)
          VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,[hashToken(newCode),tier,days,uses,end,admin]);
        promoId=p.rows[0]!.id;
        await client.query("INSERT INTO administrative_actions(actor_user_id,promo_code_id,action,metadata) VALUES($1,$2,'create_promo',jsonb_build_object('tier',$3::text,'max_uses',$4::int))",[admin,promoId,tier,uses]);
      }else if(command==='disable-promo'){
        if(args.length!==3)throw new Error('Invalid arguments');const id=uuid.parse(args[2]);
        const result=await client.query('UPDATE promo_codes SET disabled_at=now() WHERE id=$1 AND disabled_at IS NULL',[id]);
        if(!result.rowCount)throw new Error('Promo unavailable');
        await client.query("INSERT INTO administrative_actions(actor_user_id,promo_code_id,action) VALUES($1,$2,'disable_promo')",[admin,id]);
      }else if(command==='set-flag'){
        if(args.length!==4)throw new Error('Invalid arguments');const feature=featureName.parse(args[2]),value=z.enum(['on','off']).parse(args[3]);
        const result=await client.query('UPDATE feature_catalog SET enabled=$2 WHERE feature_key=$1',[feature,value==='on']);
        if(!result.rowCount)throw new Error('Feature not found');
        await client.query("INSERT INTO administrative_actions(actor_user_id,action,metadata) VALUES($1,'set_flag',jsonb_build_object('feature',$2::text,'enabled',$3::boolean))",[admin,feature,value==='on']);
      }
      await client.query('COMMIT');
      if(newCode) console.log(`PROMO_ID=${promoId}\nPROMO_CODE=${newCode}`); // Shown once; never printed in application logs.
      else if(listing) console.log(JSON.stringify(listing));
      else console.log('Operation completed');
    }catch(error){try{await client.query('ROLLBACK')}catch{}throw error}finally{client.release()}
  }finally{await pool.end()}
}
main().catch(()=>{console.error('Operation failed. Verify access, arguments and target state.');process.exitCode=1});
