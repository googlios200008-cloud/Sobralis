import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import argon2 from 'argon2';
import { z } from 'zod';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Pool, PoolClient } from 'pg';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import type { SecurityConfig } from './config.js';
import { resolveEntitlements, hasFeature } from './entitlements.js';
import type { VerificationMailer } from './mail.js';

const sessionCookie = '__Host-sobralis_session';
const cookieOptions = { httpOnly: true, secure: true, sameSite: 'strict' as const, path: '/' };
const tokenPattern = /^[A-Za-z0-9_-]{43}$/;
const sessionSeconds = 24 * 60 * 60;
const passwordOptions = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };
const emailField = z.string().trim().max(254).email().transform(x => x.toLowerCase());
const loginSchema = z.object({ email: emailField, password: z.string().min(1).max(128) }).strict();
const registrationSchema = z.object({
  email: emailField,
  displayName: z.string().trim().min(1).max(120),
  dataConsentAccepted: z.literal(true),
  termsAccepted: z.literal(true),
}).strict();
const verifySchema=z.object({token:z.string().regex(tokenPattern),password:z.string().min(12).max(128),dataConsentAccepted:z.literal(true),termsAccepted:z.literal(true),dataConsentVersion:z.string().min(1).max(80),termsVersion:z.string().min(1).max(80)}).strict();
const resendSchema=z.object({email:emailField}).strict();
const resetSchema=z.object({token:z.string().regex(tokenPattern),password:z.string().min(12).max(128)}).strict();
const tripParams = z.object({ tripId: z.string().uuid() }).strict();
const updateTripSchema = z.object({ expectedRevision:z.string().uuid(), title:z.string().trim().min(1).max(200).refine(v=>!v.includes('\0')), startsOn:z.string().refine(isCalendarDate).nullable(), endsOn:z.string().refine(isCalendarDate).nullable() }).strict().refine(v=>(v.startsOn===null&&v.endsOn===null)||(v.startsOn!==null&&v.endsOn!==null&&v.endsOn>=v.startsOn&&Date.parse(v.endsOn+'T00:00:00Z')-Date.parse(v.startsOn+'T00:00:00Z')<=365*86400000));
const communityParams = z.object({ communityId: z.string().uuid() }).strict();
const scheduleParams = communityParams.extend({ date: z.string().refine(isCalendarDate) }).strict();
const scheduleBody = z.object({ status: z.enum(['free','work','busy','unknown']) }).strict();
const communityBody = z.object({ name: z.string().trim().min(1).max(120), clientRequestId:z.string().uuid().optional() }).strict();
const createTripBody = z.object({ title: z.string().trim().min(1).max(200), timezone: z.string().min(1).max(100).default('Europe/Moscow'), clientRequestId:z.string().uuid().optional() }).strict();
const listTripsQuery = z.object({ cursor: z.string().uuid().optional() }).strict();
const eventBody=z.object({
  title:z.string().trim().min(1).max(200).refine(v=>!v.includes('\0')), description:z.string().trim().max(5000).refine(v=>!v.includes('\0')).default(''),
  location:z.string().trim().max(500).refine(v=>!v.includes('\0')).default(''),
  startsAt:z.iso.datetime({precision:0}).refine(v=>isCalendarDate(v.slice(0,10))),
  timezone:z.string().min(1).max(100).refine(v=>!v.includes('\0')).default('Europe/Moscow'),
  venue:z.enum(['home','other']).default('other'),
  overnight:z.enum(['undecided','yes','no']).default('undecided'),
  overnightCapacity:z.number().int().min(1).max(99).nullable().default(null),
  guests:z.enum(['undecided','allowed','not_allowed']).default('undecided'),
  alcohol:z.enum(['undecided','yes','no']).default('undecided'),
  food:z.string().trim().max(500).refine(v=>!v.includes('\0')).default(''),
  clientRequestId:z.string().uuid().optional(),
}).strict().refine(v => (v.venue==='home'||v.overnight==='undecided') &&
  (v.overnight==='yes'?v.overnightCapacity!==null:v.overnightCapacity===null));
const eventParams=z.object({eventId:z.string().uuid()}).strict();
const cancelEventBody=z.object({expectedRevision:z.string().uuid()}).strict();
const editEventBody=z.object({expectedRevision:z.string().uuid(),title:z.string().trim().min(1).max(200).refine(v=>!v.includes('\0')),startsAt:z.iso.datetime().refine(v=>isCalendarDate(v.slice(0,10))),timezone:z.string().min(1).max(100).refine(v=>!v.includes('\0'))}).strict();
const pollParams=z.object({pollId:z.string().uuid()}).strict();
const commentParams=eventParams.extend({commentId:z.string().uuid()}).strict();
const commentBody=z.object({clientMessageId:z.string().uuid(),text:z.string().trim().min(1).max(5000).refine(v=>!v.includes('\0'))}).strict();
const commentQuery=z.object({after:z.string().uuid().optional()}).strict();
const conversationParams=z.object({conversationId:z.string().uuid()}).strict();
const directMessageParams=conversationParams.extend({messageId:z.string().uuid()}).strict();
const directCreateBody=z.object({recipientId:z.string().uuid()}).strict();


const pollString=z.string().trim().min(1).max(500).refine(v=>!v.includes('\0'));
const createPollBody=z.object({question:pollString,options:z.array(pollString).min(2).max(10)}).strict()
  .refine(v=>new Set(v.options.map(x=>x.toLowerCase())).size===v.options.length);
const voteBody=z.object({optionId:z.string().uuid().nullable()}).strict();

const proposalParams=eventParams.extend({proposalId:z.string().uuid()}).strict();
const hostProposalBody=z.object({hostId:z.string().uuid()}).strict();
const hostResponseBody=z.object({decision:z.enum(['accept','decline']),clearPreviousLocation:z.boolean().default(false)}).strict();
const hostConditionsBody=z.object({overnight:z.enum(['undecided','yes','no']),overnightCapacity:z.number().int().min(1).max(99).nullable()}).strict()
  .refine(v=>v.overnight==='yes'?v.overnightCapacity!==null:v.overnightCapacity===null);


const scheduleQuery = z.object({ from: z.string().refine(isCalendarDate), to: z.string().refine(isCalendarDate) }).strict()
  .refine(x => Date.parse(x.to + 'T00:00:00Z') >= Date.parse(x.from + 'T00:00:00Z') &&
    Date.parse(x.to + 'T00:00:00Z') - Date.parse(x.from + 'T00:00:00Z') <= 92 * 86400000);
export function isCalendarDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(value + 'T00:00:00Z');
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value &&
    parsed.getUTCFullYear() >= 1900 && parsed.getUTCFullYear() <= 2100;
}

type SessionUser = { id: string; email: string; displayName: string; accountRole: string; token: string };
type TripRole = 'owner' | 'editor' | 'viewer';
export function hashToken(token: string): string { return createHash('sha256').update(token).digest('hex'); }
export function csrfForToken(secret: string, token: string): string { return createHmac('sha256', secret).update('sobralis:csrf:v1:').update(token).digest('base64url'); }
export function equalCsrf(expected: string, actual: unknown): boolean {
  if (typeof actual !== 'string' || !tokenPattern.test(actual)) return false;
  const a = Buffer.from(expected), b = Buffer.from(actual);
  return a.length === b.length && timingSafeEqual(a, b);
}
function mutationAllowed(request: FastifyRequest, config: SecurityConfig): boolean {
  return request.headers.origin === config.PUBLIC_ORIGIN && /^application\/json(?:\s*;|$)/i.test(request.headers['content-type'] ?? '');
}
function badRequest(reply: FastifyReply) { return reply.code(400).send({ error: 'INVALID_INPUT' }); }
function notAuthenticated(reply: FastifyReply) { return reply.code(401).send({ error: 'UNAUTHENTICATED' }); }
function forbidden(reply: FastifyReply) { return reply.code(403).send({ error: 'FORBIDDEN' }); }
function isUniqueViolation(error: unknown): boolean { return typeof error === 'object' && error !== null && 'code' in error && error.code === '23505'; }

async function sessionFor(request: FastifyRequest, pool: Pool): Promise<SessionUser | null> {
  const token = request.cookies[sessionCookie];
  if (!token || !tokenPattern.test(token)) return null;
  const result = await pool.query<{id:string; email:string; display_name:string; account_role:string}>(
    `SELECT u.id, u.email, u.display_name, u.account_role
     FROM user_sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL`, [hashToken(token)]);
  const user = result.rows[0];
  return user ? { id: user.id, email: user.email, displayName: user.display_name, accountRole: user.account_role, token } : null;
}
async function roleForTrip(pool: Pool, tripId: string, userId: string): Promise<TripRole | null> {
  const result = await pool.query<{role:TripRole}>(
    `SELECT tm.role FROM trip_members tm
     JOIN trips t ON t.id = tm.trip_id AND t.community_id = tm.community_id
     JOIN communities c ON c.id = t.community_id
     JOIN community_members cm ON cm.community_id = tm.community_id AND cm.user_id = tm.user_id
     WHERE tm.trip_id = $1 AND tm.user_id = $2 AND tm.left_at IS NULL AND cm.left_at IS NULL AND t.deleted_at IS NULL AND c.deleted_at IS NULL`, [tripId, userId]);
  return result.rows[0]?.role ?? null;
}
async function rollback(client: PoolClient) { try { await client.query('ROLLBACK'); } catch { /* connection unavailable */ } }

export async function registerSecurity(app: FastifyInstance, pool: Pool, config: SecurityConfig, mailer: VerificationMailer | null) {
  if ((config.REGISTRATION_ENABLED==='true' || config.PASSWORD_RESET_ENABLED==='true') && !mailer) throw new Error('Verification email transport is required');
  await app.register(cookie);
  // In-memory limiter is scoped to one process. A shared store is required before multi-instance deployment.
  await app.register(rateLimit, { global: false, keyGenerator: request => request.ip });
  // Dummy hash prevents a fast verification path for non-existent accounts.
  const dummyHash = await argon2.hash(randomBytes(32).toString('base64url'), passwordOptions);
  let passwordOperations = 0;
  const passwordSlots = 4;
  // Public synthetic demo visitors share one proxy IP. Never enable this in production.
  const demoActionMax=(normal:number)=>config.DEMO_SHARED_ACTION_LIMIT==='true'?normal*5:normal;
  // One limiter per invitation kind/action is shared by the legacy URL and
  // body-token routes; keeping compatibility must not double the attempt budget.
  const communityPreviewLimit=app.rateLimit({max:demoActionMax(30),timeWindow:'1 minute'});
  const communityRedeemLimit=app.rateLimit({max:demoActionMax(10),timeWindow:'1 hour'});
  const tripPreviewLimit=app.rateLimit({max:demoActionMax(30),timeWindow:'1 minute'});
  const tripRedeemLimit=app.rateLimit({max:demoActionMax(10),timeWindow:'1 hour'});
  const inviteTokenBody=z.object({token:z.string().regex(tokenPattern)}).strict();

  // Only the currently configured, same-origin document paths and versions are public.
  // Production remains blocked by readSecurityConfig until legal review and deployment.
  app.get('/api/auth/registration-config', async (_request,reply)=>{
    if(config.REGISTRATION_ENABLED!=='true'||!mailer)return reply.header('Cache-Control','no-store').send({enabled:false});
    return reply.header('Cache-Control','no-store').send({enabled:true,documents:{
      dataConsent:{version:config.DATA_CONSENT_VERSION,url:config.DATA_CONSENT_URL},
      terms:{version:config.TERMS_VERSION,url:config.TERMS_URL}
    }});
  });

  app.post('/api/auth/register', { config: { rateLimit: { max: 4, timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!mutationAllowed(request,config)) return forbidden(reply);
    if (config.REGISTRATION_ENABLED!=='true' || !mailer) return reply.code(503).send({error:'REGISTRATION_DISABLED'});
    const parsed=registrationSchema.safeParse(request.body);if(!parsed.success)return badRequest(reply);
    const {email,displayName}=parsed.data;
    const token=randomBytes(32).toString('base64url');
    let deliver=false;
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      // Password is chosen only after the email owner follows the verification link.
      const result=await client.query<{id:string}>('INSERT INTO users (email,display_name) VALUES ($1,$2) RETURNING id',[email,displayName]);
      const userId=result.rows[0]?.id;if(!userId)throw new Error('User creation failed');
      const issued=await client.query<{issued:boolean}>('SELECT public.issue_email_verification($1,$2) AS issued',[userId,hashToken(token)]);
      if(!issued.rows[0]?.issued)throw new Error('Verification issuance failed');
      await client.query('COMMIT');deliver=true;
    } catch(error) {
      await rollback(client);if(!isUniqueViolation(error))throw error;
    } finally {client.release();}
    // Failure does not authenticate the account. User may retry after cooldown.
    if(deliver)try{await mailer.sendVerification(email,`${config.PUBLIC_ORIGIN}/verify-email#${token}`)}catch{console.error('Verification email delivery failed')}
    return reply.header('Cache-Control','no-store').code(202).send({status:'accepted'});
  });
  app.post('/api/auth/resend-verification', {config:{rateLimit:{max:3,timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    if(config.REGISTRATION_ENABLED!=='true'||!mailer)return reply.code(503).send({error:'REGISTRATION_DISABLED'});
    const body=resendSchema.safeParse(request.body);if(!body.success)return badRequest(reply);
    const user=await pool.query<{id:string}>('SELECT id FROM users WHERE lower(email)=$1 AND deleted_at IS NULL AND email_verified_at IS NULL',[body.data.email]);
    const token=randomBytes(32).toString('base64url');
    if(user.rows[0]){
      const issued=await pool.query<{issued:boolean}>('SELECT public.issue_email_verification($1,$2) AS issued',[user.rows[0].id,hashToken(token)]);
      if(issued.rows[0]?.issued)try{await mailer.sendVerification(body.data.email,`${config.PUBLIC_ORIGIN}/verify-email#${token}`)}catch{console.error('Verification email delivery failed')}
    }
    return reply.header('Cache-Control','no-store').code(202).send({status:'accepted'});
  });
  app.post('/api/auth/verify-email', {config:{rateLimit:{max:10,timeWindow:'15 minutes'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    if(config.REGISTRATION_ENABLED!=='true'||!mailer)return reply.code(503).send({error:'REGISTRATION_DISABLED'});
    const body=verifySchema.safeParse(request.body);if(!body.success)return badRequest(reply);
    // Client must have displayed the same document versions that are recorded.
    if(body.data.dataConsentVersion!==config.DATA_CONSENT_VERSION || body.data.termsVersion!==config.TERMS_VERSION)return reply.code(400).send({error:'DOCUMENT_VERSION_CHANGED'});
    const tokenHash=hashToken(body.data.token);
    const check=await pool.query<{valid:boolean}>('SELECT public.check_email_verification($1) AS valid',[tokenHash]);
    if(!check.rows[0]?.valid)return reply.code(400).send({error:'INVALID_OR_EXPIRED_TOKEN'});
    if(passwordOperations>=passwordSlots)return reply.code(503).send({error:'SERVICE_BUSY'});
    let passwordHash:string;passwordOperations++;
    try{passwordHash=await argon2.hash(body.data.password,passwordOptions)}finally{passwordOperations--}
    const ip=isIP(request.ip)?request.ip:null;
    const result=await pool.query<{verified:boolean}>(
      'SELECT public.consume_email_verification($1,$2,$3,$4,$5,$6,$7) AS verified',
      [tokenHash,passwordHash,ip,config.DATA_CONSENT_VERSION,config.DATA_CONSENT_URL,config.TERMS_VERSION,config.TERMS_URL]);
    if(!result.rows[0]?.verified)return reply.code(400).send({error:'INVALID_OR_EXPIRED_TOKEN'});
    return reply.header('Cache-Control','no-store').send({status:'verified'});
  });

  app.get('/api/auth/recovery-config', async (_request,reply)=>reply.header('Cache-Control','no-store').send({enabled:config.PASSWORD_RESET_ENABLED==='true'&&!!mailer}));
  app.post('/api/auth/request-password-reset', {config:{rateLimit:{max:3,timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    if(config.PASSWORD_RESET_ENABLED!=='true'||!mailer)return reply.code(503).send({error:'RECOVERY_DISABLED'});
    const body=resendSchema.safeParse(request.body);if(!body.success)return badRequest(reply);
    const token=randomBytes(32).toString('base64url');
    const issued=await pool.query<{issued:boolean}>('SELECT public.issue_password_reset($1,$2) AS issued',[body.data.email,hashToken(token)]);
    if(issued.rows[0]?.issued)try{await mailer.sendPasswordReset(body.data.email,`${config.PUBLIC_ORIGIN}/reset-password#${token}`)}catch{console.error('Password recovery email delivery failed')}
    return reply.header('Cache-Control','no-store').code(202).send({status:'accepted'});
  });
  app.post('/api/auth/reset-password', {config:{rateLimit:{max:10,timeWindow:'15 minutes'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    if(config.PASSWORD_RESET_ENABLED!=='true'||!mailer)return reply.code(503).send({error:'RECOVERY_DISABLED'});
    const body=resetSchema.safeParse(request.body);if(!body.success)return badRequest(reply);
    const tokenHash=hashToken(body.data.token),check=await pool.query<{valid:boolean}>('SELECT public.check_password_reset($1) AS valid',[tokenHash]);
    if(!check.rows[0]?.valid)return reply.code(400).send({error:'INVALID_OR_EXPIRED_TOKEN'});
    if(passwordOperations>=passwordSlots)return reply.code(503).send({error:'SERVICE_BUSY'});
    let passwordHash:string;passwordOperations++;try{passwordHash=await argon2.hash(body.data.password,passwordOptions)}finally{passwordOperations--}
    const done=await pool.query<{changed:boolean}>('SELECT public.consume_password_reset($1,$2) AS changed',[tokenHash,passwordHash]);
    if(!done.rows[0]?.changed)return reply.code(400).send({error:'INVALID_OR_EXPIRED_TOKEN'});
    return reply.header('Cache-Control','no-store').send({status:'changed'});
  });

  app.post('/api/auth/login', { config: { rateLimit: { max: config.DEMO_SHARED_LOGIN_LIMIT === 'true' ? 60 : 8, timeWindow: '15 minutes' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) return badRequest(reply);
    const result = await pool.query<{id:string; password_hash:string|null; email_verified_at:Date|null; recovery_generation:string}>(
      'SELECT id, password_hash, email_verified_at, recovery_generation FROM users WHERE lower(email) = $1 AND deleted_at IS NULL', [parsed.data.email]);
    const user = result.rows[0];
    if (passwordOperations >= passwordSlots) return reply.code(503).send({ error: 'SERVICE_BUSY' });
    let valid = false;
    passwordOperations++;
    try { valid = await argon2.verify(user?.password_hash ?? dummyHash, parsed.data.password); } catch { valid = false; } finally { passwordOperations--; }
    if (!user || !user.password_hash || !user.email_verified_at || !valid) return reply.code(401).send({ error: 'INVALID_CREDENTIALS' });
    const token = randomBytes(32).toString('base64url');
    const old=request.cookies[sessionCookie];
    const issued=await pool.query<{issued:boolean}>('SELECT public.issue_verified_session($1,$2,$3,$4,$5,$6) AS issued',
      [user.id,parsed.data.email,user.recovery_generation,user.password_hash,hashToken(token),old&&tokenPattern.test(old)?hashToken(old):null]);
    if(!issued.rows[0]?.issued)return reply.code(401).send({error:'INVALID_CREDENTIALS'});
    reply.setCookie(sessionCookie, token, { ...cookieOptions, maxAge: sessionSeconds });
    return reply.header('Cache-Control','no-store').send({ status: 'ok', csrfToken: csrfForToken(config.CSRF_SECRET, token) });
  });

  app.get('/api/auth/me', async (request, reply) => {
    const user = await sessionFor(request, pool);
    if (!user) return notAuthenticated(reply);
    return reply.header('Cache-Control','no-store').send({ user: { id:user.id, email:user.email, displayName:user.displayName, role:user.accountRole }, csrfToken:csrfForToken(config.CSRF_SECRET, user.token) });
  });
  app.post('/api/auth/logout', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const user = await sessionFor(request, pool);
    if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET, user.token), request.headers['x-csrf-token'])) return forbidden(reply);
    await pool.query('UPDATE user_sessions SET revoked_at = now() WHERE token_hash = $1 AND user_id = $2 AND revoked_at IS NULL', [hashToken(user.token), user.id]);
    reply.clearCookie(sessionCookie, cookieOptions);
    return reply.header('Cache-Control','no-store').send({ status:'ok' });
  });
  app.post('/api/auth/revoke-other-sessions', {config:{rateLimit:{max:5,timeWindow:'15 minutes'}}}, async (request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const body=z.object({password:z.string().min(1).max(128)}).strict().safeParse(request.body);if(!body.success)return badRequest(reply);
    const snapshot=await pool.query<{password_hash:string|null;recovery_generation:string}>(
      'SELECT password_hash,recovery_generation FROM users WHERE id=$1 AND deleted_at IS NULL AND email_verified_at IS NOT NULL',[user.id]);
    const row=snapshot.rows[0];if(passwordOperations>=passwordSlots)return reply.code(503).send({error:'SERVICE_BUSY'});
    let valid=false;passwordOperations++;try{valid=await argon2.verify(row?.password_hash??dummyHash,body.data.password)}catch{valid=false}finally{passwordOperations--}
    if(!row?.password_hash||!valid)return reply.code(401).send({error:'REAUTHENTICATION_FAILED'});
    const result=await pool.query<{revoked:number}>('SELECT public.revoke_other_sessions($1,$2,$3,$4) AS revoked',
      [user.id,hashToken(user.token),row.password_hash,row.recovery_generation]);
    const revoked=result.rows[0]?.revoked;if(revoked===undefined||revoked<0)return reply.code(401).send({error:'REAUTHENTICATION_FAILED'});
    return reply.header('Cache-Control','no-store').send({status:'ok',revoked});
  });
  app.get('/api/entitlements', async (request, reply) => {
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    const entitlements = await resolveEntitlements(pool, user.id);
    return reply.header('Cache-Control','no-store').send(entitlements);
  });
  app.get('/api/feature-access/:feature', async (request, reply) => {
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    const params = z.object({feature:z.string().regex(/^[A-Z][A-Z0-9_]{1,63}$/)}).strict().safeParse(request.params);
    if (!params.success) return badRequest(reply);
    const access = await hasFeature(pool, user.id, params.data.feature);
    if (access === 'unknown' || access === 'disabled') return reply.code(404).send({error:'FEATURE_NOT_AVAILABLE'});
    if (access === 'upgrade') return reply.code(403).send({error:'UPGRADE_REQUIRED'});
    return reply.header('Cache-Control','no-store').send({allowed:true});
  });
  app.post('/api/promos/redeem', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET, user.token), request.headers['x-csrf-token'])) return forbidden(reply);
    const body = z.object({code:z.string().regex(tokenPattern)}).strict().safeParse(request.body);
    if (!body.success) return badRequest(reply);
    const result = await pool.query<{status:string}>('SELECT public.redeem_promo($1,$2) AS status', [user.id, hashToken(body.data.code)]);
    const status=result.rows[0]?.status;
    if (status==='already_unlimited') return reply.code(409).send({error:'ALREADY_UNLIMITED'});
    if (status!=='redeemed') return reply.code(400).send({error:'INVALID_PROMO'});
    const access=await resolveEntitlements(pool,user.id);
    return reply.header('Cache-Control','no-store').send({status:'ok',entitlements:access});
  });
  app.get('/api/communities', async (request, reply) => {
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    const result = await pool.query<{id:string; name:string; role:string}>(
      `SELECT c.id, c.name, cm.role FROM communities c JOIN community_members cm ON cm.community_id = c.id
       WHERE cm.user_id = $1 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL ORDER BY c.name, c.id LIMIT 501`, [user.id]);
    if (result.rows.length > 500) return reply.code(422).send({ error:'TOO_MANY_COMMUNITIES' });
    return reply.header('Cache-Control','no-store').send({ communities: result.rows });
  });
  app.post('/api/communities', { config: { rateLimit: { max: demoActionMax(10), timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET, user.token), request.headers['x-csrf-token'])) return forbidden(reply);
    const body = communityBody.safeParse(request.body); if (!body.success) return badRequest(reply);
    // Older clients without a request ID retain their original behavior.
    if (!body.data.clientRequestId) {
      const result = await pool.query<{id:string;name:string}>(
        'SELECT * FROM public.create_community_for_owner($1, $2)', [body.data.name, user.id]);
      const community = result.rows[0]; if (!community) throw new Error('Community creation failed');
      return reply.header('Cache-Control','no-store').code(201).send({ community: {...community, role:'owner'} });
    }
    const result=await pool.query<{status:string;id:string|null;name:string|null;role:string|null}>(
      'SELECT * FROM public.create_community_once($1,$2,$3)',[user.id,body.data.clientRequestId,body.data.name]);
    const row=result.rows[0];if(row?.status==='conflict')return reply.code(409).send({error:'REQUEST_ID_CONFLICT'});
    if(row?.status==='unavailable')return reply.code(404).send({error:'NOT_FOUND'});
    if(row?.status!=='ok'||!row.id||!row.name||!row.role)throw new Error('Community creation failed');
    return reply.header('Cache-Control','no-store').code(201).send({community:{id:row.id,name:row.name,role:row.role}});
  });
  app.get('/api/communities/:communityId/members', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=communityParams.safeParse(request.params);if(!params.success)return badRequest(reply);
    const access=await pool.query(`SELECT 1 FROM community_members cm JOIN communities c ON c.id=cm.community_id
      WHERE cm.community_id=$1 AND cm.user_id=$2 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL`,[params.data.communityId,user.id]);
    if(!access.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    const r=await pool.query(`SELECT target.user_id AS id,u.display_name,target.role FROM community_members target
      JOIN users u ON u.id=target.user_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
      JOIN communities c ON c.id=target.community_id AND c.deleted_at IS NULL
      JOIN community_members viewer ON viewer.community_id=target.community_id AND viewer.user_id=$2 AND viewer.left_at IS NULL AND viewer.membership_scope='full'
      WHERE target.community_id=$1 AND target.left_at IS NULL AND target.membership_scope='full' ORDER BY u.display_name,target.user_id LIMIT 501`,[params.data.communityId,user.id]);
    if(r.rows.length>500)return reply.code(422).send({error:'TOO_MANY_MEMBERS'});
    return reply.header('Cache-Control','no-store').send({members:r.rows});
  });
  app.get('/api/communities/:communityId/invites', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=communityParams.safeParse(request.params),query=listTripsQuery.safeParse(request.query);
    if(!params.success||!query.success)return badRequest(reply);
    const access=await pool.query(`SELECT 1 FROM community_members cm JOIN communities c ON c.id=cm.community_id
      JOIN users u ON u.id=cm.user_id WHERE cm.community_id=$1 AND cm.user_id=$2
      AND cm.left_at IS NULL AND cm.membership_scope='full' AND cm.role='owner'
      AND c.deleted_at IS NULL AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL`,[params.data.communityId,user.id]);
    if(!access.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    // The database function repeats the authorization in the same query as the data read.
    const result=await pool.query<{invite_id:string;granted_role:string;max_uses:number;uses_count:number;created_at:Date;expires_at:Date;disabled_at:Date|null}>(
      'SELECT * FROM public.list_community_invites_for_owner($1,$2,$3)',[user.id,params.data.communityId,query.data.cursor??null]);
    const hasMore=result.rows.length>50,invites=result.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({invites,nextCursor:hasMore?invites.at(-1)!.invite_id:null});
  });
  app.post('/api/communities/:communityId/invites', {config:{rateLimit:{max:demoActionMax(10),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.safeParse(request.params),body=z.object({role:z.enum(['viewer','editor']),expiresInHours:z.number().int().min(1).max(720),maxUses:z.number().int().min(1).max(50)}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const token=randomBytes(32).toString('base64url');
    const r=await pool.query<{invite_id:string;expires_at:Date}>('SELECT * FROM public.create_community_invite($1,$2,$3,$4,$5,$6)',[user.id,params.data.communityId,hashToken(token),body.data.role,body.data.expiresInHours,body.data.maxUses]);
    if(!r.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer').code(201).send({inviteId:r.rows[0].invite_id,inviteUrl:`${config.PUBLIC_ORIGIN}/#community-invite=${token}`,role:body.data.role,expiresAt:r.rows[0].expires_at});
  });
  // Token-in-path routes are retained only for isolated compatibility tests;
  // production never registers them. Current clients use the JSON body.
  const communityPreview=async(request:FastifyRequest,reply:FastifyReply)=>{
    reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer');
    const legacy=request.method==='GET';
    if(!legacy&&!mutationAllowed(request,config))return forbidden(reply);
    const token=inviteTokenBody.safeParse(legacy?request.params:request.body);if(!token.success)return reply.code(404).send({error:'NOT_FOUND'});
    const r=await pool.query<{community_name:string;granted_role:string;expires_at:Date}>('SELECT * FROM public.preview_community_invite($1)',[hashToken(token.data.token)]);
    if(!r.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({preview:{communityName:r.rows[0].community_name,role:r.rows[0].granted_role,expiresAt:r.rows[0].expires_at}});
  };
  if(config.legacyInviteUrlsEnabled)app.get('/api/community-invites/:token/preview',{onRequest:communityPreviewLimit},communityPreview);
  app.post('/api/community-invites/preview',{onRequest:communityPreviewLimit},communityPreview);
  const communityRedeem=async(request:FastifyRequest,reply:FastifyReply)=>{
    reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer');
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const legacy=request.routeOptions.url==='/api/community-invites/:token/redeem';
    const token=inviteTokenBody.safeParse(legacy?request.params:request.body);
    if(!token.success||(legacy&&!z.object({}).strict().safeParse(request.body).success))return badRequest(reply);
    const r=await pool.query<{result:string;community_id:string|null}>('SELECT * FROM public.redeem_community_invite($1,$2)',[user.id,hashToken(token.data.token)]);
    const x=r.rows[0];if(!x||x.result==='invalid'||!x.community_id)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({status:x.result,communityId:x.community_id});
  };
  if(config.legacyInviteUrlsEnabled)app.post('/api/community-invites/:token/redeem',{onRequest:communityRedeemLimit},communityRedeem);
  app.post('/api/community-invites/redeem',{onRequest:communityRedeemLimit},communityRedeem);
  app.delete('/api/communities/:communityId/invites/:inviteId',{config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}},async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.extend({inviteId:z.string().uuid()}).strict().safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{disabled:boolean}>('SELECT public.disable_community_invite($1,$2,$3) AS disabled',[user.id,params.data.communityId,params.data.inviteId]);
    if(!r.rows[0]?.disabled)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').send({status:'disabled'});
  });
  app.get('/api/communities/:communityId/schedules', async (request, reply) => {
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    const params = communityParams.safeParse(request.params), range = scheduleQuery.safeParse(request.query);
    if (!params.success || !range.success) return badRequest(reply);
    const membership = await pool.query<{role:string}>(
      `SELECT cm.role FROM community_members cm JOIN communities c ON c.id=cm.community_id
       WHERE cm.community_id=$1 AND cm.user_id=$2 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL`, [params.data.communityId, user.id]);
    if (!membership.rows[0]) return reply.code(404).send({ error:'NOT_FOUND' });
    // Recheck membership in the actual SELECT as well: a revoked member gets no data.
    const result = await pool.query(
      `SELECT s.user_id, u.display_name, s.local_date, s.status, s.updated_at
       FROM schedule_entries s
       JOIN users u ON u.id=s.user_id AND u.deleted_at IS NULL
       JOIN communities c ON c.id=s.community_id AND c.deleted_at IS NULL
       JOIN community_members owner ON owner.community_id=s.community_id AND owner.user_id=s.user_id AND owner.left_at IS NULL AND owner.membership_scope='full'
       JOIN community_members viewer ON viewer.community_id=s.community_id AND viewer.user_id=$2 AND viewer.left_at IS NULL AND viewer.membership_scope='full'
       WHERE s.community_id=$1 AND s.local_date >= $3::date AND s.local_date <= $4::date
       ORDER BY s.local_date, s.user_id LIMIT 5001`, [params.data.communityId, user.id, range.data.from, range.data.to]);
    if (result.rows.length > 5000) return reply.code(422).send({ error:'RANGE_TOO_LARGE' });
    return reply.header('Cache-Control','no-store').send({ entries: result.rows });
  });
  app.put('/api/communities/:communityId/schedules/:date', { config: { rateLimit: { max: demoActionMax(120), timeWindow: '1 minute' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET, user.token), request.headers['x-csrf-token'])) return forbidden(reply);
    const params = scheduleParams.safeParse(request.params), body = scheduleBody.safeParse(request.body);
    if (!params.success || !body.success) return badRequest(reply);
    // Use the same locked authorization path as range writes. Keep its locks
    // until the returned entry is read, so a concurrent removal/downgrade cannot
    // pass authorization and commit a write after revocation has won.
    const client=await pool.connect();
    try {
      await client.query('BEGIN');
      const result=await client.query<{updated:boolean}>('SELECT public.write_schedule_range($1,$2,$1,$3,$3,$4) AS updated',
        [user.id,params.data.communityId,params.data.date,body.data.status]);
      if(result.rows[0]?.updated){
        const entry=await client.query<{local_date:string;status:string;updated_at:Date}>(
          'SELECT local_date,status,updated_at FROM schedule_entries WHERE community_id=$1 AND user_id=$2 AND local_date=$3::date',
          [params.data.communityId,user.id,params.data.date]);
        if(!entry.rows[0])throw new Error('Schedule write did not return an entry');
        await client.query('COMMIT');
        return reply.header('Cache-Control','no-store').send({entry:entry.rows[0]});
      }
      const member=await client.query<{role:string}>(`SELECT cm.role FROM community_members cm JOIN communities c ON c.id=cm.community_id
        WHERE cm.community_id=$1 AND cm.user_id=$2 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL`,[params.data.communityId,user.id]);
      await client.query('COMMIT');
      if(!member.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
      return forbidden(reply);
    } catch(e) { await client.query('ROLLBACK');throw e; }
    finally {client.release();}
  });
  app.put('/api/communities/:communityId/schedule-range', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.safeParse(request.params);
    const body=z.object({ownerId:z.string().uuid(),from:z.string().refine(isCalendarDate),to:z.string().refine(isCalendarDate),status:z.enum(['free','work','busy','unknown'])}).strict()
      .refine(x=>Date.parse(x.to+'T00:00:00Z')>=Date.parse(x.from+'T00:00:00Z')&&Date.parse(x.to+'T00:00:00Z')-Date.parse(x.from+'T00:00:00Z')<=30*86400000).safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const b=body.data,r=await pool.query<{updated:boolean}>('SELECT public.write_schedule_range($1,$2,$3,$4,$5,$6) AS updated',[user.id,params.data.communityId,b.ownerId,b.from,b.to,b.status]);
    if(!r.rows[0]?.updated)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').send({status:'updated',days:Math.floor((Date.parse(b.to+'T00:00:00Z')-Date.parse(b.from+'T00:00:00Z'))/86400000)+1});
  });
  // Narrow delegation: a user gives another active member permission to edit
  // that user's schedule only. All authority is rechecked inside SQL functions.
  app.get('/api/communities/:communityId/schedule-delegations', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=communityParams.safeParse(request.params);if(!params.success)return badRequest(reply);
    const member=await pool.query(`SELECT 1 FROM community_members cm JOIN communities c ON c.id=cm.community_id
      WHERE cm.community_id=$1 AND cm.user_id=$2 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL`,[params.data.communityId,user.id]);
    if(!member.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    const r=await pool.query('SELECT * FROM public.list_schedule_delegations($1,$2)',[user.id,params.data.communityId]);
    if(r.rows.length>500)return reply.code(422).send({error:'TOO_MANY_DELEGATIONS'});
    return reply.send({delegations:r.rows});
  });
  app.post('/api/communities/:communityId/schedule-delegations', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.safeParse(request.params),body=z.object({delegateId:z.string().uuid()}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{id:string|null}>('SELECT public.grant_schedule_delegate($1,$2,$3) AS id',[user.id,params.data.communityId,body.data.delegateId]);
    if(!r.rows[0]?.id)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.code(201).send({id:r.rows[0].id});
  });
  app.delete('/api/communities/:communityId/schedule-delegations/:delegationId', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.extend({delegationId:z.string().uuid()}).strict().safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{revoked:boolean}>('SELECT public.revoke_schedule_delegate($1,$2,$3) AS revoked',[user.id,params.data.communityId,params.data.delegationId]);
    if(!r.rows[0]?.revoked)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({status:'revoked'});
  });
  app.put('/api/communities/:communityId/schedules/:date/delegated/:ownerId', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=scheduleParams.extend({ownerId:z.string().uuid()}).strict().safeParse(request.params),body=scheduleBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{updated:boolean}>('SELECT public.write_delegated_schedule($1,$2,$3,$4,$5) AS updated',[user.id,params.data.communityId,params.data.ownerId,params.data.date,body.data.status]);
    if(!r.rows[0]?.updated)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({status:'updated'});
  });
  app.post('/api/communities/:communityId/trips', { config: { rateLimit: { max: demoActionMax(20), timeWindow: '1 hour' } } }, async (request,reply) => {
    if (!mutationAllowed(request,config)) return forbidden(reply);
    const user=await sessionFor(request,pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token'])) return forbidden(reply);
    const params=communityParams.safeParse(request.params),body=createTripBody.safeParse(request.body);
    if (!params.success || !body.success) return badRequest(reply);
    type TripCreation={result:string;trip_id:string|null;title:string|null;timezone:string|null;role?:TripRole};
    const result=body.data.clientRequestId
      ? await pool.query<TripCreation>('SELECT * FROM public.create_trip_once($1,$2,$3,$4,$5)',[params.data.communityId,user.id,body.data.clientRequestId,body.data.title,body.data.timezone])
      : await pool.query<TripCreation>('SELECT * FROM public.create_trip_for_member($1,$2,$3,$4)',[params.data.communityId,user.id,body.data.title,body.data.timezone]);
    const created=result.rows[0];
    if (!created || created.result==='not_found') return reply.code(404).send({error:'NOT_FOUND'});
    if (created.result==='forbidden') return forbidden(reply);
    if (created.result==='invalid') return badRequest(reply);
    if (created.result==='conflict') return reply.code(409).send({error:'REQUEST_CONFLICT'});
    if (created.result!=='created' || !created.trip_id) throw new Error('Unexpected trip creation result');
    return reply.header('Cache-Control','no-store').code(201).send({trip:{id:created.trip_id,communityId:params.data.communityId,title:created.title,timezone:created.timezone,role:created.role??'owner'}});
  });
  app.get('/api/trips', { config: { rateLimit: { max: demoActionMax(120), timeWindow: '1 minute' } } }, async (request,reply) => {
    const user=await sessionFor(request,pool);if (!user) return notAuthenticated(reply);
    const query=listTripsQuery.safeParse(request.query);if (!query.success) return badRequest(reply);
    // Keyset pagination returns only the caller's active trip memberships. A
    // trip-only member may discover that trip but not the community calendar.
    const result=await pool.query<{id:string;community_id:string;title:string;timezone:string;role:TripRole}>(
      `SELECT t.id,t.community_id,t.title,t.timezone,t.starts_on,t.ends_on,t.revision,tm.role FROM trips t
       JOIN communities c ON c.id=t.community_id AND c.deleted_at IS NULL
       JOIN trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.user_id=$1 AND tm.left_at IS NULL
       JOIN community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id AND cm.left_at IS NULL
       WHERE t.deleted_at IS NULL AND ($2::uuid IS NULL OR t.id>$2::uuid)
       ORDER BY t.id LIMIT 51`,[user.id,query.data.cursor??null]);
    const hasMore=result.rows.length>50, trips=result.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({trips,nextCursor:hasMore?trips.at(-1)!.id:null});
  });
  app.get('/api/trips/:tripId/members', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=tripParams.safeParse(request.params),query=listTripsQuery.safeParse(request.query);
    if(!params.success||!query.success)return badRequest(reply);
    if(!await roleForTrip(pool,params.data.tripId,user.id))return reply.code(404).send({error:'NOT_FOUND'});
    // Recheck the viewer's active membership in the same statement; never
    // expose the parent community or inactive/unverified member information.
    const r=await pool.query<{id:string;display_name:string;role:TripRole}>(`
      SELECT u.id,u.display_name,tm.role FROM trips t
      JOIN communities c ON c.id=t.community_id AND c.deleted_at IS NULL
      JOIN trip_members me ON me.trip_id=t.id AND me.community_id=t.community_id AND me.user_id=$1 AND me.left_at IS NULL
      JOIN community_members mycm ON mycm.community_id=t.community_id AND mycm.user_id=$1 AND mycm.left_at IS NULL
      JOIN users viewer ON viewer.id=$1 AND viewer.deleted_at IS NULL AND viewer.email_verified_at IS NOT NULL
      JOIN trip_members tm ON tm.trip_id=t.id AND tm.community_id=t.community_id AND tm.left_at IS NULL
      JOIN community_members cm ON cm.community_id=tm.community_id AND cm.user_id=tm.user_id AND cm.left_at IS NULL
      JOIN users u ON u.id=tm.user_id AND u.deleted_at IS NULL AND u.email_verified_at IS NOT NULL
      WHERE t.id=$2 AND t.deleted_at IS NULL AND ($3::uuid IS NULL OR u.id>$3::uuid)
      ORDER BY u.id LIMIT 51`,[user.id,params.data.tripId,query.data.cursor??null]);
    const more=r.rows.length>50,members=r.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({members,nextCursor:more?members.at(-1)!.id:null});
  });
  // Both operations only change trip membership. History and community
  // membership are intentionally retained; active links may permit re-entry.
  for(const own of [true,false] as const){
    const path=own?'/api/trips/:tripId/membership':'/api/trips/:tripId/members/:memberId';
    app.delete(path,{config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}},async(request,reply)=>{
      if(!mutationAllowed(request,config))return forbidden(reply);
      const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
      if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
      const params=(own?tripParams:tripParams.extend({memberId:z.string().uuid()}).strict()).safeParse(request.params);
      const body=z.object({}).strict().safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
      const target=own?user.id:('memberId' in params.data?params.data.memberId:undefined);
      const r=await pool.query<{result:string}>('SELECT public.remove_trip_member($1,$2,$3) AS result',[user.id,params.data.tripId,target]);
      const status=r.rows[0]?.result;
      if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
      if(status==='owner_restricted')return reply.code(409).send({error:'OWNER_CANNOT_LEAVE'});
      if(status!=='removed')throw new Error('Unexpected trip membership result');
      return reply.header('Cache-Control','no-store').send({status:'removed'});
    });
  }
  // Scope is part of the route, never a user-supplied organizer or role.
  for (const scope of ['community','trip'] as const) {
    const path=scope==='community'?'/api/communities/:communityId/events':'/api/trips/:tripId/events';
    app.post(path, {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
      if(!mutationAllowed(request,config))return forbidden(reply);
      const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
      if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
      const params=scope==='community'?communityParams.safeParse(request.params):tripParams.safeParse(request.params);
      const body=eventBody.safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
      const scopeId='communityId' in params.data?params.data.communityId:params.data.tripId;
      const b=body.data;
      const args=[user.id,scope,scopeId,b.title,b.description,b.location,b.startsAt,b.timezone,b.venue,b.overnight,b.overnightCapacity,b.guests,b.alcohol,b.food];
      const result=b.clientRequestId
        ?await pool.query<{result:string;event:Record<string,unknown>|null;host_active:boolean|null}>(
          'SELECT * FROM public.create_event_once($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',[user.id,b.clientRequestId,...args.slice(1)])
        :await pool.query<{result:string;event:Record<string,unknown>|null;host_active?:boolean|null}>(
          'SELECT * FROM public.create_event_for_member($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',args);
      const row=result.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
      if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
      if(row.result==='conflict')return reply.code(409).send({error:'EVENT_REQUEST_CONFLICT'});
      if(row.result!=='created'||!row.event)throw new Error('Unexpected event creation result');
      // Normalize timestamptz returned inside JSONB independently of DB timezone.
      for(const field of ['starts_at','created_at','updated_at'])row.event[field]=new Date(String(row.event[field])).toISOString();
      row.event.host_active=b.clientRequestId?row.host_active:(row.event.venue_type==='home'?true:null);
      return reply.header('Cache-Control','no-store').code(201).send({event:row.event});
    });
    app.get(path, {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
      const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
      const params=scope==='community'?communityParams.safeParse(request.params):tripParams.safeParse(request.params);
      const query=listTripsQuery.safeParse(request.query);if(!params.success||!query.success)return badRequest(reply);
      const scopeId='communityId' in params.data?params.data.communityId:params.data.tripId;
      if(scope==='trip') {if(!await roleForTrip(pool,scopeId,user.id))return reply.code(404).send({error:'NOT_FOUND'});}
      else {
        const allowed=await pool.query(`SELECT 1 FROM community_members cm JOIN communities c ON c.id=cm.community_id
          WHERE cm.community_id=$1 AND cm.user_id=$2 AND cm.left_at IS NULL AND cm.membership_scope='full' AND c.deleted_at IS NULL`,[scopeId,user.id]);
        if(!allowed.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
      }
      const result=await pool.query('SELECT e.*,public.event_host_currently_active($1,e.id) AS host_active FROM public.list_events_for_member($1,$2,$3,$4) e',[user.id,scope,scopeId,query.data.cursor??null]);
      const hasMore=result.rows.length>50,events=result.rows.slice(0,50);
      return reply.header('Cache-Control','no-store').send({events,nextCursor:hasMore?events.at(-1)!.id:null});
    });
  }
  app.get('/api/events/:eventId', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=eventParams.safeParse(request.params);if(!params.success)return badRequest(reply);
    const result=await pool.query('SELECT e.*,public.event_host_currently_active($1,e.id) AS host_active FROM public.get_event_for_member($1,$2) e',[user.id,params.data.eventId]);
    if(!result.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').send({event:result.rows[0]});
  });
  app.patch('/api/events/:eventId', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=editEventBody.safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const b=body.data,result=await pool.query<{result:string}>('SELECT public.edit_event_for_member($1,$2,$3,$4,$5,$6) AS result',[user.id,params.data.eventId,b.expectedRevision,b.title,b.startsAt,b.timezone]);
    const outcome=result.rows[0]?.result;if(outcome==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(outcome==='forbidden')return forbidden(reply);
    if(outcome==='conflict')return reply.code(409).send({error:'EVENT_CHANGED'});if(outcome==='host_confirmation_required')return reply.code(409).send({error:'HOST_CONFIRMATION_REQUIRED'});
    if(outcome==='invalid')return badRequest(reply);if(outcome!=='updated')throw new Error('Unexpected event edit result');
    return reply.header('Cache-Control','no-store').send({status:'updated'});
  });
  app.delete('/api/events/:eventId', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=cancelEventBody.safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const result=await pool.query<{result:string}>('SELECT public.cancel_event_for_member($1,$2,$3) AS result',[user.id,params.data.eventId,body.data.expectedRevision]);
    const outcome=result.rows[0]?.result;if(outcome==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(outcome==='forbidden')return forbidden(reply);
    if(outcome==='conflict')return reply.code(409).send({error:'EVENT_CHANGED'});if(outcome==='invalid')return badRequest(reply);
    if(outcome!=='cancelled')throw new Error('Unexpected event cancellation result');
    return reply.header('Cache-Control','no-store').send({status:'cancelled'});
  });
  app.post('/api/events/:eventId/polls', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=createPollBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string;poll_id:string|null}>('SELECT * FROM public.create_event_poll($1,$2,$3,$4)',
      [user.id,params.data.eventId,body.data.question,body.data.options]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
    if(row.result!=='created'||!row.poll_id)throw new Error('Unexpected poll creation result');
    return reply.header('Cache-Control','no-store').code(201).send({pollId:row.poll_id});
  });
  app.get('/api/events/:eventId/polls', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=eventParams.safeParse(request.params),query=listTripsQuery.safeParse(request.query);
    if(!params.success||!query.success)return badRequest(reply);
    const access=await pool.query('SELECT 1 FROM public.get_event_for_member($1,$2)',[user.id,params.data.eventId]);
    if(!access.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    const result=await pool.query('SELECT * FROM public.list_event_polls($1,$2,$3)',[user.id,params.data.eventId,query.data.cursor??null]);
    const hasMore=result.rows.length>50,polls=result.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({polls,nextCursor:hasMore?polls.at(-1)!.id:null});
  });
  app.put('/api/polls/:pollId/vote', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=pollParams.safeParse(request.params),body=voteBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.set_event_poll_vote($1,$2,$3) AS result',[user.id,params.data.pollId,body.data.optionId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status==='invalid_option')return badRequest(reply);
    if(status!=='voted'&&status!=='withdrawn')throw new Error('Unexpected vote result');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.post('/api/events/:eventId/comments', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=commentBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string;comment_id:string|null}>('SELECT * FROM public.create_event_comment($1,$2,$3,$4)',
      [user.id,params.data.eventId,body.data.clientMessageId,body.data.text]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
    if(row.result==='conflict')return reply.code(409).send({error:'MESSAGE_ID_CONFLICT'});
    if(!row.comment_id||(row.result!=='created'&&row.result!=='existing'))throw new Error('Unexpected comment creation result');
    return reply.header('Cache-Control','no-store').code(row.result==='created'?201:200).send({status:row.result,commentId:row.comment_id});
  });
  app.get('/api/events/:eventId/comments', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=eventParams.safeParse(request.params),query=commentQuery.safeParse(request.query);
    if(!params.success||!query.success)return badRequest(reply);
    const r=await pool.query<{result:string;comments:Array<{createdAt:string}>|null;next_cursor:string|null;has_more:boolean}>(
      'SELECT * FROM public.list_event_comments($1,$2,$3)',[user.id,params.data.eventId,query.data.after??null]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='invalid_cursor')return badRequest(reply);
    if(row.result!=='ok'||!row.comments)throw new Error('Unexpected comment list result');
    for(const comment of row.comments)comment.createdAt=new Date(comment.createdAt).toISOString();
    return reply.header('Cache-Control','no-store').send({comments:row.comments,nextCursor:row.next_cursor,hasMore:row.has_more});
  });
  app.delete('/api/events/:eventId/comments/:commentId', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=commentParams.safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.delete_event_comment($1,$2,$3) AS result',[user.id,params.data.eventId,params.data.commentId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status!=='deleted')throw new Error('Unexpected comment deletion result');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.post('/api/communities/:communityId/direct-conversations', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=communityParams.safeParse(request.params),body=directCreateBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string;conversation_id:string|null}>('SELECT * FROM public.create_direct_conversation($1,$2,$3)',[user.id,params.data.communityId,body.data.recipientId]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
    if(!row.conversation_id||(row.result!=='created'&&row.result!=='existing'))throw new Error('Unexpected direct creation result');
    return reply.header('Cache-Control','no-store').code(row.result==='created'?201:200).send({status:row.result,conversationId:row.conversation_id});
  });
  app.get('/api/direct-conversations', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const query=listTripsQuery.safeParse(request.query);if(!query.success)return badRequest(reply);
    const r=await pool.query('SELECT * FROM public.list_direct_conversations($1,$2)',[user.id,query.data.cursor??null]);
    const hasMore=r.rows.length>50,conversations=r.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({conversations,nextCursor:hasMore?conversations.at(-1)!.id:null});
  });
  app.post('/api/direct-conversations/:conversationId/messages', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=conversationParams.safeParse(request.params),body=commentBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string;message_id:string|null}>('SELECT * FROM public.send_direct_message($1,$2,$3,$4)',
      [user.id,params.data.conversationId,body.data.clientMessageId,body.data.text]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
    if(row.result==='conflict')return reply.code(409).send({error:'MESSAGE_ID_CONFLICT'});
    if(row.result==='peer_unavailable')return reply.code(409).send({error:'RECIPIENT_UNAVAILABLE'});
    if(!row.message_id||(row.result!=='created'&&row.result!=='existing'))throw new Error('Unexpected direct message result');
    return reply.header('Cache-Control','no-store').code(row.result==='created'?201:200).send({status:row.result,messageId:row.message_id});
  });
  app.get('/api/direct-conversations/:conversationId/messages', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=conversationParams.safeParse(request.params),query=commentQuery.safeParse(request.query);
    if(!params.success||!query.success)return badRequest(reply);
    const r=await pool.query<{result:string;messages:Array<{createdAt:string}>|null;next_cursor:string|null;has_more:boolean}>(
      'SELECT * FROM public.list_direct_messages($1,$2,$3)',[user.id,params.data.conversationId,query.data.after??null]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(row.result==='invalid_cursor')return badRequest(reply);
    if(row.result!=='ok'||!row.messages)throw new Error('Unexpected direct message list result');
    for(const message of row.messages)message.createdAt=new Date(message.createdAt).toISOString();
    return reply.header('Cache-Control','no-store').send({messages:row.messages,nextCursor:row.next_cursor,hasMore:row.has_more});
  });
  app.delete('/api/direct-conversations/:conversationId/messages/:messageId', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 minute'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=directMessageParams.safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.delete_direct_message($1,$2,$3) AS result',[user.id,params.data.conversationId,params.data.messageId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status!=='deleted')throw new Error('Unexpected direct message deletion');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.get('/api/events/:eventId/change-proposal',{config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}},async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=eventParams.safeParse(request.params);if(!params.success)return badRequest(reply);
    const access=await pool.query('SELECT 1 FROM public.get_event_for_member($1,$2)',[user.id,params.data.eventId]);if(!access.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    const r=await pool.query('SELECT * FROM public.get_event_change($1,$2)',[user.id,params.data.eventId]);
    return reply.header('Cache-Control','no-store').send({proposal:r.rows[0]??null});
  });
  app.post('/api/events/:eventId/change-proposals',{config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}},async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=editEventBody.safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const b=body.data,r=await pool.query<{result:string;proposal_id:string|null}>('SELECT * FROM public.propose_event_change($1,$2,$3,$4,$5,$6)',[user.id,params.data.eventId,b.expectedRevision,b.title,b.startsAt,b.timezone]);
    const row=r.rows[0];if(!row||row.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(row.result==='forbidden')return forbidden(reply);if(row.result==='invalid')return badRequest(reply);
    if(row.result==='conflict')return reply.code(409).send({error:'EVENT_CHANGED'});if(row.result==='pending')return reply.code(409).send({error:'CHANGE_ALREADY_PENDING'});
    if(row.result==='host_unavailable')return reply.code(409).send({error:'HOST_UNAVAILABLE'});if(row.result==='unchanged')return reply.code(409).send({error:'NO_CHANGE'});
    if(row.result!=='created'||!row.proposal_id)throw new Error('Unexpected event change proposal');return reply.header('Cache-Control','no-store').code(201).send({status:'pending',proposalId:row.proposal_id});
  });
  app.post('/api/events/:eventId/change-proposals/:proposalId/respond',{config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 hour'}}},async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=proposalParams.safeParse(request.params),body=z.object({decision:z.enum(['accept','decline'])}).strict().safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.respond_event_change($1,$2,$3,$4) result',[user.id,params.data.eventId,params.data.proposalId,body.data.decision]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(status==='invalid')return badRequest(reply);if(status==='stale')return reply.code(409).send({error:'CHANGE_PROPOSAL_STALE'});
    if(status!=='accepted'&&status!=='declined')throw new Error('Unexpected event change response');return reply.header('Cache-Control','no-store').send({status});
  });
  app.delete('/api/events/:eventId/change-proposals/:proposalId',{config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}},async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=proposalParams.safeParse(request.params),body=z.object({}).strict().safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.cancel_event_change($1,$2,$3) result',[user.id,params.data.eventId,params.data.proposalId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(status==='forbidden')return forbidden(reply);if(status!=='cancelled')throw new Error('Unexpected event change cancellation');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.get('/api/events/:eventId/host-proposal', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=eventParams.safeParse(request.params);if(!params.success)return badRequest(reply);
    const access=await pool.query('SELECT 1 FROM public.get_event_for_member($1,$2)',[user.id,params.data.eventId]);
    if(!access.rows[0])return reply.code(404).send({error:'NOT_FOUND'});
    const pending=await pool.query('SELECT * FROM public.get_pending_event_host($1,$2)',[user.id,params.data.eventId]);
    return reply.header('Cache-Control','no-store').send({proposal:pending.rows[0]??null});
  });
  app.post('/api/events/:eventId/host-proposals', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=hostProposalBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string;proposal_id:string|null;expires_at:Date|null}>('SELECT * FROM public.propose_event_host($1,$2,$3)',[user.id,params.data.eventId,body.data.hostId]);
    const x=r.rows[0];if(!x||x.result==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(x.result==='forbidden')return forbidden(reply);if(x.result==='invalid')return badRequest(reply);
    if(x.result==='already_host')return reply.code(409).send({error:'ALREADY_HOST'});
    if(x.result!=='pending'||!x.proposal_id)throw new Error('Unexpected host proposal result');
    return reply.header('Cache-Control','no-store').send({status:'pending',proposalId:x.proposal_id,expiresAt:x.expires_at});
  });
  app.post('/api/events/:eventId/host-proposals/:proposalId/respond', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=proposalParams.safeParse(request.params),body=hostResponseBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.respond_event_host($1,$2,$3,$4,$5) AS result',
      [user.id,params.data.eventId,params.data.proposalId,body.data.decision,body.data.clearPreviousLocation]);
    const status=r.rows[0]?.result;
    if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='stale')return reply.code(409).send({error:'PROPOSAL_NOT_PENDING'});
    if(status==='location_confirmation_required')return reply.code(409).send({error:'LOCATION_CONFIRMATION_REQUIRED'});
    if(status==='invalid')return badRequest(reply);
    if(status!=='accepted'&&status!=='declined')throw new Error('Unexpected host response');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.delete('/api/events/:eventId/host-proposals/:proposalId', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=proposalParams.safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.cancel_event_host($1,$2,$3) AS result',[user.id,params.data.eventId,params.data.proposalId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status!=='cancelled')throw new Error('Unexpected host cancellation');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.delete('/api/events/:eventId/hosting', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=z.object({}).strict().safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.withdraw_event_host_consent($1,$2) AS result',[user.id,params.data.eventId]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status!=='revoked')throw new Error('Unexpected hosting revocation');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.put('/api/events/:eventId/hosting', {config:{rateLimit:{max:demoActionMax(60),timeWindow:'1 hour'}}}, async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=eventParams.safeParse(request.params),body=hostConditionsBody.safeParse(request.body);
    if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.set_event_host_conditions($1,$2,$3,$4) AS result',
      [user.id,params.data.eventId,body.data.overnight,body.data.overnightCapacity]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(status==='forbidden')return forbidden(reply);if(status==='invalid')return badRequest(reply);
    if(status!=='updated')throw new Error('Unexpected hosting result');
    return reply.header('Cache-Control','no-store').send({status});
  });
  app.get('/api/trips/:tripId/invites', {config:{rateLimit:{max:demoActionMax(120),timeWindow:'1 minute'}}}, async(request,reply)=>{
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    const params=tripParams.safeParse(request.params),query=listTripsQuery.safeParse(request.query);if(!params.success||!query.success)return badRequest(reply);
    if(await roleForTrip(pool,params.data.tripId,user.id)!=='owner')return reply.code(404).send({error:'NOT_FOUND'});
    // Repeat authorization in the same database statement as the actual read.
    const result=await pool.query<{invite_id:string;granted_role:string;max_uses:number;uses_count:number;created_at:Date;expires_at:Date;disabled_at:Date|null}>(
      'SELECT * FROM public.list_trip_invites_for_owner($1,$2,$3)',[user.id,params.data.tripId,query.data.cursor??null]);
    const hasMore=result.rows.length>50,invites=result.rows.slice(0,50);
    return reply.header('Cache-Control','no-store').send({invites,nextCursor:hasMore?invites.at(-1)!.invite_id:null});
  });
  app.post('/api/trips/:tripId/invites', { config: { rateLimit: { max: demoActionMax(10), timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!mutationAllowed(request,config)) return forbidden(reply);
    const user = await sessionFor(request,pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token'])) return forbidden(reply);
    const params=tripParams.safeParse(request.params);
    const body=z.object({role:z.enum(['viewer','editor']),expiresInHours:z.number().int().min(1).max(720),maxUses:z.number().int().min(1).max(50)}).strict().safeParse(request.body);
    if (!params.success || !body.success) return badRequest(reply);
    const token=randomBytes(32).toString('base64url');
    const result=await pool.query<{invite_id:string;expires_at:Date}>(
      'SELECT * FROM public.create_trip_invite($1,$2,$3,$4,$5,$6)',[user.id,params.data.tripId,hashToken(token),body.data.role,body.data.expiresInHours,body.data.maxUses]);
    if (!result.rows[0]) return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer').code(201).send({
      inviteId:result.rows[0].invite_id,inviteUrl:`${config.PUBLIC_ORIGIN}/#trip-invite=${token}`,role:body.data.role,expiresAt:result.rows[0].expires_at});
  });
  app.delete('/api/trips/:tripId/invites/:inviteId', { config: { rateLimit: { max: demoActionMax(30), timeWindow: '1 hour' } } }, async (request, reply) => {
    if (!mutationAllowed(request,config)) return forbidden(reply);
    const user=await sessionFor(request,pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token'])) return forbidden(reply);
    const params=z.object({tripId:z.string().uuid(),inviteId:z.string().uuid()}).strict().safeParse(request.params);
    if (!params.success) return badRequest(reply);
    const result=await pool.query<{disabled:boolean}>('SELECT public.disable_trip_invite($1,$2,$3) AS disabled',[user.id,params.data.tripId,params.data.inviteId]);
    if (!result.rows[0]?.disabled) return reply.code(404).send({error:'NOT_FOUND'});
    return reply.header('Cache-Control','no-store').send({status:'disabled'});
  });
  const tripPreview=async(request:FastifyRequest,reply:FastifyReply)=>{
    reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer');
    const legacy=request.method==='GET';
    if(!legacy&&!mutationAllowed(request,config))return forbidden(reply);
    const token=inviteTokenBody.safeParse(legacy?request.params:request.body);
    if(!token.success)return reply.code(404).send({error:'NOT_FOUND'});
    const result=await pool.query<{trip_title:string;community_name:string;granted_role:string;expires_at:Date}>('SELECT * FROM public.preview_trip_invite($1)',[hashToken(token.data.token)]);
    const invitation=result.rows[0];if(!invitation)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({preview:{tripTitle:invitation.trip_title,communityName:invitation.community_name,role:invitation.granted_role,communityScopeForNewMember:'trip_only',expiresAt:invitation.expires_at}});
  };
  if(config.legacyInviteUrlsEnabled)app.get('/api/invites/:token/preview',{onRequest:tripPreviewLimit},tripPreview);
  app.post('/api/invites/preview',{onRequest:tripPreviewLimit},tripPreview);
  const tripRedeem=async(request:FastifyRequest,reply:FastifyReply)=>{
    reply.header('Cache-Control','no-store').header('Referrer-Policy','no-referrer');
    if(!mutationAllowed(request,config))return forbidden(reply);
    const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const legacy=request.routeOptions.url==='/api/invites/:token/redeem';
    const token=inviteTokenBody.safeParse(legacy?request.params:request.body);
    if(!token.success||(legacy&&!z.object({}).strict().safeParse(request.body).success))return badRequest(reply);
    const result=await pool.query<{result:string;trip_id:string|null}>('SELECT * FROM public.redeem_trip_invite($1,$2)',[user.id,hashToken(token.data.token)]);
    const redemption=result.rows[0];
    if(!redemption||redemption.result==='invalid'||!redemption.trip_id)return reply.code(404).send({error:'NOT_FOUND'});
    return reply.send({status:redemption.result,tripId:redemption.trip_id});
  };
  if(config.legacyInviteUrlsEnabled)app.post('/api/invites/:token/redeem',{onRequest:tripRedeemLimit},tripRedeem);
  app.post('/api/invites/redeem',{onRequest:tripRedeemLimit},tripRedeem);
  app.get('/api/trips/:tripId', async (request, reply) => {
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    const params = tripParams.safeParse(request.params); if (!params.success) return badRequest(reply);
    const result = await pool.query<{id:string; title:string; timezone:string; role:TripRole}>(
      `SELECT t.id, t.title, t.timezone, t.starts_on, t.ends_on, t.revision, tm.role FROM trips t
       JOIN communities c ON c.id = t.community_id
       JOIN trip_members tm ON tm.trip_id = t.id AND tm.community_id = t.community_id
       JOIN community_members cm ON cm.community_id = tm.community_id AND cm.user_id = tm.user_id
       WHERE t.id = $1 AND tm.user_id = $2 AND tm.left_at IS NULL AND cm.left_at IS NULL AND t.deleted_at IS NULL AND c.deleted_at IS NULL`, [params.data.tripId, user.id]);
    const trip = result.rows[0];
    if (!trip) return reply.code(404).send({ error:'NOT_FOUND' });
    return reply.header('Cache-Control','no-store').send({ trip });
  });
  app.delete('/api/trips/:tripId', {config:{rateLimit:{max:demoActionMax(30),timeWindow:'1 minute'}}},async(request,reply)=>{
    if(!mutationAllowed(request,config))return forbidden(reply);const user=await sessionFor(request,pool);if(!user)return notAuthenticated(reply);
    if(!equalCsrf(csrfForToken(config.CSRF_SECRET,user.token),request.headers['x-csrf-token']))return forbidden(reply);
    const params=tripParams.safeParse(request.params),body=cancelEventBody.safeParse(request.body);if(!params.success||!body.success)return badRequest(reply);
    const r=await pool.query<{result:string}>('SELECT public.cancel_trip_for_owner($1,$2,$3) result',[user.id,params.data.tripId,body.data.expectedRevision]);
    const status=r.rows[0]?.result;if(status==='not_found')return reply.code(404).send({error:'NOT_FOUND'});if(status==='forbidden')return forbidden(reply);if(status==='conflict')return reply.code(409).send({error:'TRIP_CHANGED'});
    if(status!=='cancelled')throw new Error('Unexpected trip cancellation result');return reply.header('Cache-Control','no-store').send({status:'cancelled'});
  });
  app.patch('/api/trips/:tripId', { config: { rateLimit: { max: demoActionMax(30), timeWindow: '1 minute' } } }, async (request, reply) => {
    if (!mutationAllowed(request, config)) return forbidden(reply);
    const user = await sessionFor(request, pool); if (!user) return notAuthenticated(reply);
    if (!equalCsrf(csrfForToken(config.CSRF_SECRET, user.token), request.headers['x-csrf-token'])) return forbidden(reply);
    const params = tripParams.safeParse(request.params), body = updateTripSchema.safeParse(request.body);
    if (!params.success || !body.success) return badRequest(reply);
    // Lock the verified user, trip and active membership in the same database
    // operation as the edit. A completed removal/downgrade wins over this write.
    const b=body.data,result=await pool.query<{result:string}>(
      'SELECT public.edit_trip_for_member($1,$2,$3,$4,$5,$6) AS result',[user.id,params.data.tripId,b.expectedRevision,b.title,b.startsOn,b.endsOn]);
    const outcome=result.rows[0]?.result;if(outcome==='not_found')return reply.code(404).send({error:'NOT_FOUND'});
    if(outcome==='forbidden')return forbidden(reply);if(outcome==='invalid')return badRequest(reply);if(outcome==='conflict')return reply.code(409).send({error:'TRIP_CHANGED'});
    if(outcome!=='updated')throw new Error('Unexpected trip edit result');
    return reply.header('Cache-Control','no-store').send({status:'updated'});
  });
}
