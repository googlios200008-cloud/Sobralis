import type { Pool } from 'pg';

export type Tier = 'FREE' | 'PRO' | 'FRIENDS_UNLIMITED';
export type FeatureAccess = { key:string; enabled:boolean; allowed:boolean };
export type UserEntitlements = { tier:Tier; expiresAt:Date|null; features:FeatureAccess[] };
type FeatureRow = { feature_key:string; is_enabled:boolean; is_allowed:boolean; effective_tier:Tier; tier_expires_at:Date|null };

// userId must come from the authenticated server session, never the request body.
export async function resolveEntitlements(pool: Pool, userId: string): Promise<UserEntitlements> {
  const result = await pool.query<FeatureRow>('SELECT * FROM public.resolve_user_features($1)', [userId]);
  const first = result.rows[0];
  if (!first) throw new Error('Entitlements unavailable');
  return { tier:first.effective_tier, expiresAt:first.tier_expires_at,
    features:result.rows.map(row=>({key:row.feature_key, enabled:row.is_enabled, allowed:row.is_allowed})) };
}
export async function hasFeature(pool: Pool, userId: string, featureName: string): Promise<'allowed'|'upgrade'|'disabled'|'unknown'> {
  const access = await resolveEntitlements(pool,userId);
  const feature = access.features.find(item=>item.key===featureName);
  if (!feature) return 'unknown';
  if (!feature.enabled) return 'disabled';
  return feature.allowed ? 'allowed' : 'upgrade';
}
