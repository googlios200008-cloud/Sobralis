import { z } from 'zod';
import { isIP } from 'node:net';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  SAFE_DIAGNOSTICS: z.enum(['true', 'false']).default('false'),
  DB_HOST: z.string().min(1),
  DB_PORT: z.coerce.number().int().min(1).max(65535).default(5432),
  DB_NAME: z.string().regex(/^[a-zA-Z0-9_]{1,63}$/),
  DB_USER: z.string().regex(/^[a-zA-Z0-9_]{1,63}$/),
  DB_PASSWORD: z.string().min(32).refine(value => !value.includes('REPLACE_WITH'), 'Replace the example password'),
});
export type AppConfig = z.infer<typeof schema>;

// Never include supplied values or a full database URL in diagnostic messages.
export function readConfig(env: NodeJS.ProcessEnv): AppConfig {
  const result = schema.safeParse(env);
  if (!result.success) {
    const fields = [...new Set(result.error.issues.map(issue => issue.path.join('.')))];
    throw new Error(`Invalid configuration fields: ${fields.join(', ')}`);
  }
  return result.data;
}

const securitySchema = z.object({
  PUBLIC_ORIGIN: z.string().url(),
  CSRF_SECRET: z.string().min(32).refine(v => !v.includes('REPLACE_WITH')),
  REGISTRATION_ENABLED: z.enum(['true', 'false']).default('false'),
  PASSWORD_RESET_ENABLED: z.enum(['true', 'false']).default('false'),
  DEMO_SHARED_LOGIN_LIMIT: z.enum(['true', 'false']).default('false'),
  DEMO_SHARED_ACTION_LIMIT: z.enum(['true', 'false']).default('false'),
  TRUSTED_PROXY_IP: z.string().default('').refine(v => v === '' || isIP(v) !== 0),
  DATA_CONSENT_VERSION: z.string().max(80).default(''),
  DATA_CONSENT_URL: z.string().max(500).default(''),
  TERMS_VERSION: z.string().max(80).default(''),
  TERMS_URL: z.string().max(500).default(''),
});
export type SecurityConfig = z.infer<typeof securitySchema> & { readonly legacyInviteUrlsEnabled: boolean };
export function readSecurityConfig(env: NodeJS.ProcessEnv, mode: AppConfig['NODE_ENV']): SecurityConfig {
  const result = securitySchema.safeParse(env);
  if (!result.success) {
    const fields = [...new Set(result.error.issues.map(issue => issue.path.join('.')))];
    throw new Error(`Invalid security configuration fields: ${fields.join(', ')}`);
  }
  const config = result.data;
  const origin = new URL(config.PUBLIC_ORIGIN);
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname);
  if (origin.origin !== config.PUBLIC_ORIGIN || origin.username || origin.password ||
      (origin.protocol !== 'https:' && !(mode !== 'production' && isLocal && origin.protocol === 'http:')) ||
      config.PUBLIC_ORIGIN.includes('REPLACE_WITH')) {
    throw new Error('Invalid security configuration fields: PUBLIC_ORIGIN');
  }
  // Opt-in relaxation ONLY for an isolated disposable shared demo. Never usable in production or with registration.
  if ((config.DEMO_SHARED_LOGIN_LIMIT === 'true' || config.DEMO_SHARED_ACTION_LIMIT === 'true') && (mode !== 'development' || env.DB_NAME !== 'sobralis_demo' || config.REGISTRATION_ENABLED !== 'false' || config.PASSWORD_RESET_ENABLED !== 'false')) {
    throw new Error('Relaxed demo login limit requires a disposable development database');
  }
  if (config.PASSWORD_RESET_ENABLED === 'true' && mode === 'production') {
    throw new Error('Production password recovery requires security review and verified mail delivery');
  }
  if (config.REGISTRATION_ENABLED === 'true' && mode === 'production') {
    throw new Error('Production registration requires email verification and reviewed documents');
  }
  if (config.REGISTRATION_ENABLED === 'true') {
    const validPath = (v: string) => /^\/legal\/[a-zA-Z0-9/_-]+$/.test(v);
    if (!config.DATA_CONSENT_VERSION || !config.TERMS_VERSION || !validPath(config.DATA_CONSENT_URL) || !validPath(config.TERMS_URL)) {
      throw new Error('Registration requires reviewed, versioned legal documents');
    }
  }
  // Legacy URLs expose bearer tokens to intermediaries. Compatibility is
  // limited to isolated test/development; production cannot opt back in.
  return {...config, legacyInviteUrlsEnabled: mode !== 'production'};
}
