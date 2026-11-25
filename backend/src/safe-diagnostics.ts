// Deliberately minimal, opt-in operational signals. Never pass request objects,
// exception objects or arbitrary strings to the output writer.
export type DiagnosticInput = {
  requestId: string;
  method: string;
  url: string;
  status: number;
  durationMs: number;
};
export type DiagnosticSink = (input: DiagnosticInput) => void;

type Category = 'auth' | 'communities' | 'trips' | 'events' | 'invitations' | 'messages' | 'other';
function category(url: string): Category {
  if (/^\/api\/auth(?:\/|\?|$)/.test(url)) return 'auth';
  if (/^\/api\/communities(?:\/|\?|$)/.test(url)) return 'communities';
  if (/^\/api\/trips(?:\/|\?|$)/.test(url)) return 'trips';
  if (/^\/api\/events(?:\/|\?|$)/.test(url)) return 'events';
  if (/^\/api\/(?:invites|community-invites)(?:\/|\?|$)/.test(url)) return 'invitations';
  if (/^\/api\/direct-conversations(?:\/|\?|$)/.test(url)) return 'messages';
  return 'other';
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const methods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

// Process-local budget bounds output during repeated errors. It is NOT an
// abuse limiter or a reliable counter; restarts reset it and dropped events are
// only reported when another eligible event is emitted in a later window.
export function createSafeDiagnostics(write: (line: string) => void, clock: () => number = Date.now): DiagnosticSink {
  let windowStart = clock(), emitted = 0, suppressed = 0;
  return input => {
    const status = Number.isInteger(input.status) && input.status >= 100 && input.status <= 599 ? input.status : 500;
    const durationMs = Number.isFinite(input.durationMs) ? Math.max(0, Math.min(3_600_000, Math.round(input.durationMs))) : 0;
    const event = status >= 500 ? 'server_error' : status === 429 ? 'rate_limited' : durationMs >= 2_000 ? 'slow_response' : null;
    if (!event) return;
    const now = clock();
    if (!Number.isFinite(now)) return;
    if (now < windowStart || now - windowStart >= 60_000) { windowStart = now; emitted = 0; }
    if (emitted >= 20) { suppressed = Math.min(1_000_000, suppressed + 1); return; }
    emitted++;
    const line = {
      event,
      at: new Date(now).toISOString(),
      requestId: uuid.test(input.requestId) ? input.requestId : 'invalid',
      category: category(input.url),
      method: methods.has(input.method) ? input.method : 'OTHER',
      status,
      durationMs,
      suppressed,
    };
    suppressed = 0;
    // Diagnostics must not turn a completed user request into another failure.
    try { write(JSON.stringify(line)); } catch { /* unavailable log sink */ }
  };
}
