// Coalesce only an outstanding check. A timeout makes requests fail closed,
// but retains the in-flight check until it actually settles: repeated traffic
// must not launch an unbounded number of abandoned database operations.
// If a check never settles the instance remains unavailable and must be
// restarted or its underlying database connection repaired.
export function createServingReadiness(check: () => Promise<void>, timeoutMs = 4_000): () => Promise<void> {
  let checking: Promise<void> | undefined;
  return () => {
    if (checking) return checking;
    let accept!: () => void, reject!: (error: Error) => void;
    const bounded = new Promise<void>((resolve, fail) => { accept = resolve; reject = fail; });
    checking = bounded;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; reject(new Error('Readiness check timed out')); }, timeoutMs);
    void Promise.resolve().then(check).then(
      () => { clearTimeout(timer); if (!timedOut) accept(); if (checking === bounded) checking = undefined; },
      () => { clearTimeout(timer); if (!timedOut) reject(new Error('Readiness check failed')); if (checking === bounded) checking = undefined; },
    );
    return bounded;
  };
}
