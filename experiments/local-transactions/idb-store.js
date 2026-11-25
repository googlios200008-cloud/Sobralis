/* Isolated experiment ONLY. Not loaded by the application; never migrate real
 * localStorage here. Atomicity is limited to cooperating IndexedDB clients. */
(function (global) {
  'use strict';
  const dbName = /^sobralis-idb-experiment-[a-z0-9-]{1,80}$/;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const validToken = t => !!t && typeof t === 'object' && typeof t.epoch === 'string' && uuid.test(t.epoch) && Number.isSafeInteger(t.revision) && t.revision >= 1;
  const validRow = r => r && r.key === 'state' && validToken(r) && typeof r.text === 'string' && (r.previous === null || typeof r.previous === 'string');
  const error = code => Object.assign(new Error(code), {code});
  const view = r => ({epoch:r.epoch, revision:r.revision, text:r.text, previous:r.previous});
  function tokenMatches(row, token) { return row.epoch === token.epoch && row.revision === token.revision; }

  async function open(name) {
    if (typeof name !== 'string' || !dbName.test(name)) throw error('EXPERIMENT_DATABASE_REQUIRED');
    if (!global.indexedDB || typeof global.crypto?.randomUUID !== 'function') throw error('STORAGE_UNAVAILABLE');
    const db = await new Promise((resolve, reject) => {
      let settled = false;
      let request;
      try { request = global.indexedDB.open(name, 1); } catch { reject(error('STORAGE_UNAVAILABLE')); return; }
      request.onupgradeneeded = () => { try { if (settled) { request.transaction.abort(); return; } request.result.createObjectStore('snapshots', {keyPath:'key'}); } catch { try { request.transaction.abort(); } catch {} } };
      request.onblocked = () => { if (!settled) { settled = true; reject(error('OPEN_BLOCKED')); } };
      request.onerror = () => { if (!settled) { settled = true; reject(error('STORAGE_UNAVAILABLE')); } };
      request.onsuccess = () => { if (settled) { request.result.close(); return; } settled = true; resolve(request.result); };
    });
    db.onversionchange = () => db.close();

    // Resolve only after transaction completion, not after put. Callers never
    // receive a success for an aborted transaction. A conflict is read-only.
    function transaction(mode, action) {
      return new Promise((resolve, reject) => {
        let tx, result, failure = 'TRANSACTION_FAILED';
        try { tx = db.transaction('snapshots', mode); } catch { reject(error('STORAGE_UNAVAILABLE')); return; }
        tx.oncomplete = () => resolve(result);
        tx.onabort = () => reject(error(failure));
        tx.onerror = () => {}; // default abort remains enabled
        try {
          const store = tx.objectStore('snapshots');
          const get = store.get('state');
          get.onsuccess = () => {
            try {
              const row = get.result;
              if (row !== undefined && !validRow(row)) { failure = 'INVALID_STATE'; tx.abort(); return; }
              result = action(store, row);
            } catch { failure = 'TRANSACTION_FAILED'; try { tx.abort(); } catch { reject(error(failure)); } }
          };
        } catch { try { tx.abort(); } catch { reject(error(failure)); } }
      });
    }
    return {
      close() { db.close(); },
      read() { return transaction('readonly', (_store, row) => row === undefined ? null : view(row)); },
      // A synthetic initial snapshot; not a migration protocol. Concurrent
      // creators return the winning value rather than replacing it.
      initialize(text) {
        if (typeof text !== 'string') return Promise.reject(error('INVALID_INPUT'));
        const epoch = global.crypto.randomUUID();
        return transaction('readwrite', (store, row) => {
          if (row !== undefined) return {created:false, snapshot:view(row)};
          const next = {key:'state',epoch,revision:1,text,previous:null};
          store.add(next); return {created:true, snapshot:view(next)};
        });
      },
      // Caller must decide what to do on conflict; no merge is attempted.
      commit(expected, text, capturePrevious = false) {
        if (!validToken(expected) || typeof text !== 'string' || typeof capturePrevious !== 'boolean') return Promise.reject(error('INVALID_INPUT'));
        const token = {epoch:expected.epoch,revision:expected.revision};
        return transaction('readwrite', (store, row) => {
          if (row === undefined) return {status:'missing'};
          if (!tokenMatches(row, token)) return {status:'conflict', snapshot:view(row)};
          if (row.revision === Number.MAX_SAFE_INTEGER) return {status:'revision_exhausted'};
          const next = {...row,revision:row.revision+1,text,previous:capturePrevious ? row.text : row.previous};
          store.put(next); return {status:'committed',snapshot:view(next)};
        });
      },
      // Swap current and restore point atomically, retaining one step of undo.
      restore(expected) {
        if (!validToken(expected)) return Promise.reject(error('INVALID_INPUT'));
        const token = {epoch:expected.epoch,revision:expected.revision};
        return transaction('readwrite', (store, row) => {
          if (row === undefined) return {status:'missing'};
          if (!tokenMatches(row, token)) return {status:'conflict', snapshot:view(row)};
          if (row.previous === null) return {status:'no_restore_point'};
          if (row.revision === Number.MAX_SAFE_INTEGER) return {status:'revision_exhausted'};
          const next = {...row,revision:row.revision+1,text:row.previous,previous:row.text};
          store.put(next); return {status:'committed',snapshot:view(next)};
        });
      }
    };
  }
  global.SobralisExperimentalTransactions = Object.freeze({open});
})(globalThis);
