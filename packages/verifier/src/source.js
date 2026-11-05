// SPDX-License-Identifier: Apache-2.0
// Reading the published log. Every read answers one of three things, and the verdict
// rules (docs/PROTOCOL.md §12.3) depend on telling them apart:
//   { ok: true, bytes }          the object
//   { ok: false, missing: true } the host answered and does not serve it (404)
//   { ok: false, missing: false } the host did not answer usefully (network, 5xx, 403)

const RETRY = new Set([429, 500, 502, 503, 504]);
const MAX_ATTEMPTS = 5;
const RETRY_AFTER_CAP_S = 120;

/**
 * @typedef {{ ok: true, bytes: Uint8Array, headers: Headers } | { ok: false, missing: boolean, status: number | null, error?: string }} ReadResult
 */

/**
 * @param {string} url @param {{ fetch?: typeof fetch, log?: (s: string) => void }} [opts]
 * @returns {Promise<ReadResult>}
 */
export async function read(url, opts = {}) {
  const f = opts.fetch ?? fetch;
  for (let attempt = 1; ; attempt++) {
    let res;
    try {
      res = await f(url, { headers: { "accept-encoding": "gzip, identity" } });
    } catch (e) {
      if (attempt >= MAX_ATTEMPTS) return { ok: false, missing: false, status: null, error: String(/** @type {Error} */ (e).message ?? e) };
      await pause(2 ** attempt * 500);
      continue;
    }
    if (res.ok) return { ok: true, bytes: new Uint8Array(await res.arrayBuffer()), headers: res.headers };
    if (res.status === 404) return { ok: false, missing: true, status: 404 };
    if (!RETRY.has(res.status) || attempt >= MAX_ATTEMPTS) return { ok: false, missing: false, status: res.status };
    const after = Number(res.headers.get("retry-after"));
    const waitMs = Number.isFinite(after) && after > 0 ? Math.min(after, RETRY_AFTER_CAP_S) * 1000 : 2 ** attempt * 500;
    opts.log?.(`${res.status} on ${url}; retry in ${Math.round(waitMs / 1000)} s`);
    await pause(waitMs);
  }
}

/** @param {number} ms */
function pause(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

const decoder = new TextDecoder("utf-8", { fatal: true });

/** @param {ReadResult} r */
export function text(r) {
  if (!r.ok) throw new Error("no bytes");
  return decoder.decode(r.bytes);
}

/**
 * A log host: the base URL of the bucket (`https://log.emojery.app`) or of the mirror's
 * raw files (`https://raw.githubusercontent.com/khasky/emojery-tlog/main`).
 * @param {string} base @param {{ fetch?: typeof fetch, log?: (s: string) => void }} [opts]
 */
export function host(base, opts = {}) {
  const root = base.replace(/\/+$/, "");
  return {
    base: root,
    /** @param {string} path */
    get: (path) => read(`${root}/${path}`, opts),
  };
}
