// SPDX-License-Identifier: Apache-2.0
// The published log as a reader sees it: the generations index.json declares, the
// prefix every object lives under (docs/PROTOCOL.md §6, §9), and tiles read with the
// fallback from a full object to a larger partial one.

import { decodeEntryBundle, entriesPath, hashTilePath, parseOrigin, parseRewind, TILE_WIDTH, verifyNote } from "@emojery/shared/core";
import { text } from "./source.js";

/**
 * @typedef {object} Generation
 * @property {string} origin
 * @property {number} generation
 * @property {number} start the first leaf sealed in this generation (0 for g0, N of the rewind that opened it)
 * @property {number | null} end one past the last leaf it holds; null while current
 * @property {any} [rewind] the record that closed it
 */

/**
 * Reads index.json and returns the generations in order. Every record must verify under
 * the log key; the chain must run g0, g1, ... each forking from the one before.
 * @param {string | null} indexText null when the file is absent
 * @param {string} logName @param {Uint8Array} logKey
 * @returns {Promise<Generation[]>}
 */
export async function generations(indexText, logName, logKey) {
  /** @type {Generation[]} */
  const out = [{ origin: `${logName}/g0`, generation: 0, start: 0, end: null }];
  if (indexText === null) return out;
  const doc = JSON.parse(indexText);
  if (!doc || !Array.isArray(doc.records)) throw new Error("index.json has no records array");
  for (const rec of doc.records) {
    if (rec?.kind !== "rewind" || typeof rec.note !== "string") throw new Error(`index.json record of unknown kind ${rec?.kind}`);
    const r = parseRewind(await verifyNote(rec.note, logName, logKey));
    const cur = out[out.length - 1];
    if (r.forkedFrom !== cur.origin) throw new Error(`rewind forks from ${r.forkedFrom}, current is ${cur.origin}`);
    const next = parseOrigin(r.origin);
    if (next.logName !== logName || next.generation !== cur.generation + 1) throw new Error(`rewind opens ${r.origin} after ${cur.origin}`);
    cur.end = r.m;
    cur.rewind = r;
    out.push({ origin: r.origin, generation: next.generation, start: r.n, end: null });
  }
  return out;
}

/**
 * The generation that sealed position `seq` of the current tree. Each generation keeps
 * the leaves below its start from the one before it and seals everything from its start
 * on, so walking back from the current one, the first generation whose start is at most
 * `seq` sealed it.
 * @param {Generation[]} gens @param {number} seq
 */
export function sealedIn(gens, seq) {
  for (let i = gens.length - 1; i > 0; i--) if (seq >= gens[i].start) return gens[i];
  return gens[0];
}

/** The origin a REACT at `seq` was signed for. @param {Generation[]} gens @param {number} seq */
export function originAt(gens, seq) {
  return sealedIn(gens, seq).origin;
}

/**
 * The prefix of an object whose last leaf is `last`: the generation that wrote it, which
 * is the one that sealed that leaf.
 * @param {Generation[]} gens @param {number} last
 */
export function prefixFor(gens, last) {
  return `g${sealedIn(gens, last).generation}`;
}

/**
 * Reads a tile or bundle of `width` entries. A full object is read as itself; a partial
 * one as `.p/<width>`, and when the publisher has already replaced that with the full
 * object (§6), as the full object's first `width` entries.
 * @param {{ get: (path: string) => Promise<import("./source.js").ReadResult> }} bucket
 * @param {Generation[]} gens
 * @param {"hash" | "entries"} kind @param {number} level @param {number} index @param {number} width
 */
export async function readTile(bucket, gens, kind, level, index, width) {
  const leavesPerEntry = 2 ** (8 * level);
  const at = (/** @type {number} */ w) => `${prefixFor(gens, (index * TILE_WIDTH + w) * leavesPerEntry - 1)}/${kind === "entries" ? entriesPath(index, w) : hashTilePath(level, index, w)}`;
  const exact = at(width);
  const r = await bucket.get(exact);
  if (r.ok || width === TILE_WIDTH || !r.missing) return { ...r, path: exact };
  const fullPath = at(TILE_WIDTH);
  const full = await bucket.get(fullPath);
  if (!full.ok) return { ...r, path: exact };
  const bytes = kind === "hash" ? full.bytes.subarray(0, 32 * width) : bundlePrefix(full.bytes, width);
  return { ok: /** @type {const} */ (true), bytes, headers: full.headers, path: fullPath };
}

/** The bytes of the first `n` records of an entry bundle. @param {Uint8Array} b @param {number} n */
function bundlePrefix(b, n) {
  let o = 0;
  for (let i = 0; i < n; i++) {
    if (o + 2 > b.length) return b;
    o += 2 + ((b[o] << 8) | b[o + 1]);
  }
  return b.subarray(0, o);
}

/** @param {import("./source.js").ReadResult & { ok: true }} r @param {number} width */
export function entries(r, width) {
  return decodeEntryBundle(r.bytes, width);
}

export { text };
