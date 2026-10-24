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
 * Reads a tile or bundle of the current generation's tree: the full object, or the
 * partial one of exactly `width`, falling back from full to partial at the right edge.
 * @param {{ get: (path: string) => Promise<import("./source.js").ReadResult> }} bucket
 * @param {Generation[]} gens
 * @param {"hash" | "entries"} kind @param {number} level @param {number} index @param {number} width
 */
export async function readTile(bucket, gens, kind, level, index, width) {
  const leavesPerEntry = 2 ** (8 * level);
  const last = (index * TILE_WIDTH + width) * leavesPerEntry - 1;
  const prefix = prefixFor(gens, last);
  const path = (w) => `${prefix}/${kind === "entries" ? entriesPath(index, w) : hashTilePath(level, index, w)}`;
  const full = width === TILE_WIDTH ? await bucket.get(path(TILE_WIDTH)) : null;
  if (full?.ok) return { ...full, path: path(TILE_WIDTH) };
  const partial = width === TILE_WIDTH ? full : await bucket.get(path(width));
  return { ...partial, path: path(width) };
}

/** @param {import("./source.js").ReadResult & { ok: true }} r @param {number} width */
export function entries(r, width) {
  return decodeEntryBundle(r.bytes, width);
}

export { text };
