// SPDX-License-Identifier: Apache-2.0
// C2SP tlog-tiles as docs/PROTOCOL.md §6 uses them: width 256, a hash tile of level L
// holds the hashes of tree level 8·L, entry bundles hold `u16 length ‖ leaf` records.

import { concat, EncodingError, u16 } from "./bytes.js";
import { nodeHash } from "./messages.js";

export const TILE_WIDTH = 256;
export const TILE_HEIGHT = 8;

/**
 * `<N>` of a tile path: groups of three digits, all but the last prefixed with `x`.
 * @param {number} n
 */
export function tileIndexPath(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`bad tile index ${n}`);
  const groups = [];
  let v = n;
  do {
    groups.unshift(String(v % 1000).padStart(3, "0"));
    v = Math.floor(v / 1000);
  } while (v > 0);
  return groups.map((g, i) => (i < groups.length - 1 ? `x${g}` : g)).join("/");
}

/** @param {number} width */
function partial(width) {
  if (width === TILE_WIDTH) return "";
  if (!(Number.isInteger(width) && width >= 1 && width < TILE_WIDTH)) throw new RangeError(`bad tile width ${width}`);
  return `.p/${width}`;
}

/** @param {number} level @param {number} index @param {number} [width] */
export function hashTilePath(level, index, width = TILE_WIDTH) {
  return `tile/${level}/${tileIndexPath(index)}${partial(width)}`;
}

/** @param {number} index @param {number} [width] */
export function entriesPath(index, width = TILE_WIDTH) {
  return `tile/entries/${tileIndexPath(index)}${partial(width)}`;
}

/**
 * Width of tile `index` at `level` in a tree of `size` leaves, 0 when the tile is empty.
 * Level-L tiles count nodes of tree level 8·L.
 * @param {number} level @param {number} index @param {number} size
 */
export function tileWidth(level, index, size) {
  const nodes = Math.floor(size / 2 ** (TILE_HEIGHT * level));
  return Math.max(0, Math.min(TILE_WIDTH, nodes - index * TILE_WIDTH));
}

/**
 * Splits an entry bundle into leaves. `expected` is the width the path promised.
 * @param {Uint8Array} bytes @param {number} expected
 */
export function decodeEntryBundle(bytes, expected) {
  /** @type {Uint8Array[]} */
  const out = [];
  let o = 0;
  while (o < bytes.length) {
    if (o + 2 > bytes.length) throw new EncodingError("entry bundle cut inside a length");
    const n = (bytes[o] << 8) | bytes[o + 1];
    if (o + 2 + n > bytes.length) throw new EncodingError("entry bundle cut inside an entry");
    out.push(bytes.subarray(o + 2, o + 2 + n));
    o += 2 + n;
  }
  if (out.length !== expected) throw new EncodingError(`entry bundle holds ${out.length} entries, expected ${expected}`);
  return out;
}

/** @param {Uint8Array[]} leaves */
export function encodeEntryBundle(leaves) {
  return concat(...leaves.flatMap((l) => [u16(l.length), l]));
}

/**
 * Splits a hash tile into its hashes.
 * @param {Uint8Array} bytes @param {number} expected
 */
export function decodeHashTile(bytes, expected) {
  if (bytes.length !== expected * 32) throw new EncodingError(`hash tile is ${bytes.length} bytes, expected ${expected * 32}`);
  /** @type {Uint8Array[]} */
  const out = [];
  for (let i = 0; i < expected; i++) out.push(bytes.subarray(32 * i, 32 * i + 32));
  return out;
}

/**
 * @callback TileReader
 * Returns the bytes of the hash tile at `level`/`index` with exactly `width` hashes
 * (a full tile when width is 256). The caller handles fallbacks between the full and
 * partial object.
 * @param {number} level @param {number} index @param {number} width
 * @returns {Promise<Uint8Array>}
 */

/**
 * A SubtreeHash (tree.js) for a tree of `size` leaves, read from hash tiles. A perfect
 * subtree of height h is the stored hash at tree level 8·⌊h/8⌋ folded up h mod 8 levels.
 * @param {number} size @param {TileReader} readTile
 */
export function subtreeFromTiles(size, readTile) {
  /** @type {Map<string, Promise<Uint8Array[]>>} */
  const tiles = new Map();
  /** @param {number} tl @param {number} ti */
  const tile = (tl, ti) => {
    const width = tileWidth(tl, ti, size);
    const key = `${tl}/${ti}/${width}`;
    let p = tiles.get(key);
    if (!p) {
      p = readTile(tl, ti, width).then((b) => decodeHashTile(b, width));
      tiles.set(key, p);
    }
    return p;
  };
  /** Hash of tree level `level` (a multiple of 8) at `index`. @param {number} level @param {number} index */
  const stored = async (level, index) => {
    const tl = level / TILE_HEIGHT;
    const ti = Math.floor(index / TILE_WIDTH);
    const hs = await tile(tl, ti);
    const h = hs[index % TILE_WIDTH];
    if (!h) throw new EncodingError(`no stored hash at level ${level} index ${index}`);
    return h;
  };
  /** @param {number} level @param {number} index @returns {Promise<Uint8Array>} */
  const get = async (level, index) => {
    if (level % TILE_HEIGHT === 0) return stored(level, index);
    return nodeHash(await get(level - 1, 2 * index), await get(level - 1, 2 * index + 1));
  };
  return get;
}

/**
 * The hash tiles of a tree, built from its leaf hashes: what a publisher writes and what a
 * verifier recomputes to compare. Returns `{ level, index, width, bytes }` per tile.
 * @param {Uint8Array[]} leafHashes
 */
export async function buildHashTiles(leafHashes) {
  const out = [];
  let level = leafHashes;
  for (let tl = 0; level.length > 0; tl++) {
    for (let ti = 0; ti * TILE_WIDTH < level.length; ti++) {
      const slice = level.slice(ti * TILE_WIDTH, (ti + 1) * TILE_WIDTH);
      out.push({ level: tl, index: ti, width: slice.length, bytes: concat(...slice) });
    }
    // Fold eight levels up; only complete pairs combine, so the right edge drops off.
    let next = level;
    for (let k = 0; k < TILE_HEIGHT; k++) {
      const up = [];
      for (let i = 0; i + 1 < next.length; i += 2) up.push(await nodeHash(next[i], next[i + 1]));
      next = up;
    }
    level = next;
  }
  return out;
}
