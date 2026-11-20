// SPDX-License-Identifier: Apache-2.0
// The RFC 6962 / RFC 9162 Merkle tree of docs/PROTOCOL.md §5, written over one primitive:
// the hash of a perfect subtree, `subtree(level, index)` = the root of leaves
// [index·2^level, (index+1)·2^level). Tiles store exactly those (tiles.js), so roots and
// proofs come out of a few tile reads instead of the whole log.

import { equalBytes } from "./bytes.js";
import { nodeHash, sha256 } from "./messages.js";

/**
 * @callback SubtreeHash
 * @param {number} level
 * @param {number} index
 * @returns {Promise<Uint8Array>}
 */

export class ProofError extends Error {
  name = "ProofError";
}

/** @param {Uint8Array[]} hs */
function hashSizes(...hs) {
  for (const h of hs) if (!(h instanceof Uint8Array) || h.length !== 32) throw new ProofError("hash is not 32 bytes");
}

/** Largest power of two strictly less than n (n ≥ 2). @param {number} n */
function split(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** @param {number} n */
function log2(n) {
  return Math.round(Math.log2(n));
}

/**
 * Root of leaves [start, start + n), where start is a multiple of the largest power of
 * two not above n — true for every range RFC 6962 recursion visits.
 * @param {SubtreeHash} subtree @param {number} start @param {number} n
 * @returns {Promise<Uint8Array>}
 */
async function rangeHash(subtree, start, n) {
  if ((n & (n - 1)) === 0) return subtree(log2(n), start / n);
  const k = split(n);
  return nodeHash(await rangeHash(subtree, start, k), await rangeHash(subtree, start + k, n - k));
}

/**
 * Root of a tree of `size` leaves.
 * @param {number} size @param {SubtreeHash} subtree
 */
export async function treeRoot(size, subtree) {
  if (size === 0) return sha256(new Uint8Array(0));
  return rangeHash(subtree, 0, size);
}

/**
 * RFC 6962 audit path for leaf `index` in a tree of `size` leaves.
 * @param {number} index @param {number} size @param {SubtreeHash} subtree
 */
export async function inclusionProof(index, size, subtree) {
  if (!(index >= 0 && index < size)) throw new ProofError(`index ${index} outside a tree of ${size}`);
  /** @type {Uint8Array[]} */
  const path = [];
  let start = 0;
  let n = size;
  let m = index;
  // Walk down from the root; each step records the sibling of the side holding the leaf.
  /** @type {Uint8Array[]} */
  const siblings = [];
  while (n > 1) {
    const k = split(n);
    if (m < k) {
      siblings.push(await rangeHash(subtree, start + k, n - k));
      n = k;
    } else {
      siblings.push(await rangeHash(subtree, start, k));
      start += k;
      m -= k;
      n -= k;
    }
  }
  for (let i = siblings.length - 1; i >= 0; i--) path.push(siblings[i]);
  return path;
}

/**
 * RFC 6962 consistency proof from a tree of `m` leaves to one of `n` leaves.
 * @param {number} m @param {number} n @param {SubtreeHash} subtree
 */
export async function consistencyProof(m, n, subtree) {
  if (!(m > 0 && m <= n)) throw new ProofError(`no consistency proof from ${m} to ${n}`);
  if (m === n) return [];
  /** @type {Uint8Array[]} */
  const out = [];
  /** @param {number} mm @param {number} start @param {number} nn @param {boolean} complete */
  const sub = async (mm, start, nn, complete) => {
    if (mm === nn) {
      if (!complete) out.push(await rangeHash(subtree, start, nn));
      return;
    }
    const k = split(nn);
    if (mm <= k) {
      await sub(mm, start, k, complete);
      out.push(await rangeHash(subtree, start + k, nn - k));
    } else {
      await sub(mm - k, start + k, nn - k, false);
      out.push(await rangeHash(subtree, start, k));
    }
  };
  await sub(m, 0, n, true);
  return out;
}

/**
 * RFC 9162 §2.1.3.2: recompute the root from a leaf hash and its audit path.
 * @param {number} index @param {number} size @param {Uint8Array} leafHash @param {Uint8Array[]} proof
 */
export async function rootFromInclusionProof(index, size, leafHash, proof) {
  if (!(index >= 0 && index < size)) throw new ProofError(`index ${index} outside a tree of ${size}`);
  hashSizes(leafHash, ...proof);
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  for (const p of proof) {
    if (sn === 0) throw new ProofError("inclusion proof too long");
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new ProofError("inclusion proof too short");
  return r;
}

/**
 * @param {number} index @param {number} size @param {Uint8Array} leafHash @param {Uint8Array[]} proof @param {Uint8Array} root
 */
export async function verifyInclusion(index, size, leafHash, proof, root) {
  hashSizes(root);
  if (!equalBytes(await rootFromInclusionProof(index, size, leafHash, proof), root)) throw new ProofError("inclusion proof does not reach the root");
}

/**
 * RFC 9162 §2.1.4.2.
 * @param {number} m @param {number} n @param {Uint8Array[]} proof @param {Uint8Array} rootM @param {Uint8Array} rootN
 */
export async function verifyConsistency(m, n, proof, rootM, rootN) {
  if (!(m > 0 && m <= n)) throw new ProofError(`no consistency from ${m} to ${n}`);
  if (m === n) {
    if (proof.length !== 0) throw new ProofError("consistency proof between equal sizes must be empty");
    if (!equalBytes(rootM, rootN)) throw new ProofError("equal sizes with different roots");
    return;
  }
  hashSizes(rootM, rootN, ...proof);
  const path = (m & (m - 1)) === 0 ? [rootM, ...proof] : [...proof];
  if (path.length === 0) throw new ProofError("consistency proof is empty");
  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) throw new ProofError("consistency proof too long");
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new ProofError("consistency proof too short");
  if (!equalBytes(fr, rootM)) throw new ProofError("consistency proof does not reach the old root");
  if (!equalBytes(sr, rootN)) throw new ProofError("consistency proof does not reach the new root");
}

/**
 * A SubtreeHash over leaf hashes held in memory, for tests and for a verifier that has
 * read every leaf anyway.
 * @param {Uint8Array[]} leafHashes
 * @returns {SubtreeHash}
 */
export function subtreeFromLeafHashes(leafHashes) {
  /** @type {Map<string, Uint8Array>} */
  const memo = new Map();
  /** @type {SubtreeHash} */
  const get = async (level, index) => {
    if (level === 0) {
      const h = leafHashes[index];
      if (!h) throw new ProofError(`no leaf ${index}`);
      return h;
    }
    const key = `${level}/${index}`;
    const hit = memo.get(key);
    if (hit) return hit;
    const h = await nodeHash(await get(level - 1, 2 * index), await get(level - 1, 2 * index + 1));
    memo.set(key, h);
    return h;
  };
  return get;
}
