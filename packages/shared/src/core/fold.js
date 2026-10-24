// SPDX-License-Identifier: Apache-2.0
// The fold of docs/PROTOCOL.md §12.1: walk the leaves in order, keep every pair
// (nullifier × site × target_id) and the counts they add up to. The publisher folds the
// same way when it seals, so publisher counts and verifier counts agree by construction.

import { compareBytes, toHex, utf8 } from "./bytes.js";
import { decodeLeaf, OP } from "./leaf.js";
import { enrollHash, reactMessage, retireMessage } from "./messages.js";

export class FoldError extends Error {
  name = "FoldError";
  /** @param {number} seq @param {string} message */
  constructor(seq, message) {
    super(`leaf ${seq}: ${message}`);
    this.seq = seq;
  }
}

/** @param {string} site @param {string} targetId */
export function targetKey(site, targetId) {
  return `${site.length}:${site}${targetId}`;
}

/**
 * @typedef {object} FoldOptions
 * @property {string} logName
 * @property {(seq: number) => string} originAt the origin a REACT sealed at `seq` was signed for (§9)
 * @property {(leaf: any, seq: number, bytes: Uint8Array) => Promise<void>} [checkEnroll]
 *   the checks of an ENROLL that need outside data (proof, provider key, trust anchors);
 *   throws to refuse. Omitted: those checks are the caller's.
 * @property {(site: string, targetId: string) => boolean} [keepTarget] which targets to
 *   fold; default all. A REACT on any other target is decoded and otherwise skipped: its
 *   signature, ENROLL link and pair are not checked (the `--target` run).
 */

export class Fold {
  /** @param {FoldOptions} options */
  constructor(options) {
    this.options = options;
    this.size = 0;
    /** @type {Map<number, { nullifier: string, pubkey: Uint8Array, enrollHash: Uint8Array, retired: boolean, key?: Promise<CryptoKey> }>} */
    this.enrolls = new Map();
    /** @type {Map<string, { enrollSeqs: number[], pairs: Map<string, { site: string, targetId: string, reaction: string, counter: number }> }>} */
    this.accounts = new Map();
    /** @type {Set<string>} */
    this.proofHashes = new Set();
    /** @type {Map<string, Map<string, number>>} */
    this.counts = new Map();
  }

  /** @param {string} nullifier */
  account(nullifier) {
    let a = this.accounts.get(nullifier);
    if (!a) {
      a = { enrollSeqs: [], pairs: new Map() };
      this.accounts.set(nullifier, a);
    }
    return a;
  }

  /** @param {string} site @param {string} targetId @param {string} reaction @param {number} delta */
  bump(site, targetId, reaction, delta) {
    if (reaction === "") return;
    const key = targetKey(site, targetId);
    let m = this.counts.get(key);
    if (!m) {
      m = new Map();
      this.counts.set(key, m);
    }
    const v = (m.get(reaction) ?? 0) + delta;
    if (v < 0) throw new Error(`count of ${reaction} on ${key} went negative`);
    if (v === 0) m.delete(reaction);
    else m.set(reaction, v);
  }

  /** @param {number} seq @param {bigint} enrollSeq */
  enroll(seq, enrollSeq) {
    const e = enrollSeq < BigInt(seq) ? this.enrolls.get(Number(enrollSeq)) : undefined;
    if (!e) throw new FoldError(seq, `enroll_seq ${enrollSeq} is not an earlier ENROLL`);
    return e;
  }

  /**
   * @param {{ pubkey: Uint8Array, key?: Promise<CryptoKey> }} e @param {Uint8Array} sig @param {Uint8Array} message
   */
  async verify(e, sig, message) {
    e.key ??= crypto.subtle.importKey("raw", e.pubkey, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify({ name: "Ed25519" }, await e.key, sig, message);
  }

  /**
   * Applies the leaf at the next position. Throws FoldError if the leaf is invalid there.
   * @param {Uint8Array} bytes
   */
  async apply(bytes) {
    const seq = this.size;
    /** @type {any} */
    let leaf;
    try {
      leaf = decodeLeaf(bytes);
    } catch (e) {
      throw new FoldError(seq, /** @type {Error} */ (e).message);
    }
    switch (leaf.op) {
      case OP.ENROLL:
        await this.applyEnroll(seq, leaf, bytes);
        break;
      case OP.REACT:
        await this.applyReact(seq, leaf);
        break;
      case OP.REVOKE:
        this.applyRevoke(seq, leaf);
        break;
      default:
        await this.applyRetire(seq, leaf);
    }
    this.size = seq + 1;
    return leaf;
  }

  /** @param {number} seq @param {any} leaf @param {Uint8Array} bytes */
  async applyEnroll(seq, leaf, bytes) {
    const proof = toHex(leaf.proofHash);
    if (this.proofHashes.has(proof)) throw new FoldError(seq, "proof_hash repeats an earlier ENROLL");
    if (this.options.checkEnroll) {
      try {
        await this.options.checkEnroll(leaf, seq, bytes);
      } catch (e) {
        throw new FoldError(seq, /** @type {Error} */ (e).message);
      }
    }
    this.proofHashes.add(proof);
    const nullifier = toHex(leaf.nullifier);
    this.enrolls.set(seq, { nullifier, pubkey: leaf.accountPubkey, enrollHash: await enrollHash(bytes), retired: false });
    this.account(nullifier).enrollSeqs.push(seq);
  }

  /** @param {number} seq @param {any} leaf */
  async applyReact(seq, leaf) {
    if (!(this.options.keepTarget?.(leaf.site, leaf.targetId) ?? true)) return;
    const e = this.enroll(seq, leaf.enrollSeq);
    if (e.retired) throw new FoldError(seq, "REACT under a retired ENROLL");
    const message = reactMessage({ origin: this.options.originAt(seq), enrollHash: e.enrollHash, site: leaf.site, targetId: leaf.targetId, reaction: leaf.reaction, prevReaction: leaf.prevReaction, counter: leaf.counter });
    if (!(await this.verify(e, leaf.sig, message))) throw new FoldError(seq, "REACT signature does not verify");
    const a = this.account(e.nullifier);
    const key = targetKey(leaf.site, leaf.targetId);
    const pair = a.pairs.get(key) ?? { site: leaf.site, targetId: leaf.targetId, reaction: "", counter: 0 };
    if (leaf.prevReaction !== pair.reaction) throw new FoldError(seq, "prev_reaction does not match the pair");
    if (!(leaf.counter > pair.counter)) throw new FoldError(seq, "counter does not increase");
    this.bump(leaf.site, leaf.targetId, pair.reaction, -1);
    this.bump(leaf.site, leaf.targetId, leaf.reaction, +1);
    a.pairs.set(key, { site: leaf.site, targetId: leaf.targetId, reaction: leaf.reaction, counter: leaf.counter });
  }

  /** @param {string} nullifier @param {boolean} resetCounters */
  emptyPairs(nullifier, resetCounters) {
    const a = this.account(nullifier);
    for (const [key, pair] of a.pairs) {
      this.bump(pair.site, pair.targetId, pair.reaction, -1);
      if (resetCounters) a.pairs.delete(key);
      else pair.reaction = "";
    }
  }

  /** @param {number} seq @param {any} leaf */
  applyRevoke(seq, leaf) {
    const e = this.enroll(seq, leaf.enrollSeq);
    this.emptyPairs(e.nullifier, false);
  }

  /** @param {number} seq @param {any} leaf */
  async applyRetire(seq, leaf) {
    const e = this.enroll(seq, leaf.enrollSeq);
    if (e.nullifier !== toHex(leaf.nullifier)) throw new FoldError(seq, "RETIRE nullifier differs from its ENROLL");
    if (leaf.reason === "self") {
      if (e.retired) throw new FoldError(seq, "RETIRE self under a retired ENROLL");
      if (!(await this.verify(e, leaf.sig, retireMessage(this.options.logName, e.enrollHash)))) throw new FoldError(seq, "RETIRE signature does not verify");
    }
    this.emptyPairs(e.nullifier, true);
    const a = this.account(e.nullifier);
    for (const s of a.enrollSeqs) {
      const x = this.enrolls.get(s);
      if (x) x.retired = true;
    }
    a.enrollSeqs = [];
  }

  /**
   * The counts of one target: the top 10 by count, ties by reaction bytes, and the total.
   * @param {string} site @param {string} targetId
   */
  targetCounts(site, targetId) {
    const m = this.counts.get(targetKey(site, targetId)) ?? new Map();
    const all = [...m].map(([reaction, count]) => ({ reaction, count, bytes: utf8(reaction) }));
    all.sort((x, y) => y.count - x.count || compareBytes(x.bytes, y.bytes));
    let total = 0;
    for (const x of all) total += x.count;
    return { top: all.slice(0, 10).map(({ reaction, count }) => [reaction, count]), total };
  }
}
