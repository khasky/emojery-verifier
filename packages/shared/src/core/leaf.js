// SPDX-License-Identifier: Apache-2.0
// The four leaves of docs/PROTOCOL.md §3: encode, decode, and the shape rules of §3.5.
// A decoded leaf is a plain object; `encodeLeaf(decodeLeaf(b))` returns `b` byte for
// byte for every leaf `decodeLeaf` accepts.

import { concat, lp16, lpb16, Reader, u8, u32, u64, utf8 } from "./bytes.js";

export const LEAF_VERSION = 0x02;
export const OP = Object.freeze({ REACT: 1, REVOKE: 2, ENROLL: 3, RETIRE: 4 });
export const RETIRE_REASONS = Object.freeze(["self", "request", "legal"]);

export class LeafError extends Error {
  name = "LeafError";
}

const SITE = /^[a-z0-9]{1,32}$/;
const REASON_CODE = /^[a-z_]{1,32}$/;

// Ed25519 points of small order, with the sign bit cleared: the eight torsion points and
// the two non-canonical spellings of y = 0 and y = 1. A device key among them would let
// one signature verify under one implementation and fail under another.
const SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];

/** True for an encoding of a small-order Ed25519 point. @param {Uint8Array} key 32 bytes */
export function isSmallOrderKey(key) {
  const masked = Uint8Array.from(key);
  masked[31] &= 0x7f;
  let hex = "";
  for (const x of masked) hex += x.toString(16).padStart(2, "0");
  return SMALL_ORDER.includes(hex);
}

/** @param {boolean} ok @param {string} why */
function check(ok, why) {
  if (!ok) throw new LeafError(why);
}

/** @param {string} s */
function byteLength(s) {
  return utf8(s).length;
}

/** @param {Uint8Array} b @param {number} n @param {string} name */
function fixed(b, n, name) {
  check(b instanceof Uint8Array && b.length === n, `${name} must be ${n} bytes`);
}

/** @param {bigint} v */
function seq(v) {
  check(typeof v === "bigint" && v >= 0n && v <= 0xffffffffffffffffn, "enroll_seq must be a u64 bigint");
}

/** @param {string} r @param {string} name */
function reactionShape(r, name) {
  check(typeof r === "string" && r.isWellFormed(), `${name} must be well-formed`);
  check(byteLength(r) <= 64, `${name} must be at most 64 bytes`);
}

/**
 * The §3.5 shape rules. Throws LeafError on the first rule a leaf breaks.
 * @param {any} leaf
 */
export function checkShape(leaf) {
  switch (leaf.op) {
    case OP.REACT:
      seq(leaf.enrollSeq);
      check(typeof leaf.site === "string" && SITE.test(leaf.site), "site must be 1-32 bytes [a-z0-9]");
      check(typeof leaf.targetId === "string" && leaf.targetId.isWellFormed(), "target_id must be well-formed");
      check(byteLength(leaf.targetId) >= 1 && byteLength(leaf.targetId) <= 256, "target_id must be 1-256 bytes");
      reactionShape(leaf.reaction, "reaction");
      reactionShape(leaf.prevReaction, "prev_reaction");
      check(Number.isInteger(leaf.counter) && leaf.counter >= 0 && leaf.counter <= 0xffffffff, "counter must be a u32");
      fixed(leaf.sig, 64, "sig");
      return;
    case OP.REVOKE:
      seq(leaf.enrollSeq);
      check(typeof leaf.reasonCode === "string" && REASON_CODE.test(leaf.reasonCode), "reason_code must be 1-32 bytes [a-z_]");
      fixed(leaf.caseId, 16, "case_id");
      check(Number.isInteger(leaf.banUntil) && leaf.banUntil >= 0 && leaf.banUntil <= 0xffffffff, "ban_until must be a u32");
      return;
    case OP.ENROLL:
      fixed(leaf.nullifier, 32, "nullifier");
      for (const k of ["iss", "aud"]) {
        check(typeof leaf[k] === "string" && leaf[k].isWellFormed() && byteLength(leaf[k]) >= 1, `${k} must be a non-empty string`);
      }
      fixed(leaf.modulusHash, 32, "modulus_hash");
      fixed(leaf.accountPubkey, 32, "account_pubkey");
      check(!isSmallOrderKey(leaf.accountPubkey), "account_pubkey is a small-order point");
      fixed(leaf.proofHash, 32, "proof_hash");
      return;
    case OP.RETIRE:
      seq(leaf.enrollSeq);
      fixed(leaf.nullifier, 32, "nullifier");
      check(RETIRE_REASONS.includes(leaf.reason), "reason must be self, request or legal");
      if (leaf.reason === "self") {
        fixed(leaf.sig, 64, "sig");
        fixed(leaf.caseId, 0, "case_id");
      } else {
        fixed(leaf.sig, 0, "sig");
        fixed(leaf.caseId, 16, "case_id");
      }
      return;
    default:
      throw new LeafError(`unknown op ${leaf.op}`);
  }
}

/**
 * Canonical bytes of a leaf. Checks the shape first, so a publisher cannot write a leaf
 * a verifier would refuse.
 * @param {any} leaf
 * @returns {Uint8Array}
 */
export function encodeLeaf(leaf) {
  checkShape(leaf);
  const head = concat(u8(LEAF_VERSION), u8(leaf.op));
  switch (leaf.op) {
    case OP.REACT:
      return concat(head, u64(leaf.enrollSeq), lp16(leaf.site), lp16(leaf.targetId), lp16(leaf.reaction), lp16(leaf.prevReaction), u32(leaf.counter), lpb16(leaf.sig));
    case OP.REVOKE:
      return concat(head, u64(leaf.enrollSeq), lp16(leaf.reasonCode), lpb16(leaf.caseId), u32(leaf.banUntil));
    case OP.ENROLL:
      return concat(head, lpb16(leaf.nullifier), lp16(leaf.iss), lp16(leaf.aud), lpb16(leaf.modulusHash), lpb16(leaf.accountPubkey), lpb16(leaf.proofHash));
    default:
      return concat(head, u64(leaf.enrollSeq), lpb16(leaf.nullifier), lp16(leaf.reason), lpb16(leaf.sig), lpb16(leaf.caseId));
  }
}

/**
 * Parses and shape-checks one leaf. Throws LeafError (or EncodingError) on anything a
 * verifier must refuse: an unknown version or op, the reserved 0xff first byte,
 * truncation, trailing bytes, ill-formed UTF-8, a field outside §3.5.
 * @param {Uint8Array} bytes
 */
export function decodeLeaf(bytes) {
  const r = new Reader(bytes);
  const version = r.u8();
  check(version !== 0xff, "record 0xff is reserved");
  check(version === LEAF_VERSION, `unknown leaf version ${version}`);
  const op = r.u8();
  /** @type {any} */
  let leaf;
  switch (op) {
    case OP.REACT:
      leaf = { op, enrollSeq: r.u64(), site: r.lp16(), targetId: r.lp16(), reaction: r.lp16(), prevReaction: r.lp16(), counter: r.u32(), sig: r.lpb16() };
      break;
    case OP.REVOKE:
      leaf = { op, enrollSeq: r.u64(), reasonCode: r.lp16(), caseId: r.lpb16(), banUntil: r.u32() };
      break;
    case OP.ENROLL:
      leaf = { op, nullifier: r.lpb16(), iss: r.lp16(), aud: r.lp16(), modulusHash: r.lpb16(), accountPubkey: r.lpb16(), proofHash: r.lpb16() };
      break;
    case OP.RETIRE:
      leaf = { op, enrollSeq: r.u64(), nullifier: r.lpb16(), reason: r.lp16(), sig: r.lpb16(), caseId: r.lpb16() };
      break;
    default:
      throw new LeafError(`unknown op ${op}`);
  }
  r.end();
  checkShape(leaf);
  return leaf;
}
