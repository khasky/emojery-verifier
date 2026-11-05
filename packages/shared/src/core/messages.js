// SPDX-License-Identifier: Apache-2.0
// Hashes and Ed25519 messages of docs/PROTOCOL.md §3, §5 and §14. Hashing is WebCrypto,
// so the same module runs in a Worker, a browser and Node.

import { concat, lp16, u32, u64 } from "./bytes.js";

/** @param {Uint8Array} b */
export async function sha256(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

/** @param {Uint8Array} b */
export async function sha512(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-512", b));
}

/** RFC 6962 leaf hash. @param {Uint8Array} leafBytes */
export function leafHash(leafBytes) {
  return sha256(concat(Uint8Array.of(0x00), leafBytes));
}

/** RFC 6962 interior node hash. @param {Uint8Array} left @param {Uint8Array} right */
export function nodeHash(left, right) {
  return sha256(concat(Uint8Array.of(0x01), left, right));
}

/** sha256 of the raw ENROLL bytes, no prefix. @param {Uint8Array} enrollBytes */
export function enrollHash(enrollBytes) {
  return sha256(enrollBytes);
}

export const TAG = Object.freeze({
  REACT: "emojery-react-v2",
  RETIRE: "emojery-retire-v1",
  SESSION: "emojery-session-v1",
  REFRESH: "emojery-refresh-v1",
});

/**
 * The bytes a REACT signature covers.
 * @param {{ origin: string, enrollHash: Uint8Array, site: string, targetId: string, reaction: string, prevReaction: string, counter: number }} m
 */
export function reactMessage(m) {
  if (m.enrollHash.length !== 32) throw new RangeError("enroll_hash must be 32 bytes");
  return concat(lp16(TAG.REACT), lp16(m.origin), m.enrollHash, lp16(m.site), lp16(m.targetId), lp16(m.reaction), lp16(m.prevReaction), u32(m.counter));
}

/** The bytes a RETIRE "self" signature covers. @param {string} logName @param {Uint8Array} enrollHash */
export function retireMessage(logName, enrollHash) {
  if (enrollHash.length !== 32) throw new RangeError("enroll_hash must be 32 bytes");
  return concat(lp16(TAG.RETIRE), lp16(logName), enrollHash);
}

/**
 * The bytes the sign-in proof of key possession covers.
 * @param {string} logName @param {Uint8Array} nonceSalt @param {Uint8Array} idTokenHash sha256 of the id_token's bytes
 */
export function sessionMessage(logName, nonceSalt, idTokenHash) {
  if (nonceSalt.length !== 32 || idTokenHash.length !== 32) throw new RangeError("nonce_salt and the token hash must be 32 bytes");
  return concat(lp16(TAG.SESSION), lp16(logName), nonceSalt, idTokenHash);
}

/** The bytes a session refresh signature covers. @param {string} logName @param {bigint | number} exp */
export function refreshMessage(logName, exp) {
  return concat(lp16(TAG.REFRESH), lp16(logName), u64(exp));
}
