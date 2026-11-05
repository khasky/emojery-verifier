// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { EncodingError, toHex } from "../src/core/bytes.js";
import { decodeLeaf, encodeLeaf, LeafError, OP } from "../src/core/leaf.js";

// A verifier reads leaves from a mirror it does not trust: any bytes must decode to a leaf that
// re-encodes to exactly those bytes, or be refused with LeafError or EncodingError. Any other
// exception would end a verifier run where a refusal should have been reported.

function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

function decodesOrRefuses(bytes) {
  let leaf;
  try {
    leaf = decodeLeaf(bytes);
  } catch (err) {
    if (err instanceof LeafError || err instanceof EncodingError) return;
    assert.fail(`${toHex(bytes)}: ${err?.constructor?.name}: ${err?.message}`);
  }
  assert.deepEqual(encodeLeaf(leaf), bytes, `${toHex(bytes)} decodes but does not re-encode to itself`);
}

const sig = new Uint8Array(64).fill(0x5a);
const seeds = [
  { op: OP.REACT, enrollSeq: 1n, site: "github", targetId: "khasky/emojery", reaction: "👍", prevReaction: "", counter: 1, sig },
  { op: OP.REVOKE, enrollSeq: 2n, reasonCode: "coordinated_voting", caseId: new Uint8Array(16).fill(7), banUntil: 0xffffffff },
  {
    op: OP.ENROLL,
    nullifier: new Uint8Array(32).fill(1),
    iss: "https://accounts.google.com",
    aud: "x".repeat(72),
    modulusHash: new Uint8Array(32).fill(2),
    accountPubkey: new Uint8Array(32).fill(3),
    proofHash: new Uint8Array(32).fill(4),
  },
  { op: OP.RETIRE, enrollSeq: 1n, nullifier: new Uint8Array(32).fill(1), reason: "self", sig, caseId: new Uint8Array(0) },
  { op: OP.RETIRE, enrollSeq: 1n, nullifier: new Uint8Array(32).fill(1), reason: "legal", sig: new Uint8Array(0), caseId: new Uint8Array(16).fill(9) },
].map(encodeLeaf);

test("every truncation of a valid leaf is refused", () => {
  for (const bytes of seeds) {
    for (let n = 0; n < bytes.length; n++) {
      assert.throws(() => decodeLeaf(bytes.subarray(0, n)), (err) => err instanceof LeafError || err instanceof EncodingError);
    }
  }
});

test("random bytes decode canonically or are refused", () => {
  const next = rng(0x5eed1eaf);
  for (let i = 0; i < 20000; i++) {
    const bytes = new Uint8Array(next() % 300);
    for (let j = 0; j < bytes.length; j++) bytes[j] = next();
    // Most random leaves die on the first byte; give half of them the real version and an op.
    if (i % 2 && bytes.length >= 2) {
      bytes[0] = 2;
      bytes[1] = 1 + (next() % 4);
    }
    decodesOrRefuses(bytes);
  }
});

test("mutated valid leaves decode canonically or are refused", () => {
  const next = rng(0xc0ffee);
  for (let i = 0; i < 20000; i++) {
    const bytes = new Uint8Array(seeds[i % seeds.length]);
    for (let k = 1 + (next() % 4); k > 0; k--) bytes[next() % bytes.length] = next();
    decodesOrRefuses(bytes);
  }
});
