// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { concat, EncodingError, fromHex, lp16, lp32, toHex, u16 } from "../src/core/bytes.js";
import { decodeLeaf, encodeLeaf, LeafError, OP } from "../src/core/leaf.js";
import { enrollHash, leafHash, reactMessage, refreshMessage, retireMessage, sessionMessage } from "../src/core/messages.js";

const sig = new Uint8Array(64).fill(0x5a);
const react = { op: OP.REACT, enrollSeq: 1n, site: "github", targetId: "khasky/emojery", reaction: "👍", prevReaction: "", counter: 1, sig };
const revoke = { op: OP.REVOKE, enrollSeq: 2n, reasonCode: "coordinated_voting", caseId: fromHex("00112233445566778899aabbccddeeff"), banUntil: 0xffffffff };
const enroll = {
  op: OP.ENROLL,
  nullifier: new Uint8Array(32).fill(1),
  iss: "https://accounts.google.com",
  aud: "x".repeat(72),
  modulusHash: new Uint8Array(32).fill(2),
  accountPubkey: new Uint8Array(32).fill(3),
  proofHash: new Uint8Array(32).fill(4),
};
const retire = (reason) => ({
  op: OP.RETIRE,
  enrollSeq: 1n,
  nullifier: new Uint8Array(32).fill(1),
  reason,
  sig: reason === "self" ? sig : new Uint8Array(0),
  caseId: reason === "self" ? new Uint8Array(0) : new Uint8Array(16).fill(9),
});

test("the PROTOCOL.md examples encode to the documented bytes", () => {
  const r = encodeLeaf(react);
  assert.equal(r.length, 112);
  assert.equal(toHex(r.subarray(0, 46)), "020100000000000000010006676974687562000e6b6861736b792f656d6f6a6572790004f09f918d000000000001");
  assert.equal(toHex(r.subarray(46, 48)), "0040");
  assert.equal(toHex(encodeLeaf(revoke)), "020200000000000000020012636f6f7264696e617465645f766f74696e67001000112233445566778899aabbccddeeffffffffff");
  assert.equal(encodeLeaf(enroll).length, 241);
  assert.deepEqual(["self", "request", "legal"].map((r) => encodeLeaf(retire(r)).length), [118, 73, 71]);
});

test("decode inverts encode", () => {
  for (const leaf of [react, revoke, enroll, retire("self"), retire("request"), retire("legal")]) {
    const bytes = encodeLeaf(leaf);
    assert.deepEqual(encodeLeaf(decodeLeaf(bytes)), bytes);
    assert.deepEqual(decodeLeaf(bytes), leaf);
  }
});

test("versions, ops and the reserved first byte", () => {
  const bytes = encodeLeaf(react);
  for (const first of [0x00, 0x01, 0x03, 0xff]) {
    assert.throws(() => decodeLeaf(concat(Uint8Array.of(first), bytes.subarray(1))), LeafError);
  }
  for (const op of [0, 5, 6, 7]) {
    assert.throws(() => decodeLeaf(concat(Uint8Array.of(2, op), bytes.subarray(2))), LeafError);
  }
});

test("truncation and trailing bytes are refused", () => {
  const bytes = encodeLeaf(react);
  assert.throws(() => decodeLeaf(bytes.subarray(0, bytes.length - 1)), EncodingError);
  assert.throws(() => decodeLeaf(concat(bytes, Uint8Array.of(0))), EncodingError);
});

test("an lp32-encoded field does not decode as lp16", () => {
  // site written with a u32 length: the u16 reader sees length 0, then site is empty and the next field is garbage.
  const bad = concat(Uint8Array.of(2, 1), new Uint8Array(8), lp32("github"), lp16("x"), lp16(""), lp16(""), new Uint8Array(4), u16(64), sig);
  assert.throws(() => decodeLeaf(bad));
});

test("field limits: at the limit passes, one past fails", () => {
  const ok = (over) => encodeLeaf({ ...react, ...over });
  const bad = (over) => assert.throws(() => encodeLeaf({ ...react, ...over }), LeafError);
  ok({ site: "a".repeat(32), targetId: "t".repeat(256), reaction: "r".repeat(64), prevReaction: "p".repeat(64), counter: 0xffffffff });
  bad({ site: "a".repeat(33) });
  bad({ site: "" });
  bad({ site: "GitHub" });
  bad({ targetId: "" });
  bad({ targetId: "t".repeat(257) });
  bad({ reaction: "r".repeat(65) });
  bad({ targetId: "‮x\uD800" });
  bad({ counter: 2 ** 32 });
  bad({ sig: new Uint8Array(63) });
  bad({ enrollSeq: 1 });
  assert.throws(() => encodeLeaf({ ...revoke, reasonCode: "Coordinated" }), LeafError);
  assert.throws(() => encodeLeaf({ ...revoke, caseId: new Uint8Array(15) }), LeafError);
  assert.throws(() => encodeLeaf({ ...enroll, iss: "" }), LeafError);
});

test("ill-formed UTF-8 in a leaf is refused", () => {
  const bytes = encodeLeaf(react);
  const broken = new Uint8Array(bytes);
  broken[20] = 0xff; // inside target_id
  assert.throws(() => decodeLeaf(broken), EncodingError);
});

test("RETIRE: case_id and sig belong to the reason", () => {
  assert.throws(() => encodeLeaf({ ...retire("self"), caseId: new Uint8Array(16) }), LeafError);
  assert.throws(() => encodeLeaf({ ...retire("request"), caseId: new Uint8Array(0) }), LeafError);
  assert.throws(() => encodeLeaf({ ...retire("legal"), sig }), LeafError);
  assert.throws(() => encodeLeaf({ ...retire("self"), reason: "admin" }), LeafError);
});

test("hashes and signed messages", async () => {
  assert.equal(toHex(await leafHash(new Uint8Array(0))), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
  const e = encodeLeaf(enroll);
  assert.deepEqual(await enrollHash(e), new Uint8Array(await crypto.subtle.digest("SHA-256", e)));

  const eh = new Uint8Array(32).fill(7);
  const m = reactMessage({ origin: "log.emojery.app/g0", enrollHash: eh, site: "github", targetId: "khasky/emojery", reaction: "👍", prevReaction: "", counter: 1 });
  assert.equal(toHex(m.subarray(0, 18)), "0010656d6f6a6572792d72656163742d7632");
  assert.equal(m.length, 18 + 20 + 32 + 8 + 16 + 6 + 2 + 4);
  assert.notDeepEqual(m, reactMessage({ origin: "log.emojery.app/g1", enrollHash: eh, site: "github", targetId: "khasky/emojery", reaction: "👍", prevReaction: "", counter: 1 }));
  assert.equal(retireMessage("log.emojery.app", eh).length, 19 + 17 + 32);
  assert.equal(sessionMessage("log.emojery.app", eh, eh).length, 20 + 17 + 64);
  assert.equal(toHex(refreshMessage("log.emojery.app", 1790604800n).subarray(-8)), "000000006aba7600");
  assert.throws(() => reactMessage({ origin: "o", enrollHash: new Uint8Array(31), site: "s", targetId: "t", reaction: "", prevReaction: "", counter: 1 }), RangeError);
});
