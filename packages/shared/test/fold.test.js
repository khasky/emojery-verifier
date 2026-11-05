// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { Fold, FoldError } from "../src/core/fold.js";
import { encodeLeaf, OP } from "../src/core/leaf.js";
import { enrollHash, reactMessage, retireMessage } from "../src/core/messages.js";

const LOG = "log.emojery.app";

async function device() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const pubkey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { privateKey: kp.privateKey, pubkey };
}

let proofCounter = 0;
/** An ENROLL of `dev` under the nullifier filled with `n`. */
function enrollBytes(dev, n, proofByte = ++proofCounter) {
  return encodeLeaf({ op: OP.ENROLL, nullifier: new Uint8Array(32).fill(n), iss: "https://accounts.google.com", aud: "client", modulusHash: new Uint8Array(32), accountPubkey: dev.pubkey, proofHash: new Uint8Array(32).fill(proofByte) });
}

async function reactBytes(dev, enrollSeq, enrollLeaf, v, origin = `${LOG}/g0`) {
  const eh = await enrollHash(enrollLeaf);
  const msg = reactMessage({ origin, enrollHash: eh, site: v.site ?? "github", targetId: v.targetId ?? "khasky/emojery", reaction: v.reaction, prevReaction: v.prev ?? "", counter: v.counter });
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, dev.privateKey, msg));
  return encodeLeaf({ op: OP.REACT, enrollSeq: BigInt(enrollSeq), site: v.site ?? "github", targetId: v.targetId ?? "khasky/emojery", reaction: v.reaction, prevReaction: v.prev ?? "", counter: v.counter, sig });
}

const revokeBytes = (enrollSeq) => encodeLeaf({ op: OP.REVOKE, enrollSeq: BigInt(enrollSeq), reasonCode: "automation", caseId: new Uint8Array(16).fill(1), banUntil: 0xffffffff });

async function retireSelf(dev, enrollSeq, enrollLeaf, n) {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, dev.privateKey, retireMessage(LOG, await enrollHash(enrollLeaf))));
  return encodeLeaf({ op: OP.RETIRE, enrollSeq: BigInt(enrollSeq), nullifier: new Uint8Array(32).fill(n), reason: "self", sig, caseId: new Uint8Array(0) });
}

const retireBy = (reason, enrollSeq, n) => encodeLeaf({ op: OP.RETIRE, enrollSeq: BigInt(enrollSeq), nullifier: new Uint8Array(32).fill(n), reason, sig: new Uint8Array(0), caseId: new Uint8Array(16).fill(2) });

const fold = (originAt = () => `${LOG}/g0`) => new Fold({ logName: LOG, originAt });
const counts = (f, site = "github", target = "khasky/emojery") => f.targetCounts(site, target);

test("add, change, remove", async () => {
  const d = await device();
  const f = fold();
  const e = enrollBytes(d, 1);
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 1 }));
  assert.deepEqual(counts(f), { top: [["👍", 1]], total: 1 });
  await f.apply(await reactBytes(d, 0, e, { reaction: "🔥", prev: "👍", counter: 2 }));
  assert.deepEqual(counts(f), { top: [["🔥", 1]], total: 1 });
  await f.apply(await reactBytes(d, 0, e, { reaction: "", prev: "🔥", counter: 3 }));
  assert.deepEqual(counts(f), { top: [], total: 0 });
});

test("a REACT must match the pair and raise the counter", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  for (const bad of [
    [{ reaction: "👍", counter: 1 }, { reaction: "🔥", prev: "", counter: 2 }],
    [{ reaction: "👍", counter: 1 }, { reaction: "🔥", prev: "👍", counter: 1 }],
    [{ reaction: "👍", counter: 0 }],
  ]) {
    const f = fold();
    await f.apply(e);
    const leaves = await Promise.all(bad.map((v) => reactBytes(d, 0, e, v)));
    for (const l of leaves.slice(0, -1)) await f.apply(l);
    await assert.rejects(f.apply(leaves.at(-1)), FoldError);
  }
});

test("signatures bind the generation, the ENROLL and the key", async () => {
  const d = await device();
  const other = await device();
  const e = enrollBytes(d, 1);
  const f = fold((seq) => (seq < 2 ? `${LOG}/g0` : `${LOG}/g1`));
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 1 }));
  await assert.rejects(f.apply(await reactBytes(d, 0, e, { reaction: "", prev: "👍", counter: 2 }, `${LOG}/g0`)), /signature/);
  await f.apply(await reactBytes(d, 0, e, { reaction: "", prev: "👍", counter: 2 }, `${LOG}/g1`));
  await assert.rejects(f.apply(await reactBytes(other, 0, e, { reaction: "👍", counter: 3 }, `${LOG}/g1`)), /signature/);
  await assert.rejects(f.apply(await reactBytes(d, 0, enrollBytes(d, 1), { reaction: "👍", counter: 3 }, `${LOG}/g1`)), /signature/);
});

test("enroll_seq must name an earlier ENROLL", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  const f = fold();
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 1 }));
  await assert.rejects(f.apply(await reactBytes(d, 1, e, { reaction: "", prev: "👍", counter: 2 })), /not an earlier ENROLL/);
  await assert.rejects(f.apply(await reactBytes(d, 5, e, { reaction: "", prev: "👍", counter: 2 })), /not an earlier ENROLL/);
  await assert.rejects(f.apply(revokeBytes(1)), /not an earlier ENROLL/);
});

test("REVOKE empties every pair, counters carry on, the ENROLL stays usable", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  const f = fold();
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 1 }));
  await f.apply(await reactBytes(d, 0, e, { reaction: "❤️", targetId: "a/b", counter: 1 }));
  await f.apply(revokeBytes(0));
  assert.equal(counts(f).total, 0);
  assert.equal(counts(f, "github", "a/b").total, 0);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 2 }));
  assert.deepEqual(counts(f), { top: [["👍", 1]], total: 1 });
});

test("after REVOKE the next REACT starts from an empty pair with a higher counter", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  const f = fold();
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 4 }));
  await f.apply(revokeBytes(0));
  await assert.rejects(f.apply(await reactBytes(d, 0, e, { reaction: "🔥", prev: "👍", counter: 5 })), /prev_reaction/);
  await assert.rejects(f.apply(await reactBytes(d, 0, e, { reaction: "🔥", counter: 4 })), /counter/);
  await f.apply(await reactBytes(d, 0, e, { reaction: "🔥", counter: 5 }));
  assert.deepEqual(counts(f), { top: [["🔥", 1]], total: 1 });
});

test("RETIRE empties pairs, restarts counters and kills earlier ENROLLs", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  const f = fold();
  await f.apply(e);
  const old = await reactBytes(d, 0, e, { reaction: "👍", counter: 1 });
  await f.apply(old);
  await f.apply(await retireSelf(d, 0, e, 1));
  assert.equal(counts(f).total, 0);
  // Replaying the old signature, or a fresh one under the retired ENROLL, fails.
  await assert.rejects(f.apply(old), /retired/);
  // A byte-for-byte copy of the old ENROLL is refused; re-enrolling needs a new proof, and counters start over.
  await assert.rejects(f.apply(e), /proof_hash/);
  const e2 = enrollBytes(d, 1);
  await f.apply(e2);
  await f.apply(await reactBytes(d, 3, e2, { reaction: "👍", counter: 1 }));
  assert.deepEqual(counts(f), { top: [["👍", 1]], total: 1 });
});

test("RETIRE rules", async () => {
  const d = await device();
  const other = await device();
  const e = enrollBytes(d, 1);
  const base = async () => {
    const f = fold();
    await f.apply(e);
    return f;
  };
  await assert.rejects((await base()).apply(await retireSelf(other, 0, e, 1)), /signature/);
  await assert.rejects((await base()).apply(retireBy("legal", 0, 2)), /nullifier/);
  const f = await base();
  await f.apply(retireBy("request", 0, 1));
  await assert.rejects(f.apply(await retireSelf(d, 0, e, 1)), /retired/);
  await f.apply(retireBy("legal", 0, 1));
  await f.apply(revokeBytes(0));
});

test("REVOKE and RETIRE count each pair once in one walk", async () => {
  const d1 = await device();
  const d2 = await device();
  const e1 = enrollBytes(d1, 1);
  const e2 = enrollBytes(d2, 2);
  const f = fold();
  await f.apply(e1);
  await f.apply(e2);
  await f.apply(await reactBytes(d1, 0, e1, { reaction: "👍", counter: 1 }));
  await f.apply(await reactBytes(d2, 1, e2, { reaction: "👍", counter: 1 }));
  await f.apply(revokeBytes(0));
  await f.apply(retireBy("request", 0, 1));
  assert.deepEqual(counts(f), { top: [["👍", 1]], total: 1 });
});

test("top 10 orders ties by bytes, not by UTF-16", async () => {
  const f = fold();
  f.bump("github", "x/y", "☝\u{1F3FB}", 1);
  f.bump("github", "x/y", "☝️", 1);
  for (let i = 0; i < 11; i++) f.bump("github", "x/y", String.fromCodePoint(0x1f600 + i), 2);
  const c = f.targetCounts("github", "x/y");
  assert.equal(c.total, 24);
  assert.equal(c.top.length, 10);
  assert.deepEqual(c.top[0], ["😀", 2]);
  const g = fold();
  g.bump("github", "x/y", "☝\u{1F3FB}", 1);
  g.bump("github", "x/y", "☝️", 1);
  assert.deepEqual(g.targetCounts("github", "x/y").top.map((x) => x[0]), ["☝️", "☝\u{1F3FB}"]);
});

test("keepTarget folds only the named targets", async () => {
  const d = await device();
  const e = enrollBytes(d, 1);
  const f = new Fold({ logName: LOG, originAt: () => `${LOG}/g0`, keepTarget: (s, t) => t === "a/b" });
  await f.apply(e);
  await f.apply(await reactBytes(d, 0, e, { reaction: "👍", counter: 1 }));
  await f.apply(await reactBytes(d, 0, e, { reaction: "❤️", targetId: "a/b", counter: 1 }));
  assert.equal(counts(f).total, 0);
  assert.deepEqual(counts(f, "github", "a/b"), { top: [["❤️", 1]], total: 1 });
});
