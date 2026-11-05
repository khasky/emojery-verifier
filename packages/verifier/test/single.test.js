// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeLeaf, enrollHash, OP, reactMessage, sha256, toHex, utf8 } from "@emojery/shared/core";
import { canonicalJwk } from "../src/enroll.js";
import { Report } from "../src/report.js";
import { leafCheck, targetCheck } from "../src/single.js";
import { Publisher } from "./helpers/publisher.js";

const NOW = 1792800000;
const ISS = "https://issuer.test";
const AUD = "client.test";

async function setup() {
  const p = new Publisher();
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
  const { modulus, json } = canonicalJwk(await crypto.subtle.exportKey("jwk", kp.publicKey));
  const hash = await sha256(modulus);
  const devs = [];
  const leaves = [];
  for (let i = 0; i < 2; i++) {
    const k = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    const pubkey = new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey));
    const enroll = encodeLeaf({ op: OP.ENROLL, nullifier: new Uint8Array(32).fill(i + 1), iss: ISS, aud: AUD, modulusHash: hash, accountPubkey: pubkey, proofHash: new Uint8Array(32).fill(i + 9) });
    devs.push({ privateKey: k.privateKey, pubkey, seq: leaves.length, eh: await enrollHash(enroll) });
    leaves.push(enroll);
  }
  const react = async (d, reaction, prev, counter, targetId = "khasky/emojery") => {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, d.privateKey, reactMessage({ origin: `${p.logName}/g0`, enrollHash: d.eh, site: "github", targetId, reaction, prevReaction: prev, counter })));
    return encodeLeaf({ op: OP.REACT, enrollSeq: BigInt(d.seq), site: "github", targetId, reaction, prevReaction: prev, counter, sig });
  };
  leaves.push(await react(devs[0], "👍", "", 1));
  leaves.push(await react(devs[1], "👍", "", 1));
  leaves.push(await react(devs[1], "🔥", "", 1, "other/repo"));
  leaves.push(encodeLeaf({ op: OP.REVOKE, enrollSeq: BigInt(devs[1].seq), reasonCode: "automation", caseId: new Uint8Array(16).fill(5), banUntil: 0xffffffff }));
  await p.seal(leaves);
  await p.publish();
  p.mirror.set(`jwks/test/${toHex(hash)}.json`, utf8(json));
  await p.anchor(NOW - 60);
  p.syncMirror();
  const pins = { ...p.pins, providers: [{ id: "test", iss: ISS, aud: [AUD], jwksUri: "https://issuer.test/jwks" }] };
  const ctx = (report, extra = {}) => ({ logName: p.logName, pins, bucket: p.host("bucket"), mirror: p.host("mirror"), report, now: NOW, shards: [p.shard.pin], checkProofs: false, ...extra });
  return { p, devs, ctx };
}

test("--leaf proves a REACT of my key with my counter", async () => {
  const { devs, ctx } = await setup();
  const ok = new Report();
  await leafCheck(ctx(ok), { seq: 2, pubkey: devs[0].pubkey, counter: 1 });
  assert.equal(ok.verdict, "PASS", ok.toText());
  const other = new Report();
  await leafCheck(ctx(other), { seq: 2, pubkey: devs[1].pubkey, counter: 1 });
  assert.equal(other.verdict, "FAIL");
  const stale = new Report();
  await leafCheck(ctx(stale), { seq: 2, pubkey: devs[0].pubkey, counter: 2 });
  assert.equal(stale.verdict, "FAIL");
  const later = new Report();
  await leafCheck(ctx(later), { seq: 99, pubkey: devs[0].pubkey });
  assert.equal(later.verdict, "WAIT");
});

test("--leaf on an ENROLL and a REVOKE", async () => {
  const { devs, ctx } = await setup();
  const e = new Report();
  await leafCheck(ctx(e), { seq: 1, pubkey: devs[1].pubkey });
  assert.equal(e.verdict, "PASS", e.toText());
  const r = new Report();
  await leafCheck(ctx(r), { seq: 5 });
  assert.equal(r.verdict, "PASS", r.toText());
  assert.match(r.info.join("\n"), /REVOKE: automation/);
});

test("--target agrees with an honest API and fails a padded one", async () => {
  const { ctx } = await setup();
  const honest = new Report();
  await targetCheck(ctx(honest, { fetchCounts: async () => ({ counts: { "👍": 1 }, total: 1, size: 6, origin: "log-staging.emojery.app/g0" }) }), [{ site: "github", targetId: "khasky/emojery" }]);
  assert.equal(honest.verdict, "PASS", honest.toText());
  assert.match(honest.info.join("\n"), /revoked automation 1 in 1 decision/);
  const atFour = new Report();
  await targetCheck(ctx(atFour, { fetchCounts: async () => ({ counts: { "👍": 2 }, total: 2, size: 4, origin: "log-staging.emojery.app/g0" }) }), [{ site: "github", targetId: "khasky/emojery" }]);
  assert.equal(atFour.verdict, "PASS", atFour.toText());
  const padded = new Report();
  await targetCheck(ctx(padded, { fetchCounts: async () => ({ counts: { "👍": 7 }, total: 7, size: 6, origin: "log-staging.emojery.app/g0" }) }), [{ site: "github", targetId: "khasky/emojery" }]);
  assert.equal(padded.verdict, "FAIL");
  const ahead = new Report();
  await targetCheck(ctx(ahead, { fetchCounts: async () => ({ counts: {}, total: 0, size: 60, origin: "log-staging.emojery.app/g0" }) }), [{ site: "github", targetId: "khasky/emojery" }]);
  assert.equal(ahead.verdict, "WAIT");
});
