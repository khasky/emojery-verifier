// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeLeaf, enrollHash, OP, reactMessage, sha256, toHex, utf8 } from "@emojery/shared/core";
import { canonicalJwk } from "../src/enroll.js";
import { fullCheck } from "../src/full.js";
import { Report } from "../src/report.js";
import { Publisher } from "./helpers/publisher.js";

const NOW = 1792800000;
const ISS = "https://issuer.test";
const AUD = "client.test";

async function providerKeyFile() {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign"]);
  const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
  const { modulus, json } = canonicalJwk(jwk);
  return { hash: await sha256(modulus), json };
}

async function device() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  return { privateKey: kp.privateKey, pubkey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) };
}

/** A log of one ENROLL and two REACTs, published, anchored and mirrored. */
async function log({ badSig = false, iss = ISS } = {}) {
  const p = new Publisher();
  const key = await providerKeyFile();
  const dev = await device();
  const proof = utf8("proof bytes");
  const enroll = encodeLeaf({ op: OP.ENROLL, nullifier: new Uint8Array(32).fill(1), iss, aud: AUD, modulusHash: key.hash, accountPubkey: dev.pubkey, proofHash: await sha256(proof) });
  const eh = await enrollHash(enroll);
  const react = async (reaction, prev, counter, origin = `${p.logName}/g0`) => {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, dev.privateKey, reactMessage({ origin, enrollHash: eh, site: "github", targetId: "khasky/emojery", reaction, prevReaction: prev, counter })));
    if (badSig) sig[0] ^= 1;
    return encodeLeaf({ op: OP.REACT, enrollSeq: 0n, site: "github", targetId: "khasky/emojery", reaction, prevReaction: prev, counter, sig });
  };
  await p.seal([enroll, await react("👍", "", 1), await react("🔥", "👍", 2)]);
  await p.publish();
  p.bucket.set("g0/proofs/0", proof);
  p.mirror.set(`jwks/test/${toHex(key.hash)}.json`, utf8(key.json));
  await p.anchor(NOW - 60);
  p.syncMirror();
  return p;
}

async function run(p, extra = {}) {
  const report = new Report();
  const pins = { ...p.pins, providers: [{ id: "test", iss: ISS, aud: [AUD], jwksUri: "https://issuer.test/jwks" }] };
  const state = await fullCheck({ logName: p.logName, pins, bucket: p.host("bucket"), mirror: p.host("mirror"), report, now: NOW, shards: [p.shard.pin], checkProofs: false, ...extra }, undefined);
  return { report, state };
}

test("an honest log replays", async () => {
  const { report, state } = await run(await log());
  assert.equal(report.verdict, "PASS", report.toText());
  assert.equal(state.size, 3);
  assert.match(report.info.join("\n"), /replayed 3 leaves: 1 ENROLL/);
});

test("a forged REACT signature fails the replay", async () => {
  const { report } = await run(await log({ badSig: true }));
  assert.equal(report.verdict, "FAIL");
  assert.match(report.failures.join("\n"), /signature/);
});

test("an ENROLL from an issuer the log does not admit fails", async () => {
  const { report } = await run(await log({ iss: "https://other.test" }));
  assert.equal(report.verdict, "FAIL");
  assert.match(report.failures.join("\n"), /does not admit|not admitted/);
});

test("a hash tile the fast run never reads is still checked", async () => {
  const p = await log();
  for (const [k, v] of p.bucket) {
    if (k.startsWith("g0/tile/0/")) {
      const bad = new Uint8Array(v);
      bad[0] ^= 1;
      p.bucket.set(k, bad);
    }
  }
  const { report } = await run(p);
  assert.equal(report.verdict, "FAIL");
});

test("a proof object that does not hash to proof_hash fails", async () => {
  const p = await log();
  p.bucket.set("g0/proofs/0", utf8("other bytes"));
  const { report } = await run(p, { checkProofs: true });
  assert.equal(report.verdict, "FAIL");
  assert.match(report.failures.join("\n"), /proof_hash/);
});

