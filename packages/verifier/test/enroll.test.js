// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { crsPoints, enrollPublicInputs, PUBLIC_INPUT_COUNT, proofChecker, verificationKey } from "../src/enroll.js";
import { pinsFor } from "../src/pins.js";

const fixture = (name) => readFile(new URL(`./fixtures/enroll-proof/${name}`, import.meta.url));

test("the packaged verification key and CRS points match their pins", async () => {
  const vk = await verificationKey(2, pinsFor("log-staging.emojery.app").enroll[2].vkSha256);
  assert.equal(vk.length, 1888);
  const { g1, g2 } = await crsPoints();
  assert.equal(g1.length, 64);
  assert.equal(g2.length, 128);
  await assert.rejects(verificationKey(2, "00".repeat(32)), /does not match its pin/);
});

test("public inputs have the circuit's layout", () => {
  const n = new Uint8Array(256).fill(0xff);
  const inputs = enrollPublicInputs({ modulus: n, iss: "https://accounts.google.com", aud: "x", nullifier: new Uint8Array(32), saltCommitment: new Uint8Array(32), accountPubkey: new Uint8Array(32).fill(7) });
  assert.equal(inputs.length, PUBLIC_INPUT_COUNT);
  assert.equal(inputs.at(-1), `0x${"07".padStart(64, "0")}`);
  assert.throws(() => enrollPublicInputs({ modulus: n.subarray(1), iss: "a", aud: "b", nullifier: new Uint8Array(32), saltCommitment: new Uint8Array(32), accountPubkey: new Uint8Array(32) }), /2048 bits/);
});

// A proof from the genesis circuit (verifier target evm), made locally with bb 5.2.0.
test("a real ENROLL proof verifies offline, a tampered one does not", { timeout: 120000 }, async () => {
  const vk = await verificationKey(2, pinsFor("log-staging.emojery.app").enroll[2].vkSha256);
  const proof = new Uint8Array(await fixture("proof"));
  const pi = new Uint8Array(await fixture("public_inputs"));
  const inputs = [];
  for (let i = 0; i < pi.length; i += 32) inputs.push(`0x${Buffer.from(pi.subarray(i, i + 32)).toString("hex")}`);
  const checker = await proofChecker(vk);
  try {
    assert.equal(await checker.verify(proof, inputs), true);
    const bad = [...inputs];
    bad[357] = `0x${"00".repeat(31)}01`;
    assert.equal(await checker.verify(proof, bad), false);
  } finally {
    await checker.close();
  }
});
