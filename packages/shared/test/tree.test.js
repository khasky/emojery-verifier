// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { EncodingError, fromBase64, fromBase64Url, fromHex, toBase64, toBase64Url, toHex } from "../src/core/bytes.js";
import { leafHash } from "../src/core/messages.js";
import { consistencyProof, inclusionProof, subtreeFromLeafHashes, treeRoot, verifyConsistency, verifyInclusion } from "../src/core/tree.js";

const third = (name) => JSON.parse(readFileSync(new URL(`../vectors/third-party/transparency-dev-merkle/${name}.json`, import.meta.url), "utf8"));
const b64 = (s) => (s == null ? null : fromBase64(s));

// testonly/constants.go of transparency-dev/merkle: eight leaf inputs and the root of
// every prefix tree.
const LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
const ROOTS = [
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];

const hashes = await Promise.all(LEAVES.map((h) => leafHash(fromHex(h))));
const subtree = subtreeFromLeafHashes(hashes);

test("prefix roots match the reference tree", async () => {
  for (let n = 0; n <= 8; n++) assert.equal(toHex(await treeRoot(n, subtree)), ROOTS[n], `size ${n}`);
});

test("generated proofs verify for every leaf and every pair of sizes", async () => {
  for (let n = 1; n <= 8; n++) {
    const root = await treeRoot(n, subtree);
    for (let i = 0; i < n; i++) await verifyInclusion(i, n, hashes[i], await inclusionProof(i, n, subtree), root);
    for (let m = 1; m <= n; m++) await verifyConsistency(m, n, await consistencyProof(m, n, subtree), await treeRoot(m, subtree), root);
  }
});

test("third-party inclusion probes", async () => {
  const probes = third("inclusion");
  assert.equal(probes.length, 98);
  for (const p of probes) {
    const run = () => verifyInclusion(p.leafIdx, p.treeSize, b64(p.leafHash), (p.proof ?? []).map(b64), b64(p.root));
    if (p.wantErr) await assert.rejects(run, undefined, p.file);
    else await run();
  }
});

test("third-party consistency probes", async () => {
  const probes = third("consistency");
  assert.equal(probes.length, 98);
  for (const p of probes) {
    const run = () => verifyConsistency(p.size1, p.size2, (p.proof ?? []).map(b64), b64(p.root1), b64(p.root2));
    if (p.wantErr) await assert.rejects(run, undefined, p.file);
    else await run();
  }
});

test("base64 and base64url are strict", () => {
  assert.equal(toBase64(fromHex("fbff")), "+/8=");
  assert.equal(toBase64Url(fromHex("fbff")), "-_8");
  assert.equal(toHex(fromBase64Url("-_8")), "fbff");
  for (const bad of ["-_8=", "a", "ab c", "+/8", "ab*c"]) assert.throws(() => fromBase64Url(bad), EncodingError, bad);
  for (const bad of ["+/8", "+/9=", " +/8=", "AA=="]) {
    if (bad === "AA==") assert.equal(toHex(fromBase64(bad)), "00");
    else assert.throws(() => fromBase64(bad), EncodingError, bad);
  }
});
