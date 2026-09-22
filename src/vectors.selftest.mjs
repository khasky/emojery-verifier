// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test against the shared log vectors (src/__data__/log-vectors.json): the RFC 6962
// roots and consistency proofs, one published chunk line per leaf kind with its
// leaf_hash and entry_hash, the signed tree head over those leaves, the object paths
// and the counter fold. The publisher replays the same file from its own test suite,
// so a format the two sides read differently fails here rather than on a live log.
//   node src/vectors.selftest.mjs

import { readFileSync } from "node:fs";
import { chunkPath, manifestPath } from "./checks/leaves.mjs";
import {
  bytesToHex,
  checkHashChain,
  checkStructuralInvariants,
  counterKey,
  foldCounters,
  hexToBytes,
  leafHashFromEntry,
  merkleRootFromLeaves,
  merkleRootsAtSizes,
  proofObjectPath,
  sthBytes,
  verifyConsistency,
  verifySth,
} from "./transparency.mjs";

const vectors = JSON.parse(readFileSync(new URL("./__data__/log-vectors.json", import.meta.url), "utf8"));

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// --- Merkle: reference roots and consistency proofs ---------------------------------
const katLeaves = vectors.merkle.leafHashes.map(hexToBytes);
for (let n = 1; n <= katLeaves.length; n++) {
  check(bytesToHex(await merkleRootFromLeaves(katLeaves.slice(0, n))) === vectors.merkle.roots[n], `merkle: root at size ${n} matches the reference`);
}
const sizes = katLeaves.map((_, i) => i + 1);
const prefixRoots = await merkleRootsAtSizes(katLeaves, sizes);
check(
  sizes.every((n) => bytesToHex(prefixRoots.get(n)) === vectors.merkle.roots[n]),
  "merkle: every prefix root from one pass matches the reference",
);
for (const v of vectors.merkle.consistency) {
  const ok = await verifyConsistency(v.first, v.second, hexToBytes(vectors.merkle.roots[v.first]), hexToBytes(vectors.merkle.roots[v.second]), v.proof.map(hexToBytes));
  check(ok, `merkle: reference consistency proof ${v.first} -> ${v.second} verifies`);
}

// --- entries: one chunk line per leaf kind -------------------------------------------
const leaves = [];
for (const e of vectors.entries) {
  const leaf = await leafHashFromEntry(e);
  leaves.push(leaf);
  check(bytesToHex(leaf) === e.leaf_hash, `entries: seq ${e.seq} (op ${e.op}) rehashes to its leaf_hash`);
}
check((await checkHashChain(vectors.entries, leaves)).length === 0, "entries: the published entry_hash chain replays from genesis");
check(checkStructuralInvariants(vectors.entries).length === 0, "entries: the lines satisfy the structural invariants");
check(bytesToHex(await merkleRootFromLeaves(leaves)) === vectors.sth.rootHex, "entries: the leaves fold to the signed root");

// --- the signed tree head ------------------------------------------------------------
const sth = { treeSize: vectors.sth.treeSize, rootHash: hexToBytes(vectors.sth.rootHex), ts: vectors.sth.ts };
check(bytesToHex(sthBytes(sth.treeSize, sth.rootHash, sth.ts)) === vectors.sth.bytesHex, "sth: preimage bytes match");
const pubB64 = Buffer.from(vectors.keypair.publicKeyHex, "hex").toString("base64");
const sig = hexToBytes(vectors.sth.signatureHex);
check(await verifySth(pubB64, sig, sth), "sth: the reference signature verifies under the reference key");
check(!(await verifySth(pubB64, sig, { ...sth, treeSize: sth.treeSize + 1 })), "sth: a different tree_size is refused");

// --- object paths ----------------------------------------------------------------------
for (const p of vectors.paths.chunk) check(chunkPath(p.from, p.to) === p.path, `paths: chunk ${p.from}-${p.to}`);
for (const p of vectors.paths.manifest) check(manifestPath(p.firstLeaf) === p.path, `paths: manifest from leaf ${p.firstLeaf}`);
for (const p of vectors.paths.proof) check(proofObjectPath(p.hashHex) === p.path, "paths: enrolment proof object");

// --- the counter fold ----------------------------------------------------------------
for (const scenario of vectors.fold) {
  const got = foldCounters(scenario.events);
  const want = new Map(scenario.counters.map((c) => [counterKey(c.site, c.target_id, c.reaction), c.count]));
  const same = got.size === want.size && [...want].every(([k, n]) => got.get(k) === n);
  check(same, `fold: ${scenario.name}`);
}

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
