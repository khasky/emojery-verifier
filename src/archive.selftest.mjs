// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the checkpoint-archive replay primitive, the published hash chain,
// the shard-coverage checkpoint choice, and the per-day aggregates derived from the
// public entries.
//   node src/archive.selftest.mjs

import { bytesToHex, checkHashChain, dailyAggregates, entryHash, GENESIS_PREV, merkleRootFromLeaves, merkleRootsAtSizes, sha256, utf8, verifyConsistency } from "./transparency.mjs";
import { pickCoveredCheckpoint } from "./checks/archive.mjs";

let failed = false;
const DAY = 86_400_000;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// merkleRootsAtSizes: prefix roots from one pass must match independent
// per-prefix recomputation — the property the archive replay stands on.
const leaves = [];
for (let i = 0; i < 9; i++) leaves.push(await sha256(utf8(`leaf${i}`)));
const sizes = [1, 2, 3, 5, 8, 9];
const roots = await merkleRootsAtSizes(leaves, sizes);
let prefixOk = true;
for (const s of sizes) {
  const direct = await merkleRootFromLeaves(leaves.slice(0, s));
  if (bytesToHex(roots.get(s)) !== bytesToHex(direct)) prefixOk = false;
}
check(prefixOk, "merkleRootsAtSizes: every prefix root equals a direct recomputation");
check(!roots.has(10), "merkleRootsAtSizes: sizes beyond the leaf count are absent");
check((await merkleRootsAtSizes(leaves, [])).size === 0, "merkleRootsAtSizes: empty size set yields no roots");

// A tampered prefix must change its root (replay would flag the archive).
const tampered = leaves.slice();
tampered[2] = await sha256(utf8("evil"));
const tamperedRoots = await merkleRootsAtSizes(tampered, [5]);
check(bytesToHex(tamperedRoots.get(5)) !== bytesToHex(roots.get(5)), "a tampered leaf changes the prefix root");

// --- hash chain ----------------------------------------------------------------
// Build a chained run of leaves the way the log publishes them, then break it the
// two ways a mirror can: a rewritten link, and a leaf that carries no entry_hash.
const chainLeaves = leaves.slice(0, 5);
const chained = [];
let prev = GENESIS_PREV;
for (const [i, leaf] of chainLeaves.entries()) {
  prev = await entryHash(prev, leaf);
  chained.push({ seq: i + 1, leaf_hash: bytesToHex(leaf), entry_hash: bytesToHex(prev) });
}
check((await checkHashChain(chained, chainLeaves)).length === 0, "chain: a correctly chained run replays from genesis");

const relinked = chained.map((e) => ({ ...e }));
relinked[2].entry_hash = bytesToHex(await sha256(utf8("forged link")));
const relinkedViolations = await checkHashChain(relinked, chainLeaves);
check(relinkedViolations.length > 0 && relinkedViolations[0].includes("seq=3"), "chain: a rewritten entry_hash is flagged at its own seq");

const reordered = [chained[0], chained[2], chained[1], chained[3], chained[4]];
const reorderedLeaves = [chainLeaves[0], chainLeaves[2], chainLeaves[1], chainLeaves[3], chainLeaves[4]];
check((await checkHashChain(reordered, reorderedLeaves)).length > 0, "chain: leaves served out of order break the chain");

const unchained = chained.map((e) => ({ ...e }));
unchained[3].entry_hash = null;
const unchainedViolations = await checkHashChain(unchained, chainLeaves);
check(unchainedViolations.length === 1 && unchainedViolations[0].includes("seq=4"), "chain: a leaf with no entry_hash stops the replay once, at that leaf");

// --- pickCoveredCheckpoint -----------------------------------------------------
// What an offline run audits when the entries shards trail the published tip.
const archive = [{ tree_size: "100" }, { tree_size: "1349" }, { tree_size: "1433" }, { parseError: true }];
check(pickCoveredCheckpoint(archive, 1400)?.tree_size === "1349", "coverage: the newest checkpoint at or below the mirrored leaves is chosen");
check(pickCoveredCheckpoint(archive, 1433)?.tree_size === "1433", "coverage: full coverage keeps the tip");
check(pickCoveredCheckpoint(archive, 99) === null, "coverage: no checkpoint below the mirrored leaves yields none");
check(pickCoveredCheckpoint([{ parseError: true }], 5000) === null, "coverage: an unparseable archive line is never chosen");

// Consistency proofs: the cheap half of "the log was not rewritten", ~log2(n) hashes
// with no leaf in hand. The proofs are generated below by a second, independent
// transcription of the subproof recursion, so the check is against the algorithm
// rather than against the verifier's own arithmetic.
async function subProof(m, d, b) {
  if (m === d.length) return b ? [] : [await merkleRootFromLeaves(d)];
  let k = 1;
  while (k * 2 < d.length) k *= 2;
  if (m <= k) return [...(await subProof(m, d.slice(0, k), b)), await merkleRootFromLeaves(d.slice(k))];
  return [...(await subProof(m - k, d.slice(k), false)), await merkleRootFromLeaves(d.slice(0, k))];
}
const consistencyProof = (m, d) => subProof(m, d, true);

let everyPairOk = true;
for (const [first, second] of [
  [1, 2],
  [1, 9],
  [2, 3],
  [3, 5],
  [4, 8],
  [5, 9],
  [8, 9],
]) {
  const proof = await consistencyProof(first, leaves.slice(0, second));
  const ok = await verifyConsistency(first, second, roots.get(first) ?? (await merkleRootFromLeaves(leaves.slice(0, first))), await merkleRootFromLeaves(leaves.slice(0, second)), proof);
  if (!ok) everyPairOk = false;
}
check(everyPairOk, "consistency: a correct proof verifies for every prefix pair tried");

const proof59 = await consistencyProof(5, leaves.slice(0, 9));
const root5 = await merkleRootFromLeaves(leaves.slice(0, 5));
const root9 = await merkleRootFromLeaves(leaves);
check(await verifyConsistency(0, 9, new Uint8Array(32), root9, []), "consistency: every tree extends the empty tree");
check(await verifyConsistency(9, 9, root9, root9, []), "consistency: a tree extends itself with no proof");
check(!(await verifyConsistency(9, 9, root9, root5, [])), "consistency: equal sizes with different roots is refused");
check(!(await verifyConsistency(5, 9, root5, root9, [])), "consistency: an empty proof cannot stand in for a real one");
const bent = proof59.map((h, i) => (i === 0 ? new Uint8Array(32) : h));
check(!(await verifyConsistency(5, 9, root5, root9, bent)), "consistency: a tampered proof element is refused");
check(!(await verifyConsistency(5, 9, root9, root9, proof59)), "consistency: a proof against the wrong old root is refused");

// The scenario the check exists for: the operator rewrites a leaf inside the sealed
// prefix and publishes a new root over the rewritten tree. No proof can carry the
// old root into the new one, whatever the operator serves.
const rewritten = leaves.slice();
rewritten[2] = await sha256(utf8("rewritten"));
const rewrittenRoot9 = await merkleRootFromLeaves(rewritten);
check(!(await verifyConsistency(5, 9, root5, rewrittenRoot9, await consistencyProof(5, rewritten))), "consistency: a rewritten prefix cannot be proven consistent with the old root");

// --- dailyAggregates -----------------------------------------------------------
const T = Date.parse("2026-07-18T10:00:00Z");
const agg = dailyAggregates([
  { seq: 1, ts: T, op: 1, user_ref: "a".repeat(64) },
  { seq: 2, ts: T + 1000, op: 2, user_ref: "a".repeat(64) },
  { seq: 3, ts: T + 2000, op: 1, user_ref: "b".repeat(64) },
  { seq: 4, ts: T + 3000, op: 4 },
  { seq: 5, ts: T + DAY, op: 1, user_ref: "c".repeat(64) },
]);
const d1 = agg.get("2026-07-18");
check(d1.votes === 3 && d1.refs.size === 2 && d1.revokes === 1, "dailyAggregates buckets votes/refs/revokes per UTC day");
check(agg.get("2026-07-19").votes === 1, "next-day leaf lands in the next bucket");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
