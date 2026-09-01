// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the revoke (op=4) track in the standalone verifier.
//   node src/revoke.selftest.mjs
//
// Asserts the verifier's serializeLeaf / foldCounters / checkStructuralInvariants
// are self-consistent on a known revoke example, and prints the resulting hashes.

import {
  bytesToHex,
  checkStructuralInvariants,
  checkWipeCompleteness,
  counterKey,
  foldCounters,
  leafHash,
  serializeLeaf,
} from "./transparency.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// --- KAT: a fixed revoke leaf -------------------------------------------------
const KAT = {
  seq: 42n,
  ts: 1700000000000,
  op: 4,
  site: "github",
  targetId: "gh:o/r",
  reaction: null,
  prevReaction: null,
  userRef: null,
  revokeSeq: 7n,
  reasonCode: "erasure_admin",
  evidenceHash: Uint8Array.from({ length: 32 }, (_, i) => i), // 0x00..0x1f
};
const canonicalHex = bytesToHex(serializeLeaf(KAT));
const leafHex = bytesToHex(await leafHash(KAT));
console.log(`KAT canonical = ${canonicalHex}`);
console.log(`KAT leaf_hash = ${leafHex}`);
// ASSERTED, not just printed: this is the byte-format pin on the verifier side
// (the publisher pins the same vector on its side, byte-for-byte).
// A silent print would let a serialization regression sail through the selftest.
check(
  canonicalHex === "000000000000002a0000018bcfe5680004000000066769746875620000000667683a6f2f72ffffffffffffffffffffffff00000000000000070000000d657261737572655f61646d696e00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "KAT canonical bytes match the pinned vector",
);
check(leafHex === "e927976c582f793b28d02a7371d5492164c67a2c88f863063e2cd9d850812837", "KAT leaf_hash matches the pinned vector");

// --- fold: add -> revoke -> re-revoke (idempotent, clamp) ---------------------
const ck = (r) => counterKey("github", "gh:o/r", r);
const evAdd = { seq: 1n, op: 1, site: "github", target_id: "gh:o/r", reaction: "👍", prev_reaction: null };
const evRevoke = { seq: 2n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 1n };
const evRevoke2 = { seq: 3n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 1n };

check(foldCounters([evAdd]).get(ck("👍")) === 1, "fold: lone add => 1");
check((foldCounters([evAdd, evRevoke]).get(ck("👍")) ?? 0) === 0, "fold: add+revoke => 0");
check(
  (foldCounters([evAdd, evRevoke, evRevoke2]).get(ck("👍")) ?? 0) === 0,
  "fold: add+revoke+re-revoke => 0 (idempotent)",
);
// revoke of an unseen / forward seq is a no-op
check(foldCounters([evRevoke, evAdd]).get(ck("👍")) === 1, "fold: forward revoke is a no-op");
// switch re-credit: add A, switch A->B, revoke the switch => A back to 1, B to 0
const evAddA = { seq: 1n, op: 1, site: "github", target_id: "gh:o/r", reaction: "A", prev_reaction: null };
const evSwitch = { seq: 2n, op: 2, site: "github", target_id: "gh:o/r", reaction: "B", prev_reaction: "A" };
const evRevSwitch = { seq: 3n, op: 4, site: "github", target_id: "gh:o/r", revoke_seq: 2n };
const sw = foldCounters([evAddA, evSwitch, evRevSwitch]);
check((sw.get(ck("A")) ?? 0) === 1 && (sw.get(ck("B")) ?? 0) === 0, "fold: revoke of switch re-credits prev");

// --- invariants D/E -----------------------------------------------------------
const base = [
  { seq: 1, op: 1, site: "s", target_id: "t", reaction: "x", prev_reaction: null, user_ref: "a".repeat(64) },
];
const ok = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
]);
check(ok.length === 0, `invariants: valid revoke passes (${ok.join("; ")})`);
const dangling = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 999 },
]);
check(dangling.length === 1, "invariants D: dangling revoke_seq flagged");
const self = checkStructuralInvariants([...base, { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 2 }]);
check(self.length === 1, "invariants D: self-revoke flagged");
const forward = checkStructuralInvariants([
  { seq: 1, op: 4, site: "s", target_id: "t", revoke_seq: 2 },
  { seq: 2, op: 1, site: "s", target_id: "t", reaction: "x", prev_reaction: null, user_ref: "a".repeat(64) },
]);
check(forward.length === 1, "invariants D: forward revoke flagged");
const dbl = checkStructuralInvariants([
  ...base,
  { seq: 2, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
  { seq: 3, op: 4, site: "s", target_id: "t", revoke_seq: 1 },
]);
check(dbl.length === 1, "invariants E: double-revoke flagged");

// --- invariant F: account-wipe completeness ------------------------------------
// Fixtures need ts (grace math) and a 64-hex user_ref on op 1/2/3 leaves.
const T0 = 1700000000000;
const HR = 3_600_000;
const TIP = T0 + 100 * HR; // checkpoint ts, far beyond the default 48h grace
const U = "b".repeat(64);
const V = "c".repeat(64);
const wl = (seq, tgt, ref) => ({
  seq,
  ts: T0,
  op: 1,
  site: "s",
  target_id: tgt,
  reaction: "x",
  prev_reaction: null,
  user_ref: ref,
});
const rv = (seq, cites, ts) => ({ seq, ts, op: 4, site: "s", target_id: "t", revoke_seq: cites });
const L = [wl(1, "t1", U), wl(2, "t2", U), wl(3, "t3", V)]; // U owns two leaves, V one

check(
  checkWipeCompleteness([...L, rv(4, 1, T0 + HR), rv(5, 2, T0 + HR)], TIP).length === 0,
  "invariant F: complete wipe passes",
);
const part = checkWipeCompleteness([...L, rv(4, 1, T0 + HR)], TIP);
check(
  part.length === 1 && part[0].startsWith("seq=2"),
  "invariant F: partial wipe flagged after grace",
);
check(
  checkWipeCompleteness([...L, rv(4, 1, T0 + HR)], T0 + 2 * HR).length === 0,
  "invariant F: partial wipe within grace passes",
);
check(checkWipeCompleteness(L, TIP).length === 0, "invariant F: un-wiped pseudonyms are not checked");
// U owns three leaves; its wipe STARTED long ago (leaf 1 revoked at T0+HR) but leaf 3 is
// still uncited. A later revoke of leaf 2 must NOT reset the grace clock and hide it: grace
// is anchored to the FIRST citing revoke, so an operator cannot drip revokes to keep one
// surgically-kept vote un-flagged forever.
const L3 = [wl(1, "t1", U), wl(2, "t2", U), wl(3, "t3", U)];
const resumed = checkWipeCompleteness([...L3, rv(4, 1, T0 + HR), rv(5, 2, TIP - HR)], TIP);
check(
  resumed.length === 1 && resumed[0].startsWith("seq=3"),
  "invariant F: grace anchors to the FIRST revoke; a later one does not extend it",
);
const fwd = checkWipeCompleteness([...L, rv(4, 1, TIP + HR)], TIP);
check(fwd.length === 1, "invariant F: revoke timestamped after the checkpoint is flagged");
const dangling4 = checkWipeCompleteness([...L, rv(4, 999, T0 + HR)], TIP);
check(dangling4.length === 0, "invariant F: dangling revoke left to invariant D (no double-report)");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
