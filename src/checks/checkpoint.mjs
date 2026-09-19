// SPDX-License-Identifier: GPL-3.0-or-later
// The signed tree head: its signature, its age, and its agreement with the anchor
// published in the log repository.

import { check, record } from "../outcomes.mjs";
import { hexToBytes, verifySth } from "../transparency.mjs";

export function checkCheckpointSignature(pubkey, cp) {
  return verifySth(pubkey, hexToBytes(cp.signature), {
    treeSize: BigInt(cp.tree_size),
    rootHash: hexToBytes(cp.root_hash),
    ts: cp.ts,
  }).then((ok) => check(ok, "checkpoint Ed25519 signature", "signature"));
}

// Judged on the live tip, never on a checkpoint an offline run stepped back to.
// The ts is part of the signed tree head, so a future-dated one is the log's fault:
// beyond a small clock-skew tolerance it is its own failure, or it would sail under
// any positive age threshold forever.
export function checkFreshness(liveCp, maxAgeHours) {
  if (maxAgeHours <= 0) {
    record("freshness", "skip");
    return;
  }
  const SKEW_H = 1;
  const ageH = (Date.now() - Number(liveCp.ts)) / 3_600_000;
  if (ageH < -SKEW_H) {
    check(false, `checkpoint ts is ${(-ageH).toFixed(1)}h in the FUTURE - the signed tree head is misdated (beyond ${SKEW_H}h clock-skew tolerance)`, "freshness");
    return;
  }
  check(ageH <= maxAgeHours, `checkpoint is fresh (${ageH.toFixed(1)}h old, threshold ${maxAgeHours}h; a quiet log ages legitimately, tune --max-checkpoint-age-hours)`, "freshness");
}
