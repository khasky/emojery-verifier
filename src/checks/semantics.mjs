// SPDX-License-Identifier: GPL-3.0-or-later
// What the log says: the re-derived counters, the published tombstone file against
// the op=4 leaves, the structural invariants and account-wipe completeness.

import { getJson } from "../http.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { details, out } from "../report.mjs";
import { checkStructuralInvariants, checkWipeCompleteness, foldCounters } from "../transparency.mjs";

// Every counter Emojery publishes is re-derived from leaves this run already
// verified against the signed root. Nothing is compared with the live counter
// surface: the totals are derived independently, which is this tool's whole value.
export function reportFold(entries) {
  const counts = foldCounters(entries);
  out(`folded ${counts.size} (site,target,reaction) counters from ${entries.length} events`);
}

// The published tombstone file against the op=4 leaves this run already verified
// against the signed root. It exists for the readers who never fold the log - the
// site renders it - so a file that shows fewer tombstones than the log holds would
// be a deletion hidden from exactly those readers.
export async function checkRevocationFeed(repo, entries, treeSize) {
  const op4 = entries
    .filter((e) => e.op === 4)
    .map((e) => String(e.seq))
    .sort();
  let published;
  try {
    published = await getJson(`${repo}/revocations/latest.json`);
  } catch (e) {
    // A log with no tombstone yet publishes no file, which is not a mismatch.
    if (e.status === 404 && op4.length === 0) {
      skipCheck("revocations/latest.json (nothing revoked yet)", "revocations");
      return;
    }
    check(false, `revocations/latest.json: ${e.message}`, "revocations");
    return;
  }
  const { listed, agree } = compareRevocations(op4, published, treeSize);
  out(`revocations: ${listed.length} tombstone(s)`);
  details(
    (published.revocations ?? []).filter((r) => Number(r.seq) <= treeSize).map((r) => `revoke seq=${r.seq} -> revoke_seq=${r.revoke_seq} reason=${r.reason_code ?? "-"} target=${r.target?.site}/${r.target?.target_id}`),
    5,
  );
  check(agree, `revocations/latest.json matches the op=4 leaves in the log (${op4.length})`, "revocations");
}

// The published file against the seqs the leaves carry. The file is written over the
// live log, so a tombstone appended after the audited checkpoint is clamped away
// rather than read as a set mismatch on an honest log.
export function compareRevocations(op4, published, treeSize) {
  const listed = (published.revocations ?? [])
    .map((r) => String(r.seq))
    .filter((seq) => Number(seq) <= treeSize)
    .sort();
  return { listed, agree: op4.length === listed.length && op4.every((seq, i) => seq === listed[i]) };
}

export function checkStructure(entries) {
  const violations = checkStructuralInvariants(entries);
  details(violations, 20);
  check(violations.length === 0, `structural invariants hold (${violations.length} violation(s))`, "invariants");
}

// Revocations are whole-account, so a pseudonym with some but not all of its leaves
// revoked is flagged, after the grace window for wipes still in flight.
export function checkWipes(entries, cp, wipeGraceHours) {
  const wipe = checkWipeCompleteness(entries, Number(cp.ts), wipeGraceHours * 3_600_000);
  details(wipe, 20);
  check(wipe.length === 0, `account wipes are complete (${wipe.length} violation(s); grace ${wipeGraceHours}h)`, "wipe_completeness");
}
