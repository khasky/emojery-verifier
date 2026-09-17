// SPDX-License-Identifier: GPL-3.0-or-later
// What the log says: the re-derived counters, the published revocation feed against
// the op=4 leaves, the structural invariants and account-wipe completeness.

import { getJson } from "../http.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { details, out } from "../report.mjs";
import { checkStructuralInvariants, checkWipeCompleteness, foldCounters } from "../transparency.mjs";
import { ENTRIES_PAGE } from "./leaves.mjs";

// Every counter Emojery publishes is re-derived from leaves this run already
// verified against the signed root. Nothing is compared with the live counter
// surface: the totals are derived independently, which is this tool's whole value.
export function reportFold(entries) {
  const counts = foldCounters(entries);
  out(`folded ${counts.size} (site,target,reaction) counters from ${entries.length} events`);
}

// The bare feed answers the newest 1000 tombstones plus has_more; when it did not
// truncate it is the whole set in one request. Otherwise the range path is walked
// over the whole tree, so a revocation the API invents outside the windows we
// already know about is still seen.
export async function fetchRevocations(api, treeSize) {
  const bare = await getJson(`${api}/log/revocations`);
  if (!bare.has_more) {
    // The feed reads the live log, so a revocation appended after the audited
    // checkpoint is clamped away rather than read as a set mismatch.
    return (bare.revocations ?? []).filter((r) => Number(r.seq) <= treeSize);
  }
  const rows = [];
  for (let from = 1; from <= treeSize; from += ENTRIES_PAGE) {
    const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
    const page = await getJson(`${api}/log/revocations/range?from=${from}&to=${to}`);
    rows.push(...(page.revocations ?? []));
  }
  return rows;
}

export async function checkRevocationFeed(api, entries, treeSize) {
  if (!api) {
    skipCheck("/log/revocations comparison (offline audit, no --api)", "revocations");
    return;
  }
  try {
    const revList = await fetchRevocations(api, treeSize);
    out(`revocations: ${revList.length} tombstone(s)`);
    details(
      revList.map((r) => `revoke seq=${r.seq} -> revoke_seq=${r.revoke_seq} reason=${r.reason_code ?? "-"} target=${r.target?.site}/${r.target?.target_id}`),
      5,
    );
    const op4 = entries
      .filter((e) => e.op === 4)
      .map((e) => String(e.seq))
      .sort();
    const listed = revList.map((r) => String(r.seq)).sort();
    check(op4.length === listed.length && op4.every((s, i) => s === listed[i]), `/log/revocations matches op=4 leaves in the log (${op4.length})`, "revocations");
  } catch (e) {
    check(false, `/log/revocations fetch: ${e.message}`, "revocations");
  }
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
