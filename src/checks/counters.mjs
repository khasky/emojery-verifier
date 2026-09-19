// SPDX-License-Identifier: GPL-3.0-or-later
// The one place the log is held against the number a reader is actually shown.
//
// Everything else in this tool re-derives the counters from the published leaves and
// stops there, which proves the log is internally sound and says nothing about what
// the service serves. The badge is the served number on a public, ungated surface -
// the same `readCounters` row the extension's own count comes from - so comparing it
// with the fold closes the one gap a log alone cannot: a count nobody can trace back
// to a leaf.
//
// A sample rather than every counter: one request per target, and the targets that
// matter are the ones carrying most of the count. `--counts-sample 0` turns it off.

import { getJson } from "../http.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { details, phase } from "../report.mjs";
import { foldCounters } from "../transparency.mjs";

// The badge path is greedy after `<site>/` and ends at the literal `.json`, so a
// target id keeps its slashes and everything else is escaped.
function badgeUrl(base, site, targetId) {
  const path = String(targetId)
    .split("/")
    .map((seg) => encodeURIComponent(seg))
    .join("/");
  return `${base.replace(/\/$/, "")}/badge/${encodeURIComponent(site)}/${path}.json`;
}

// Per-target totals, largest first: the fold is keyed per reaction, the badge counts
// the target.
export function foldedTargets(entries) {
  const totals = new Map();
  for (const [key, count] of foldCounters(entries)) {
    const [site, targetId] = key.split("\x00");
    const k = `${site}\x00${targetId}`;
    totals.set(k, (totals.get(k) ?? 0) + count);
  }
  return [...totals]
    .map(([k, total]) => {
      const [site, targetId] = k.split("\x00");
      return { site, targetId, total };
    })
    .sort((a, b) => b.total - a.total);
}

export async function checkServedCounts(entries, { base, sample }) {
  if (!base || sample <= 0) {
    skipCheck(`served counts against the fold (${base ? "--counts-sample 0" : "no --counts-base"})`, "served_counts");
    return;
  }
  const targets = foldedTargets(entries).slice(0, sample);
  if (targets.length === 0) {
    skipCheck("served counts against the fold (the log folds to no counter)", "served_counts");
    return;
  }
  const reading = phase("reading served counts");
  const mismatches = [];
  let read = 0;
  for (const t of targets) {
    let served;
    try {
      served = await getJson(badgeUrl(base, t.site, t.targetId));
    } catch (e) {
      // A target the badge host cannot answer is not a disagreement about a count.
      mismatches.push(`${t.site}/${t.targetId}: ${e.message}`);
      continue;
    }
    read++;
    reading.tick(read, targets.length);
    // `total` is the exact count behind the badge's rounded message. A build that
    // does not publish it yet leaves nothing to compare, and saying so beats
    // reporting a match that was never made.
    if (typeof served.total !== "number") {
      mismatches.push(`${t.site}/${t.targetId}: the badge carries no exact total`);
      continue;
    }
    if (served.total !== t.total) mismatches.push(`${t.site}/${t.targetId}: served ${served.total}, the log folds to ${t.total}`);
  }
  reading.end(read, targets.length);
  details(mismatches, 10);
  check(mismatches.length === 0, `the served count matches the fold on the ${targets.length} largest target(s) (${mismatches.length} disagreement(s))`, "served_counts");
}
