#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the two witness policies that decide without a network: when a
// missing or old OpenTimestamps proof is a skip, a pass or a failure (--ots), and
// which Software Heritage visit counts and whether it is recent enough (--swh).
//   node src/witness.selftest.mjs

import { otsLagOutcome } from "./checks/ots.mjs";
import { pickSwhVisit } from "./checks/swh.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = Date.parse("2026-09-21T12:00:00Z");

// --- OTS lag ---------------------------------------------------------------------

// No proof yet: the log is younger than the allowance, so maturation may still be
// under way - a skip, never a pass.
let o = otsLagOutcome({ liveTs: NOW - 6 * HOUR, proofTs: null, now: NOW, maxLagHours: 48 });
check(o.status === "skip", `no proof, 6h-old checkpoint -> skip (${o.status})`);

// No proof and the log is older than the allowance: the pipeline never matured a thing.
o = otsLagOutcome({ liveTs: NOW - 49 * HOUR, proofTs: null, now: NOW, maxLagHours: 48 });
check(o.status === "fail", `no proof, 49h-old checkpoint -> fail (${o.status})`);

// The boundary is inclusive: exactly the allowance still passes.
o = otsLagOutcome({ liveTs: NOW - 48 * HOUR, proofTs: null, now: NOW, maxLagHours: 48 });
check(o.status === "skip", `no proof, exactly 48h -> still skip (${o.status})`);

// A proof for a checkpoint 30h behind the tip: within the allowance.
o = otsLagOutcome({ liveTs: NOW - HOUR, proofTs: NOW - 31 * HOUR, now: NOW, maxLagHours: 48 });
check(o.status === "pass", `proof 30h behind the tip -> pass (${o.status})`);

// The daily-checkpoint case: yesterday's proof against today's checkpoint is a 24h lag.
o = otsLagOutcome({ liveTs: NOW - 4 * HOUR, proofTs: NOW - 28 * HOUR, now: NOW, maxLagHours: 48 });
check(o.status === "pass", `daily cadence, 24h lag -> pass (${o.status})`);

// A proof 3 days behind a fresh tip: maturation stopped.
o = otsLagOutcome({ liveTs: NOW - HOUR, proofTs: NOW - 73 * HOUR, now: NOW, maxLagHours: 48 });
check(o.status === "fail", `proof 72h behind the tip -> fail (${o.status})`);

// The proof IS the tip (a quiet log): zero lag, whatever the tip's age.
o = otsLagOutcome({ liveTs: NOW - 10 * DAY, proofTs: NOW - 10 * DAY, now: NOW, maxLagHours: 48 });
check(o.status === "pass", `proof for the tip itself, 10 days old -> pass (${o.status})`);

// --- SWH visit choice ------------------------------------------------------------

const visits = [
  { date: "2026-09-19T20:17:15Z", status: "full", snapshot: "aaaa" },
  { date: "2026-09-20T20:17:15Z", status: "partial", snapshot: "bbbb" },
  { date: "2026-09-18T20:17:15Z", status: "full", snapshot: "cccc" },
  { date: "2026-09-21T09:00:00Z", status: "not_found", snapshot: null },
];

// The newest FULL visit wins; a partial or failed one later is not an archive.
let v = pickSwhVisit(visits, NOW, 7);
check(v.visit?.snapshot === "aaaa", `newest completed visit chosen (${v.visit?.snapshot})`);
check(v.fresh === true && Math.abs(v.ageDays - 1.66) < 0.01, `1.7 days old within 7 -> fresh (${v.ageDays?.toFixed(2)})`);

// Past the allowance.
v = pickSwhVisit(visits, NOW + 8 * DAY, 7);
check(v.fresh === false, `9.7 days old past 7 -> stale (${v.ageDays?.toFixed(2)})`);

// Nothing completed at all.
v = pickSwhVisit(visits.filter((x) => x.status !== "full"), NOW, 7);
check(v.visit === null && v.fresh === false, "no completed visit -> none");

// A shape that is not a list is no visit, not a crash.
v = pickSwhVisit({ error: "throttled" }, NOW, 7);
check(v.visit === null, "non-list response -> none");

if (failed) {
  console.error("witness selftest FAILED");
  process.exit(1);
}
console.log("witness selftest OK");
