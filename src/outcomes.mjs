// SPDX-License-Identifier: GPL-3.0-or-later
// The per-check outcomes behind the verdict and the --json summary. Each check key
// holds one of pass / fail / skip; a fail is sticky, and a pass replaces a skip.

import { mark } from "./report.mjs";

export const checks = {};
let failed = false;

export function record(key, status) {
  if (checks[key] === "fail") return;
  if (status === "fail") {
    checks[key] = "fail";
    return;
  }
  if (checks[key] === undefined || checks[key] === "skip") checks[key] = status;
}

export function check(ok, msg, key) {
  mark(ok ? "pass" : "fail", msg);
  if (!ok) failed = true;
  if (key) record(key, ok ? "pass" : "fail");
}

// An observation the run reports without deciding on it. Distinct from a check that
// could not run (skipCheck) and from one that judges (check): the closing tally needs
// to show it, and a disagreement here must not turn a sound log red.
export function report(ok, msg, key) {
  mark(ok ? "pass" : "note", msg);
  if (key) record(key, ok ? "pass" : "note");
}

// A check that could not run is its own outcome, never folded into a pass: the
// closing tally has to say how much of the audit executed.
export function skipCheck(msg, key) {
  mark("skip", msg);
  if (key) record(key, "skip");
}

export function hasFailed() {
  return failed;
}
