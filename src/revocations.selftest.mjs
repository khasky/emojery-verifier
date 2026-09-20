// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the verifier's HTTP layer: the published tombstone file, the chunk
// reader and its manifest chain, the served-count comparison, and the retry.
//   node src/revocations.selftest.mjs
//
// These are the only parts of the verifier that cross a page boundary or depend on
// a status code, and neither is reachable from the pure-function selftests — so
// fetch is stubbed here and every request the code makes is recorded and asserted.
// Real network is never touched.

import { fetchEntries } from "./checks/leaves.mjs";
import { checkServedCounts, foldedTargets } from "./checks/counters.mjs";
import { compareRevocations } from "./checks/semantics.mjs";
import { createHash } from "node:crypto";
import { emptyLog, getJson, listRepoDir, RETRY_MAX } from "./http.mjs";
import { checks } from "./outcomes.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

const API = "https://api.example.test";
const REPO = "https://raw.example.test/main";
const realFetch = globalThis.fetch;
const seen = [];

// Install a stub answering from `handler(url, callNumber)` — {body} is sent as
// JSON, {text} verbatim, {status, headers} override the rest — and record every
// request it receives. Returns the recorded list.
function stubFetch(handler) {
  seen.length = 0;
  globalThis.fetch = async (url) => {
    seen.push(String(url).replace(API, "").replace(REPO, ""));
    const r = handler(new URL(url), seen.length);
    const body = r.text !== undefined ? r.text : r.body === undefined ? "" : JSON.stringify(r.body);
    return new Response(body, {
      status: r.status ?? 200,
      headers: { "content-type": "application/json", ...(r.headers ?? {}) },
    });
  };
  return seen;
}

const revoke = (seq) => ({ seq: String(seq), ts: 1, revoke_seq: "1", reason_code: "erasure_self", evidence_hash: null, target: { site: "github", target_id: "gh:o/r" } });

// --- 1. the published tombstone file against the leaves ----------------------
{
  const op4 = ["5", "9"];
  const file = { tree_size: "1000000", revocations: [revoke(5), revoke(9)] };
  check(compareRevocations(op4, file, 1_000_000).agree, "a file that lists exactly the op=4 leaves agrees");
  check(!compareRevocations(["5"], file, 1_000_000).agree, "a file listing a tombstone the log does not carry disagrees");
  check(!compareRevocations(op4, { revocations: [revoke(5)] }, 1_000_000).agree, "a file hiding a tombstone the log carries disagrees");
}

// --- 2. the file is clamped to the audited checkpoint ------------------------
// It is written over the live log, so a revocation appended mid-run would otherwise
// read as a set mismatch against leaves the checkpoint covers - a FAIL on an honest
// log.
{
  const file = { tree_size: "12", revocations: [revoke(5), revoke(11)] };
  const { listed, agree } = compareRevocations(["5"], file, 9);
  check(listed.join(",") === "5", `a tombstone past the audited tree_size is dropped (kept ${listed.join(",")})`);
  check(agree, "and what is left still has to match the leaves");
}

// --- 5. retry ----------------------------------------------------------------
// A cold audit of a large log is metered per IP, so a single 429 must not end the
// run. Retry-After is used verbatim (seconds), hence the 1s values below.
{
  const calls = stubFetch((_u, n) => (n <= 2 ? { status: 429, headers: { "retry-after": "1" } } : { body: { ok: true } }));
  const started = Date.now();
  const body = await getJson(`${API}/log/checkpoint`);
  check(body.ok === true && calls.length === 3, `429 is retried until it succeeds (${calls.length} calls)`);
  check(Date.now() - started >= 2000, "Retry-After is honoured rather than hammered");
}

{
  const calls = stubFetch(() => ({ status: 429, headers: { "retry-after": "1" } }));
  let threw = false;
  try {
    await getJson(`${API}/log/checkpoint`);
  } catch {
    threw = true;
  }
  check(threw && calls.length === RETRY_MAX + 1, `retries are bounded: ${RETRY_MAX} attempts then a throw (${calls.length} calls)`);
}

{
  const calls = stubFetch(() => ({ status: 400, body: { error: "bad_range" } }));
  let threw = false;
  try {
    await getJson(`${API}/log/revocations/range?from=5&to=1`);
  } catch {
    threw = true;
  }
  check(threw && calls.length === 1, `a 4xx that is not 429 fails immediately (${calls.length} call)`);
}

// --- 6. chunk-sourced leaves: the digest is what makes the body's host irrelevant ---
// A chunk fetched from anywhere is admitted only if its bytes hash to what the
// manifest committed to in the repository. That is the whole trust argument for
// serving the bodies off object storage, so it gets a test on both sides.
{
  const GH_REPO = "https://raw.githubusercontent.com/khasky/log/main";
  const bodyText = [1, 2, 3].map((n) => JSON.stringify({ seq: String(n), leaf_hash: "aa" })).join("\n");
  const digest = createHash("sha256").update(bodyText, "utf8").digest("hex");
  const manifest = (sha) => JSON.stringify({ from: 1, to: 3, count: 3, bytes: bodyText.length, sha256: sha });
  const serve = (sha, base) => (u) => {
    if (u.pathname.endsWith("/entries/mirrors.json")) return { body: { base } };
    if (u.pathname.endsWith("/entries/manifest/000000000001.ndjson")) return { text: manifest(sha) };
    if (u.pathname.endsWith("/entries/000000000001-000000000003.ndjson")) return { text: bodyText };
    return { status: 404 };
  };

  stubFetch(serve(digest, "https://log.example/"));
  const rows = await fetchEntries(GH_REPO, 3);
  check(rows.length === 3 && rows[2].seq === "3", `the chunk the manifest names is read (got ${rows.length} of 3)`);

  const hosts = stubFetch(serve(digest, "https://log.example/"));
  await fetchEntries(GH_REPO, 3);
  check(
    hosts.some((c) => c.startsWith("https://log.example/entries/")),
    `the body comes from the host mirrors.json names (${hosts.filter((c) => c.includes("/entries/")).join(" ")})`,
  );

  const overridden = stubFetch(serve(digest, "https://log.example/"));
  await fetchEntries(GH_REPO, 3, "https://mirror.example");
  check(
    overridden.some((c) => c.startsWith("https://mirror.example/entries/")),
    "--entries-base overrides the host mirrors.json names",
  );

  // The manifest is read by derived path and chained by its own last line, so nothing
  // here asks the GitHub contents API - whose 60-an-hour unauthenticated limit a
  // shared CI address reaches routinely.
  const apiCalls = stubFetch(serve(digest, "https://log.example/"));
  await fetchEntries(GH_REPO, 3);
  check(!apiCalls.some((c) => c.includes("api.github.com")), `reading the leaves asks api.github.com for nothing (${apiCalls.filter((c) => c.includes("api.github.com")).join(" ") || "none"})`);

  stubFetch(serve("0".repeat(64), "https://log.example/"));
  let digestThrew = "";
  try {
    await fetchEntries(GH_REPO, 3);
  } catch (e) {
    digestThrew = e.message;
  }
  check(digestThrew.includes("sha256") && digestThrew.includes("000000000001-000000000003"), `a body that does not match its manifest digest is refused (${digestThrew.slice(0, 60)})`);

  // The chain walks file to file by the `to` of the last line. A file that does not
  // advance it would otherwise loop forever.
  stubFetch((u) => {
    if (u.pathname.endsWith("/entries/mirrors.json")) return { body: { base: "https://log.example/" } };
    if (u.pathname.includes("/entries/manifest/")) return { text: JSON.stringify({ from: 1, to: 0, count: 0, bytes: 0, sha256: digest }) };
    return { status: 404 };
  });
  let chainThrew = "";
  try {
    await fetchEntries(GH_REPO, 3);
  } catch (e) {
    chainThrew = e.message;
  }
  check(chainThrew.includes("does not advance"), `a manifest file that does not advance the chain is refused (${chainThrew.slice(0, 60) || "no error"})`);
}

// --- 7. an empty log is a state, not a failure ------------------------------
// A never-signed log publishes no checkpoints/latest.json. Reading that as a crash
// published "Independent verification: FAIL" for an environment that had simply not
// started yet.
{
  stubFetch(() => ({ status: 404, body: { error: "not found" } }));
  check(await emptyLog(REPO), "a missing checkpoints/latest.json reads as an empty log");

  stubFetch(() => ({ body: { tree_size: 5, root_hash: "aa", ts: 1, signature: "bb" } }));
  check(!(await emptyLog(REPO)), "a signing log is not empty");

  stubFetch(() => ({ status: 500, body: {} }));
  check(!(await emptyLog(REPO)), "a transport failure is not an empty log either");
}

// --- 6. a directory past the Contents API's 1000-file cap falls back to Git Trees ---
// Without the fallback the listing silently truncates at 1000 and the archive/rekor
// completeness checks verify a subset while looking exhaustive.
{
  const GH_REPO = "https://raw.githubusercontent.com/khasky/emojery-log/main";
  const capped = Array.from({ length: 1000 }, (_, i) => ({ name: `${i}.json` }));
  const fullTree = Array.from({ length: 1500 }, (_, i) => ({ path: `${i}.json`, type: "blob" }));
  stubFetch((u) => {
    if (u.hostname !== "api.github.com") return { status: 404 };
    if (u.pathname.endsWith("/contents/rekor")) return { body: capped }; // hits the 1000 cap
    if (u.pathname.endsWith("/git/trees/main")) return { body: { tree: [{ path: "rekor", type: "tree", sha: "deadbeef" }] } };
    if (u.pathname.endsWith("/git/trees/deadbeef")) return { body: { tree: fullTree, truncated: false } };
    return { status: 404 };
  });
  const listed = await listRepoDir(GH_REPO, "rekor");
  check((listed?.names?.length ?? 0) === 1500, `Contents 1000-cap falls back to Git Trees for the whole dir (got ${listed?.names?.length})`);
}

globalThis.fetch = realFetch;
// --- 8. the fold against the served count ------------------------------------
// Everything else in this tool re-derives the counters and stops; this is the one
// check that holds the log against the number a reader is shown.
{
  const vote = (seq, target, reaction) => ({ seq: String(seq), op: 1, site: "github", target_id: target, reaction });
  const entries = [vote(1, "o/big", "🔥"), vote(2, "o/big", "🔥"), vote(3, "o/big", "❤️"), vote(4, "o/small", "🔥")];
  const ranked = foldedTargets(entries);
  check(ranked[0].targetId === "o/big" && ranked[0].total === 3, `the fold totals a target across its reactions, largest first (${ranked.map((t) => `${t.targetId}=${t.total}`).join(" ")})`);

  // A fail is sticky by design (outcomes.mjs), so each case starts from no outcome.
  const fresh = () => {
    delete checks.served_counts;
  };
  const serve = (total) => stubFetch((u) => ({ body: { schemaVersion: 1, label: "reactions", message: "🔥 3", color: "x", cacheSeconds: 1, total: u.pathname.includes("big") ? total : 1 } }));

  fresh();
  const urls = serve(3);
  await checkServedCounts(entries, { base: "https://api.example.test", sample: 2 });
  check(checks.served_counts === "pass", `an honest badge agrees with the fold (${checks.served_counts})`);
  check(
    urls.some((c) => c.includes("/badge/github/o/big.json")),
    `the served count is read off the public badge (${urls.join(" ")})`,
  );

  // A count the log cannot account for is REPORTED, not failed: the fold stops at the
  // audited checkpoint while the served number is live, so on a busy log the two
  // legitimately differ by whatever was cast since.
  fresh();
  serve(99);
  await checkServedCounts(entries, { base: "https://api.example.test", sample: 2 });
  check(checks.served_counts === "note", `a badge serving more than the log folds to is noted, not failed (${checks.served_counts})`);

  // And a build that publishes no exact total is not silently a match.
  fresh();
  stubFetch(() => ({ body: { schemaVersion: 1, label: "reactions", message: "🔥 3", color: "x", cacheSeconds: 1 } }));
  await checkServedCounts(entries, { base: "https://api.example.test", sample: 1 });
  check(checks.served_counts === "note", `a badge with no exact total is not counted as a match (${checks.served_counts})`);

  fresh();
  await checkServedCounts(entries, { base: "", sample: 2 });
  check(checks.served_counts === "skip", `no counts base turns the check into a skip (${checks.served_counts})`);
}


console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exitCode = failed ? 1 : 0;
