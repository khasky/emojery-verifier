// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the verifier's HTTP layer: revocation paging, the entries-source
// cross-check, and the transient-failure retry.
//   node src/revocations.selftest.mjs
//
// These are the only parts of the verifier that cross a page boundary or depend on
// a status code, and neither is reachable from the pure-function selftests — so
// fetch is stubbed here and every request the code makes is recorded and asserted.
// Real network is never touched.

import { crossCheckEntriesSource, emptyLog, fetchEntries, fetchRevocations, getJson, listRepoDir, RETRY_MAX } from "./verify.mjs";

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

// --- 1. bare feed that does not truncate IS the whole set --------------------
// The point of the shortcut: a million-leaf log must not cost a thousand requests
// to list a handful of tombstones.
{
  const calls = stubFetch((u) => {
    if (u.pathname === "/log/revocations" && u.search === "") {
      return { body: { tree_size: "1000000", revocations: [revoke(5), revoke(9)], has_more: false, next_from: null } };
    }
    return { status: 500 };
  });
  const revs = await fetchRevocations(API, 1_000_000);
  check(calls.length === 1, `complete bare feed costs ONE request over a 1M-leaf log (made ${calls.length})`);
  check(revs.map((r) => r.seq).join(",") === "5,9", `bare feed returns every tombstone (got ${revs.map((r) => r.seq).join(",")})`);
}

// --- 2. the bare feed is clamped to the audited checkpoint -------------------
// It reads the live log, so a revocation appended mid-run would otherwise read as
// a set mismatch against leaves the checkpoint covers — a FAIL on an honest log.
{
  stubFetch(() => ({ body: { tree_size: "12", revocations: [revoke(5), revoke(11)], has_more: false, next_from: null } }));
  const revs = await fetchRevocations(API, 9);
  check(revs.map((r) => r.seq).join(",") === "5", `a tombstone past the audited tree_size is dropped (kept ${revs.map((r) => r.seq).join(",")})`);
}

// --- 3. a truncated bare feed falls back to the full range walk --------------
{
  // Routed on the PATH, not just on the query: the bare feed and the range walk are
  // two endpoints, and a walk that asked the wrong one would otherwise still pass
  // here while 404ing against a real deployment.
  const calls = stubFetch((u) => {
    if (u.pathname === "/log/revocations") return { body: { tree_size: "2500", revocations: [revoke(2400)], has_more: true, next_from: null } };
    if (u.pathname !== "/log/revocations/range") return { status: 404, body: { error: "not found" } };
    const from = Number(u.searchParams.get("from"));
    return { body: { tree_size: "2500", revocations: [revoke(from)], has_more: false, next_from: null } };
  });
  const revs = await fetchRevocations(API, 2500);
  const ranges = calls.filter((c) => c.includes("from="));
  check(
    ranges.every((c) => c.startsWith("/log/revocations/range?")),
    `the range walk asks /log/revocations/range (${[...new Set(ranges.map((c) => c.split("?")[0]))].join(", ")})`,
  );
  check(ranges.length === 3, `has_more walks the whole range: ceil(2500/1000) = 3 pages (made ${ranges.length})`);
  check(ranges[0].endsWith("from=1&to=1000") && ranges[2].endsWith("from=2001&to=2500"), `range pages are 1000 wide and clamped to tree_size (${ranges.join(" ")})`);
  check(revs.map((r) => r.seq).join(",") === "1,1001,2001", `the walk keeps every page's rows (got ${revs.map((r) => r.seq).join(",")})`);
}

// --- 4. entries-source cross-check ------------------------------------------
{
  const mine = [
    { seq: "1", leaf_hash: "aa" },
    { seq: "2", leaf_hash: "bb" },
  ];
  stubFetch(() => ({ body: { entries: [{ seq: "1", leaf_hash: "aa" }, { seq: "2", leaf_hash: "bb" }] } }));
  check((await crossCheckEntriesSource(API, mine, 2)).agree === true, "cross-check agrees when the API page matches the shards");

  stubFetch(() => ({ body: { entries: [{ seq: "1", leaf_hash: "aa" }, { seq: "2", leaf_hash: "ff" }] } }));
  check((await crossCheckEntriesSource(API, mine, 2)).agree === false, "cross-check catches a leaf_hash the API serves differently");

  stubFetch(() => ({ body: { entries: [{ seq: "1", leaf_hash: "aa" }] } }));
  check((await crossCheckEntriesSource(API, mine, 2)).agree === false, "cross-check catches a short API page");
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

// --- 6. shard-sourced leaves, tail filled from the API ----------------------
// The public shards can trail the live checkpoint by a batch of leaves.
// Without the fill, --entries repo cannot reproduce the
// checkpoint root at all and every scheduled run in that mode reads as tampering.
{
  const shard = (n) => Array.from({ length: n }, (_, i) => JSON.stringify({ seq: String(i + 1), leaf_hash: "aa" })).join("\n");
  const handler = (u) => {
    if (u.pathname.includes("/entries/")) return { text: shard(1330) };
    const from = Number(u.searchParams.get("from"));
    const to = Number(u.searchParams.get("to"));
    return { body: { entries: Array.from({ length: to - from + 1 }, (_, i) => ({ seq: String(from + i), leaf_hash: "bb" })) } };
  };

  const calls = stubFetch(handler);
  const entries = await fetchEntries(API, REPO, "repo", 1340, 10_000);
  const pages = calls.filter((c) => c.includes("from="));
  check(entries.length === 1340, `shard tail is filled up to the checkpoint (got ${entries.length} of 1340)`);
  check(entries[entries.length - 1].seq === "1340", `the filled tail ends at the checkpoint's last leaf (${entries[entries.length - 1].seq})`);
  check(pages.length === 1 && pages[0].endsWith("from=1331&to=1340"), `only the missing tail is refetched (${pages.join(" ") || "none"})`);

  const offline = stubFetch(handler);
  const shardsOnly = await fetchEntries(undefined, REPO, "repo", 1340, 10_000);
  check(shardsOnly.length === 1330 && !offline.some((c) => c.includes("from=")), "a fully offline audit stays on the shards and contacts no API");

  // No shard at all: the publisher batches appends, so a young log - a freshly
  // reset staging one especially - carries a signed checkpoint and an empty
  // entries/ directory. A 404 there must read as "not mirrored yet" and fall
  // through to the same tail fill, not as a broken mirror.
  stubFetch((u) => (u.pathname.includes("/entries/") ? { status: 404 } : handler(u)));
  const unmirrored = await fetchEntries(API, REPO, "repo", 482, 10_000);
  check(unmirrored.length === 482, `an unpublished shard falls back to the API for every leaf (got ${unmirrored.length} of 482)`);

  // Any other transport failure still fails the run: a 500 is the mirror being
  // broken, and swallowing it would audit a log nobody can independently read.
  stubFetch((u) => (u.pathname.includes("/entries/") ? { status: 500 } : handler(u)));
  let shardThrew = false;
  try {
    await fetchEntries(API, REPO, "repo", 482, 10_000);
  } catch {
    shardThrew = true;
  }
  check(shardThrew, "an unreadable shard (500) still fails the run");
}

// --- 7. an empty log is a state, not a failure ------------------------------
// A never-signed log answers 404 no_checkpoint. Reading that as a crash published
// "Independent verification: FAIL" for an environment that had simply not started
// yet - but the check has to stay narrow, or a dropped route reads as "empty".
{
  stubFetch(() => ({ status: 404, body: { error: "no_checkpoint" } }));
  check(await emptyLog(API), "404 no_checkpoint reads as an empty log");

  stubFetch(() => ({ status: 404, body: { error: "not found" } }));
  check(!(await emptyLog(API)), "a plain 404 is NOT an empty log");

  stubFetch(() => ({ body: { tree_size: 5, root_hash: "aa", ts: 1, signature: "bb" } }));
  check(!(await emptyLog(API)), "a signing log is not empty");
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
console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exitCode = failed ? 1 : 0;
