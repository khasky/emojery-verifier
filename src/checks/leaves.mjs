// SPDX-License-Identifier: GPL-3.0-or-later
// The raw leaves: fetched from the API pages or the log repository's shards, rehashed,
// folded into the Merkle root and replayed along the published hash chain.

import { getBytes, getJson, getText, listRepoDir } from "../http.mjs";
import { check, record, skipCheck } from "../outcomes.mjs";
import { detail, details, phase } from "../report.mjs";
import { bytesToHex, checkHashChain, leafHashFromEntry, merkleRootFromLeaves, sha256 } from "../transparency.mjs";

export const ENTRIES_PAGE = 1000;
// The published entries/ shards are this many leaves wide; their file names derive from it.
const SHARD_SIZE = 10_000;

function padSeq(n) {
  return String(n).padStart(12, "0");
}

// Where the shard bodies live when the manifest does not say and --entries-base was
// not passed. Any copy will do: the manifest's sha256 decides whether the bytes are
// the published ones, not the host they came from.
export async function manifestBase(repo, override) {
  if (override) return override.endsWith("/") ? override : `${override}/`;
  let mirrors;
  try {
    mirrors = await getJson(`${repo}/entries/mirrors.json`);
  } catch {
    throw new Error(`${repo} publishes no entries/mirrors.json - pass --entries-base <url>, or audit this log with --entries repo`);
  }
  const base = mirrors?.base;
  if (typeof base !== "string" || !base) throw new Error(`${repo}/entries/mirrors.json declares no "base" - pass --entries-base <url>`);
  return base.endsWith("/") ? base : `${base}/`;
}

// The manifest: one line per shard, {from, to, count, bytes, sha256}, in files of
// entries/manifest/ named by the leaf range they cover. The shard's own name derives
// from its range, so no line carries a URL and a mirror needs no manifest of its own.
async function readManifest(repo) {
  const listed = await listRepoDir(repo, "entries/manifest");
  if (listed === null) throw new Error("--entries manifest needs a raw.githubusercontent.com --repo base (the manifest is listed through the GitHub API)");
  if (listed.rateLimited) throw new Error("GitHub rate-limited the manifest listing; set GITHUB_TOKEN to lift the quota");
  if (listed.missing) throw new Error("this log publishes no entries/manifest - audit it with --entries repo, or --entries none for the history alone");
  const files = (listed.names ?? []).filter((n) => n.endsWith(".ndjson")).sort();
  const shards = [];
  for (const name of files) {
    const text = await getText(`${repo}/entries/manifest/${name}`);
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      shards.push(JSON.parse(t));
    }
  }
  shards.sort((a, b) => Number(a.from) - Number(b.from));
  return shards;
}

// Shards are published in batches, so a mirrored source routinely stops short of the
// signed tip. With --api the gap is fetched; without it the run says so and the
// caller steps back to the newest checkpoint the leaves in hand fully cover.
async function fillTail(rows, api, treeSize, fetching, source) {
  const covered = rows.length ? Number(rows[rows.length - 1].seq) : 0;
  if (covered < treeSize) {
    if (!api) {
      detail(`${source} cover ${covered} of ${treeSize} leaves - the newest tail is not mirrored yet, and an offline audit cannot fill it`);
      fetching.end(rows.length, treeSize);
      return rows;
    }
    detail(`${source} cover ${covered} of ${treeSize} leaves - filling the tail from the API`);
    for (let from = covered + 1; from <= treeSize; from += ENTRIES_PAGE) {
      const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
      rows.push(...((await getJson(`${api}/log/entries?from=${from}&to=${to}`)).entries ?? []));
      fetching.tick(rows.length, treeSize);
    }
  }
  fetching.end(rows.length, treeSize);
  return rows;
}

// /log/entries-shaped rows [1..treeSize] from the API (paged), the log repo's
// entries/ shards, or the manifest plus the bodies it names. The whole log is held in
// memory: the fold, the invariants and the archive replay each need the full set.
// Around a million leaves that is about a gigabyte of heap; past a few million, fold
// and verify from a streamed source instead.
export async function fetchEntries(api, repo, treeSize, { mode, base } = {}) {
  const entriesMode = mode ?? "api";
  const rows = [];
  const fetching = phase(entriesMode === "api" ? "fetching leaves" : "reading entries shards");
  if (entriesMode === "manifest") {
    const shards = await readManifest(repo);
    const from = await manifestBase(repo, base);
    for (const shard of shards) {
      if (Number(shard.from) > treeSize) break;
      const name = `entries/${padSeq(Number(shard.from))}-${padSeq(Number(shard.to))}.ndjson`;
      const body = await getBytes(`${from}${name}`);
      // The digest is what makes the body's origin irrelevant - and it fails a
      // truncated download here, rather than as an unexplained root mismatch later.
      const got = bytesToHex(await sha256(body));
      if (got !== shard.sha256) throw new Error(`${name}: sha256 ${got} != ${shard.sha256} declared in the manifest`);
      for (const line of new TextDecoder().decode(body).split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const e = JSON.parse(t);
        if (Number(e.seq) <= treeSize) rows.push(e);
      }
      fetching.tick(rows.length, treeSize);
    }
    return fillTail(rows, api, treeSize, fetching, "the manifest");
  }
  if (entriesMode === "repo") {
    for (let start = 1; start <= treeSize; start += SHARD_SIZE) {
      const path = `entries/${padSeq(start)}-${padSeq(start + SHARD_SIZE - 1)}.ndjson`;
      let text;
      try {
        text = await getText(`${repo}/${path}`);
      } catch (e) {
        // A shard that does not exist yet is the publisher's batching window (a young
        // log has a signed checkpoint and no shard); the tail fills from the API below.
        // Any other transport failure fails the run.
        if (e.status === 404) break;
        throw new Error(`entries shard ${path} could not be read (${e.message})`);
      }
      for (const line of text.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const e = JSON.parse(t);
        if (Number(e.seq) <= treeSize) rows.push(e);
      }
      fetching.tick(rows.length, treeSize);
    }
    return fillTail(rows, api, treeSize, fetching, "entries/ shards");
  }
  for (let from = 1; from <= treeSize; from += ENTRIES_PAGE) {
    const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
    const page = await getJson(`${api}/log/entries?from=${from}&to=${to}`);
    rows.push(...page.entries);
    fetching.tick(rows.length, treeSize);
  }
  fetching.end(rows.length, treeSize);
  return rows;
}

export async function rehashLeaves(entries) {
  const leaves = [];
  let mismatches = 0;
  const rehash = phase("recomputing leaf hashes");
  for (const e of entries) {
    const leaf = await leafHashFromEntry(e);
    if (bytesToHex(leaf) !== e.leaf_hash) mismatches++;
    leaves.push(leaf);
    rehash.tick(leaves.length, entries.length);
  }
  rehash.end(leaves.length, entries.length);
  check(mismatches === 0, `every recomputed leaf_hash matches the served leaf (${mismatches} mismatch)`, "leaf_hashes");
  return leaves;
}

// `uncovered` means a mirror whose shards reach no published checkpoint: there is
// no signed root to compare the leaves with, which is a gap in the mirror, not
// evidence against the log.
export async function checkMerkleRoot(leaves, cp, treeSize, entriesMode, uncovered) {
  if (uncovered) {
    skipCheck(`Merkle root (the ${leaves.length} mirrored leaves reach no published checkpoint; pass --api, or audit a mirror that carries one)`, "merkle_root");
    return;
  }
  check(leaves.length === treeSize, `fetched all ${treeSize} leaves (got ${leaves.length}, source: ${entriesMode})`, "merkle_root");
  const root = await merkleRootFromLeaves(leaves);
  check(bytesToHex(root) === cp.root_hash, "recomputed Merkle root == checkpoint root_hash", "merkle_root");
}

// The Merkle root pins which leaves the tree holds; the chain pins their order.
export async function checkHashChainReplay(entries, leaves) {
  const breaks = await checkHashChain(entries, leaves);
  details(breaks, 5);
  check(breaks.length === 0, `hash chain replays from genesis (${entries.length} leaves, ${breaks.length} break(s))`, "hash_chain");
}

// With --entries repo the API's own /log/entries is never read, so one page (the
// first, immutable and cached) is compared against the shard-derived leaves.
export async function crossCheckEntriesSource(api, entries, treeSize) {
  const to = Math.min(ENTRIES_PAGE, treeSize);
  const served = (await getJson(`${api}/log/entries?from=1&to=${to}`)).entries ?? [];
  const mine = entries.slice(0, to);
  const agree = served.length === mine.length && mine.every((e, i) => String(served[i].seq) === String(e.seq) && served[i].leaf_hash === e.leaf_hash);
  return { agree, servedCount: served.length, expected: mine.length };
}

export async function checkEntriesSource(api, entriesMode, entries, treeSize) {
  if (!api || entriesMode !== "repo") {
    record("entries_source", "skip");
    return;
  }
  try {
    const x = await crossCheckEntriesSource(api, entries, treeSize);
    check(x.agree, `/log/entries agrees with the repo shards over the first ${x.expected} leaves (served ${x.servedCount})`, "entries_source");
  } catch (e) {
    check(false, `/log/entries cross-check: ${e.message}`, "entries_source");
  }
}
