// SPDX-License-Identifier: GPL-3.0-or-later
// The raw leaves: fetched from the API pages or the log repository's shards, rehashed,
// folded into the Merkle root and replayed along the published hash chain.

import { getBytes, getJson, getText } from "../http.mjs";
import { check, record, skipCheck } from "../outcomes.mjs";
import { detail, details, phase } from "../report.mjs";
import { bytesToHex, checkHashChain, leafHashFromEntry, merkleRootFromLeaves, sha256 } from "../transparency.mjs";

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

// Named for the first leaf it covers. A chunk holds whatever one publish had, so a
// file spans no predictable range - but it needs no directory listing either: the
// first file is leaf 1, and the next one starts at the `to` of its last line.
function manifestPath(firstLeaf) {
  return `entries/manifest/${padSeq(firstLeaf)}.ndjson`;
}

// The manifest: one line per chunk, {from, to, count, bytes, sha256}, chained across
// files as above. Read by DERIVED path, never by listing the directory: a listing
// means the GitHub contents API, rate-limited to 60 an hour per IP unauthenticated -
// which a shared CI address reaches routinely. A mode whose whole point is auditing
// from a mirror cannot depend on api.github.com answering.
async function readManifest(repo) {
  const shards = [];
  for (let firstLeaf = 1; ; ) {
    let text;
    try {
      text = await getText(`${repo}/${manifestPath(firstLeaf)}`);
    } catch (e) {
      // The chain ends at the first file that does not exist.
      if (e.status === 404) break;
      throw new Error(`${manifestPath(firstLeaf)} could not be read (${e.message})`);
    }
    const lines = [];
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      lines.push(JSON.parse(t));
    }
    const last = lines[lines.length - 1];
    if (!last) break;
    shards.push(...lines);
    const next = Number(last.to) + 1;
    // The chain only ever moves forward. A file whose last line does not advance
    // past its own first leaf is malformed, and following it would loop.
    if (!(next > firstLeaf)) throw new Error(`${manifestPath(firstLeaf)} ends at leaf ${last.to}, which does not advance the manifest chain`);
    firstLeaf = next;
  }
  return shards;
}

// The highest seq the published shards reach. Bodies are batched, so the mirror
// routinely stops short of the signed tip, and a leaf past this is not missing -
// it is not published yet. Null when this log publishes no manifest at all.
export async function manifestCoverage(repo) {
  if (!repo) return null;
  try {
    const shards = await readManifest(repo);
    return shards.reduce((high, s) => Math.max(high, Number(s.to)), 0);
  } catch {
    return null;
  }
}

// The leaves [1..treeSize]: every chunk the manifest names, fetched from the entries
// base and admitted only if its bytes hash to the digest the repository committed to.
// The whole log is held in memory: the fold, the invariants and the archive replay
// each need the full set. Around a million leaves that is about a gigabyte of heap;
// past a few million, fold and verify from a streamed source instead.
export async function fetchEntries(repo, treeSize, base) {
  const rows = [];
  const fetching = phase("reading entries chunks");
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
export async function checkMerkleRoot(leaves, cp, treeSize, uncovered) {
  if (uncovered) {
    skipCheck(`Merkle root (the ${leaves.length} published leaves reach no published checkpoint - the mirror is behind its own checkpoints)`, "merkle_root");
    return;
  }
  check(leaves.length === treeSize, `fetched all ${treeSize} leaves (got ${leaves.length})`, "merkle_root");
  const root = await merkleRootFromLeaves(leaves);
  check(bytesToHex(root) === cp.root_hash, "recomputed Merkle root == checkpoint root_hash", "merkle_root");
}

// The Merkle root pins which leaves the tree holds; the chain pins their order.
export async function checkHashChainReplay(entries, leaves) {
  const breaks = await checkHashChain(entries, leaves);
  details(breaks, 5);
  check(breaks.length === 0, `hash chain replays from genesis (${entries.length} leaves, ${breaks.length} break(s))`, "hash_chain");
}
