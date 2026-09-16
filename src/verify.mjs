#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone transparency-log verifier.
//
//   node src/verify.mjs --api https://api.emojery.app \
//     [--repo https://raw.githubusercontent.com/khasky/emojery-log/main] \
//     [--entries api|repo] [--shard-size 10000] \
//     [--pubkey <base64 raw Ed25519>] \
//     [--wipe-grace-hours 48] [--max-checkpoint-age-hours 168] [--stats] [--counters] \
//     [--no-rekor] [--ots] [--btc-api <Esplora base>] [--ots-external <bin>] [--json]
//     [--allow-unsigned-votes] [--no-proofs] [--blind-pubkey <SPKI b64>]
//     [--enroll-vk-hash <sha256 hex>] [--salt-commitment <sha256 hex>]
//     [--issuers provider=iss,...] [--audiences client_id,...]
//     [--no-color] [--ascii]
//
// --entries repo reads the raw leaves from the log repo's public
// entries/<start>-<end>.ndjson shards instead of the API; combined with --repo
// (and no --api) that is a FULL OFFLINE audit of a clone/mirror — the operator's
// API is not contacted at all (the /log/revocations endpoint comparison is then
// skipped; the in-log revoke invariants still run). It is also the practical mode
// for a large log: 10k leaves per shard file against 1000 per API page, and the
// shards are not charged against the API's per-IP /log/* rate limit.
//
// Shard appends are batched, so the shards routinely trail the live checkpoint by a
// few hundred leaves. With --api the missing tail is fetched in one page. Offline
// there is no tail to fetch, so the run STEPS BACK to the newest published checkpoint
// the shards do cover and audits that one (checkpointForShardCoverage) — auditing a
// checkpoint the shards cannot reproduce would FAIL an honest log, which is the one
// verdict this tool must never invent.
//
// --json prints a single machine-readable summary on stdout (result + per-check
// pass/fail/skip + tree_size) instead of the human report — used by the status-page
// ingest job. Human/info lines then go to stderr. Exit code is unchanged.
//
// Checks, in order:
//   1. signed checkpoint (STH) Ed25519 signature with the pinned/--pubkey key
//   1b. checkpoint freshness (--max-checkpoint-age-hours, default 168; 0 disables)
//   2. (if --repo AND --api) the signed root matches the GitHub anchor (split-view
//      check). Offline the anchor IS the checkpoint under test, so it is skipped
//      rather than compared against itself.
//   3. every leaf refetched, leaf_hash recomputed, Merkle root == checkpoint root
//   3a. the published hash chain replays: entry_hash(seq) == SHA256(0x00 ||
//       entry_hash(seq-1) || leaf_hash(seq)), from GENESIS_PREV — the root pins the
//       set of leaves, the chain pins their order
//   3b. (if --repo) checkpoint-ARCHIVE replay: every STH ever published to
//       checkpoints/*.ndjson has a valid signature, no two published STHs claim
//       the same tree_size with different roots (equivocation-in-archive), ts is
//       monotone in tree_size, and each archived root equals the root recomputed
//       from today's leaves at that tree_size — i.e. the whole published history
//       lies on ONE append-only line (an internally-consistent rewrite fails here)
//   3c. (default when --repo is set; --no-rekor to skip) the newest
//       rekor/<tree_size>.json sidecar resolves to a real Sigstore Rekor entry
//       carrying exactly our signed STH bytes, signature, and public key. An
//       unreachable Rekor downgrades to a skip; only disagreeing bytes FAIL.
//   3d. (only with --entries repo + --api) one API page cross-checked against the
//       shard-derived leaves, so an audit that reads the shards still notices a
//       broken /log/entries or a disagreement between the two published sources.
//   4. counters re-derived from the verified leaves (revoke reversal included)
//      and reported — the totals a third party can publish independently
//   5. structural consistency of the log (well-formed entries, no impossible
//      negative counts) + /log/revocations matches the log + account-wipe
//      completeness (a pseudonym partially revoked is flagged; --wipe-grace-hours)
//   5c. identity track (op 5..7 and signed votes): every signed vote names a key an
//       earlier KEY leaf registered and verifies under it (G); every KEY leaf carries a
//       valid blind RSA-PSS signature under the pinned blind key and no epoch registers
//       more keys than it issued (H); every ISSUE cites an earlier ENROLL, at most three
//       per epoch (I); every ENROLL proof verifies under the pinned verification key with
//       public inputs rebuilt from the leaf and the archived provider key (J, via
//       @aztec/bb.js; --no-proofs skips it). An unsigned vote is admitted only under
//       --allow-unsigned-votes (the 1.0.0 compatibility window).
//   6. (if --ots) deep audit: the matured OpenTimestamps proof anchors the signed
//      checkpoint root in a Bitcoin block. Network-bound, so opt-in; needs
//      --repo and an Esplora-compatible block-header source.
//
// --stats additionally prints a per-day aggregate CSV (votes, unique pseudonyms,
// revocations) derived from the entries alone; --counters prints the re-derived
// per-(site, target, reaction) totals themselves, so an auditor publishes the
// numbers rather than quoting ours.
//
// Exit code 0 = PASS, 1 = FAIL. The core checks need only @noble/ed25519;
// --ots is dependency-clean and uses only Node built-ins; the ENROLL proof check
// (5c/J) is the one place @aztec/bb.js is loaded.

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import {
  bytesToHex,
  checkHashChain,
  checkIdentityInvariants,
  checkStructuralInvariants,
  checkWipeCompleteness,
  dailyAggregates,
  foldCounters,
  hexToBytes,
  leafHashFromEntry,
  merkleRootFromLeaves,
  merkleRootsAtSizes,
  sha256,
  splitCounterKey,
  sthBytes,
  verifyIdentitySignatures,
  verifySignature,
  verifySth,
} from "./transparency.mjs";
import { DEFAULT_ISSUERS, parseIssuersFlag, parseListFlag, verifyEnrollProofs } from "./identity.mjs";
import { runExternalOts, verifyDetachedOtsProof } from "./ots-bitcoin.mjs";
import { beginAudit, detail, ELL, flush, mark, out, phase, raw, section, verdict } from "./report.mjs";

// The published Emojery log signing key (base64 raw Ed25519). Pinned so --pubkey is optional.
const PINNED_PUBKEY_B64 = "XeLiQ5CMhsjLmnQbIWSwWHNjcJg01Zs0veQDiwluT6c=";

// Identity-track pins (check 5c). Each is published by the operator once the OpenID
// sign-in ships; until then it is empty and the check that needs it reports a skip
// naming the pin. A fork verifying another deployment overrides them with the flags.
//   PINNED_BLIND_PUBKEY_SPKI_B64 — the RSA-2048 blind-signing public key (SPKI, base64),
//     also published as keys/blind-rsa-v1.json in the log repo; the H signature check.
//   PINNED_ENROLL_VK_SHA256 — SHA-256 of keys/enroll-v1.vk, the UltraHonk verification
//     key of the ENROLL circuit; the J proof check.
//   PINNED_SALT_COMMITMENT — SHA-256 of the operator's nullifier salt; a public input
//     of every ENROLL proof.
//   PINNED_AUDIENCES — the OAuth client ids the id_tokens were minted for.
const PINNED_BLIND_PUBKEY_SPKI_B64 = "";
const PINNED_ENROLL_VK_SHA256 = "";
const PINNED_SALT_COMMITMENT = "";
const PINNED_AUDIENCES = [];
const PINNED_ISSUERS = DEFAULT_ISSUERS;

// The bb.js version this verifier is pinned to (package.json); keys/enroll-v1.json
// records the bb the operator proved with, and a drift between the two is reported.
const BB_JS_VERSION = createRequire(import.meta.url)("../package.json").dependencies["@aztec/bb.js"];

// The Sigstore Rekor instance the checkpoint's independent witness lives in. PINNED, not
// read from the sidecar under test: a compromised log repo could otherwise point the
// "independent" check at a server it controls that echoes the expected bytes. A fork on a
// different Rekor edits this, like the pubkey.
let rekorEntryId = null;
let btcBlockHeight = null;

const PINNED_REKOR_URL = "https://rekor.sigstore.dev";

const ENTRIES_PAGE = 1000;
// Fixed shard size of the public entries/ shards (documented in the log repo's
// README; file names are derived from it). Overridable via --shard-size just in case.
const DEFAULT_SHARD_SIZE = 10_000;

// Flags that take a value, and the bare switches. Every accepted flag is listed:
// a typo used to be accepted in silence, so `--targett site/id` (or any flag this
// build does not have) quietly ran a SMALLER audit and still printed PASS. An audit
// tool that answers a question it was not asked is worse than one that refuses.
const VALUE_FLAGS = new Set([
  "--api",
  "--repo",
  "--entries",
  "--shard-size",
  "--pubkey",
  "--wipe-grace-hours",
  "--max-checkpoint-age-hours",
  "--btc-api",
  "--ots-external",
  "--blind-pubkey",
  "--enroll-vk-hash",
  "--salt-commitment",
  "--issuers",
  "--audiences",
]);
const BARE_FLAGS = new Set(["--stats", "--counters", "--json", "--rekor", "--no-rekor", "--ots", "--allow-unsigned-votes", "--no-proofs", "--no-color", "--ascii", "--help"]);
const USAGE =
  "usage: node src/verify.mjs --api <url> [--repo <raw base>] [--entries api|repo] [--shard-size <n>] [--pubkey <b64>] [--wipe-grace-hours <n>] [--max-checkpoint-age-hours <n>] [--stats] [--counters] [--no-rekor] [--ots] [--btc-api <url>] [--ots-external <bin>] [--allow-unsigned-votes] [--no-proofs] [--blind-pubkey <spki b64>] [--enroll-vk-hash <hex>] [--salt-commitment <hex>] [--issuers provider=iss,...] [--audiences id,...] [--json] [--no-color] [--ascii]";

function arg(name) {
  const i = process.argv.indexOf(name);
  if (i === -1) return undefined;
  const value = process.argv[i + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

// Reject an unknown flag, and a value flag left without its value — `--pubkey` with
// an empty string used to fall through to the pinned key, so a fork whose LOG_PUBKEY
// variable resolved to nothing verified a DIFFERENT deployment's log against the
// production key and never learned why it failed.
function argvErrors() {
  const errors = [];
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    if (BARE_FLAGS.has(token)) continue;
    if (VALUE_FLAGS.has(token)) {
      const value = args[i + 1];
      // A value never legitimately starts with `-` (URLs, base64 keys, non-negative
      // integers). Rejecting one here catches `--pubkey --json`, where --json would
      // otherwise be swallowed as the value and the flag silently dropped.
      if (!value || value.startsWith("-")) errors.push(`${token} needs a value`);
      else i++; // consume the value
      continue;
    }
    // Anything else is neither a known flag nor a consumed value: a mistyped flag
    // (`--targett`), a single-dash typo (`-ots`), or stray positional junk. Each used
    // to be ignored, running a SMALLER audit in silence and still printing PASS.
    errors.push(token.startsWith("-") ? `unknown flag ${token}` : `unexpected argument ${token}`);
  }
  return errors;
}

// A full audit of a large log is thousands of requests and the API meters /log/*
// per IP — a cold pass is all cache misses — so a bare throw on the first 429
// loses the whole run at whatever page it reached: there is no resume. Retry-After
// is honoured when sent, otherwise exponential backoff. Deliberately NOT used by
// listRepoDir(), where 403/429 means "GitHub is throttling us, skip check 3b"
// rather than "wait and ask again".
const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
export const RETRY_MAX = 4;
const RETRY_AFTER_CAP_S = 60;

export async function getRes(url, attempt = 0) {
  const res = await fetch(url);
  if (res.ok || attempt >= RETRY_MAX || !RETRY_STATUS.has(res.status)) return res;
  const after = Number(res.headers.get("retry-after"));
  const waitMs = Number.isFinite(after) && after > 0 ? Math.min(after, RETRY_AFTER_CAP_S) * 1000 : 2 ** attempt * 1000;
  detail(`${res.status} on ${new URL(url).pathname} — retry ${attempt + 1}/${RETRY_MAX} in ${waitMs / 1000}s`);
  await new Promise((r) => setTimeout(r, waitMs));
  return getRes(url, attempt + 1);
}

export async function getJson(url) {
  const res = await getRes(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

// Whether the API serves a log with no checkpoint at all. Narrow on purpose: only
// a 404 whose body IS the documented `no_checkpoint` error counts, so a 404 from a
// dropped route, a proxy or a typo'd --api still fails the run.
export async function emptyLog(api) {
  const res = await getRes(`${api}/log/checkpoint`);
  if (res.status !== 404) return false;
  const body = await res.json().catch(() => null);
  return body?.error === "no_checkpoint";
}

async function getBytes(url) {
  const res = await getRes(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

async function getText(url) {
  const res = await getRes(url);
  if (!res.ok) {
    // The status rides on the error: fetchEntries has to tell "this shard was
    // never published" (404) from "the mirror is broken" (anything else).
    const err = new Error(`GET ${url} -> ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.text();
}

// --json (see header). report.mjs keeps stdout for the JSON summary alone and prints
// the human lines undecorated on stderr.
const JSON_MODE = process.argv.includes("--json");

const checks = {};
function record(key, status) {
  if (checks[key] === "fail") return; // sticky: once a key fails it stays failed
  if (status === "fail") {
    checks[key] = "fail";
    return;
  }
  if (checks[key] === undefined || checks[key] === "skip") checks[key] = status;
}

let failed = false;
function check(ok, msg, key) {
  mark(ok ? "pass" : "fail", msg);
  if (!ok) failed = true;
  if (key) record(key, ok ? "pass" : "fail");
}

// A check that could not run. Reported as its own outcome, never folded into a pass:
// the closing tally has to say how much of the audit actually executed.
function skipCheck(msg, key) {
  mark("skip", msg);
  if (key) record(key, "skip");
}

// Check 6 (--ots, see header). --ots-external adds an independent official-CLI cross-check.
async function verifyOts(repo, pubkey, btcApi, otsExternal) {
  if (!repo) {
    check(false, "OTS: --ots needs --repo (the .ots proof lives in the log repo)", "ots");
    return;
  }
  let latest;
  try {
    latest = await getJson(`${repo}/ots/latest.json`);
  } catch (e) {
    check(false, `OTS: no matured proof published yet (ots/latest.json: ${e.message})`, "ots");
    return;
  }
  const t = String(latest.tree_size);
  let sidecar;
  try {
    sidecar = await getJson(`${repo}/ots/${t}.json`);
  } catch (e) {
    check(false, `OTS sidecar fetch: ${e.message}`, "ots");
    return;
  }

  // root_hash is repo-controlled and flows into both the Bitcoin check and, with
  // --ots-external, an argv to a spawned process. Validate it is a 64-hex digest BEFORE
  // any of that: a non-hex value is malformed data, and an unvalidated one is a shell
  // injection lever on the external path.
  if (!/^[0-9a-f]{64}$/i.test(String(sidecar.root_hash ?? ""))) {
    check(false, `OTS sidecar root_hash is not a 64-hex digest`, "ots");
    return;
  }

  // 6a. the sidecar is a real signed checkpoint STH (Ed25519) — no library needed.
  const sigOk = await verifySth(pubkey, hexToBytes(sidecar.signature), {
    treeSize: BigInt(sidecar.tree_size),
    rootHash: hexToBytes(sidecar.root_hash),
    ts: sidecar.ts,
  });
  check(sigOk, `OTS sidecar is a signed checkpoint STH (tree_size=${t})`, "ots");
  // A sidecar we cannot verify must not drive the Bitcoin check or, worse, hand its
  // fields to an external process. Stop here.
  if (!sigOk) return;

  // 6b. the .ots proof anchors that exact root in Bitcoin.
  let otsBytes;
  try {
    const res = await getRes(`${repo}/${sidecar.ots_path}`);
    if (!res.ok) throw new Error(`GET ${sidecar.ots_path} -> ${res.status}`);
    otsBytes = new Uint8Array(await res.arrayBuffer());
  } catch (e) {
    check(false, `OTS: fetch proof: ${e.message}`, "ots");
    return;
  }

  try {
    const result = await verifyDetachedOtsProof({
      rootHashHex: sidecar.root_hash,
      otsBytes,
      btcApi,
    });
    btcBlockHeight = result.height;
    check(true, `OTS: signed root anchored in Bitcoin (block ${result.height})`, "ots");
    if (sidecar.btc_block_height != null) {
      // A multi-calendar proof anchors in several blocks; the sidecar records one
      // of them (the worker writes the earliest), so accept any anchored height.
      check(
        result.heights.includes(Number(sidecar.btc_block_height)),
        `OTS sidecar block height is anchored by the proof (${sidecar.btc_block_height})`,
        "ots",
      );
    }
  } catch (e) {
    check(false, `OTS Bitcoin verification: ${e.message}`, "ots");
  }

  if (!otsExternal) return;
  try {
    await runExternalOts({
      command: otsExternal,
      rootHashHex: sidecar.root_hash,
      otsBytes,
    });
    check(true, `OTS external verifier passed (${otsExternal})`, "ots_external");
  } catch (e) {
    check(false, `OTS external verifier: ${e.message}`, "ots_external");
  }
}

// --- checkpoint-archive replay (check 3b) ---------------------------------

// Directory listing needs the GitHub contents API, so the repo slug is derived
// from the raw.githubusercontent.com base; a non-GitHub --repo skips 3b.
function githubSlugFromRawBase(repo) {
  const m = /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/?$/.exec(repo);
  return m ? { owner: m[1], repo: m[2], ref: m[3] } : null;
}

// List file names in a log-repo directory via the GitHub contents API. Returns { names },
// { rateLimited: true } when throttled, { missing: true } for an absent directory, or
// null for a non-GitHub base. GITHUB_TOKEN (optional) lifts the 60/h unauthenticated
// quota; a rate-limited listing is GitHub throttling us, not tamper evidence → skip.
//
// The Contents API caps a directory listing at 1000 entries and does NOT paginate, so a
// dir past that would silently truncate — and the archive/rekor completeness checks would
// then verify a SUBSET while reporting themselves exhaustive. rekor/ (one file per
// checkpoint) reaches 1000 in months of hourly checkpoints, checkpoints/ (daily shards) in
// ~2.7 years. When the cap is hit, re-list via the Git Trees API (up to 100k entries),
// which the flat log dirs fit in for years; a Trees listing that ITSELF truncates is
// surfaced as `truncated` so a caller never mistakes a capped list for the whole one.
export async function listRepoDir(repo, dir) {
  const slug = githubSlugFromRawBase(repo);
  if (!slug) return null;
  const headers = { accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
  const listUrl = `https://api.github.com/repos/${slug.owner}/${slug.repo}/contents/${dir}?ref=${slug.ref}`;
  const res = await fetch(listUrl, { headers });
  if (res.status === 403 || res.status === 429) return { rateLimited: true };
  if (res.status === 404) return { missing: true };
  if (!res.ok) throw new Error(`GET ${listUrl} -> ${res.status}`);
  const listing = await res.json();
  const names = (Array.isArray(listing) ? listing : []).map((f) => f.name).filter((n) => typeof n === "string");
  if (names.length >= 1000) {
    const viaTree = await listRepoDirViaTree(slug, dir, headers);
    if (viaTree) return viaTree;
  }
  return { names };
}

// The Git Trees fallback: root tree → the dir's tree sha → that tree's blobs. The log dirs
// are flat, so a non-recursive listing of the dir tree is the whole directory.
async function listRepoDirViaTree(slug, dir, headers) {
  const base = `https://api.github.com/repos/${slug.owner}/${slug.repo}/git/trees`;
  const rootRes = await fetch(`${base}/${encodeURIComponent(slug.ref)}`, { headers });
  if (!rootRes.ok) return null;
  const root = await rootRes.json();
  const entry = (root.tree ?? []).find((e) => e.path === dir && e.type === "tree");
  if (!entry?.sha) return null;
  const dirRes = await fetch(`${base}/${entry.sha}`, { headers });
  if (!dirRes.ok) return null;
  const tree = await dirRes.json();
  const names = (tree.tree ?? []).filter((e) => e.type === "blob" && typeof e.path === "string").map((e) => e.path);
  if (tree.truncated) {
    // >100k entries / 7 MB: even the Trees API stops short. Say so loudly so the
    // completeness checks below are read as "over what we could list", not "over all".
    detail(`NOTE: ${dir}/ listing truncated by the GitHub Trees API (>100k files) — the archive/rekor completeness check covers the listed subset only`);
    return { names, truncated: true };
  }
  return { names };
}

// Collect every STH ever published to the checkpoints/*.ndjson shards. Only shards
// are merged; checkpoints/latest.json is the live anchor, read separately in check 2.
// Memoized: an offline run reads the archive twice — once to pick the checkpoint the
// shards can reproduce, once to replay it — and the listing is metered by GitHub.
let archiveCache = null;
async function fetchCheckpointArchive(repo) {
  if (archiveCache) return archiveCache;
  archiveCache = await readCheckpointArchive(repo);
  return archiveCache;
}

async function readCheckpointArchive(repo) {
  const listed = await listRepoDir(repo, "checkpoints");
  if (listed === null || listed.rateLimited) return listed;
  const shards = (listed.names ?? []).filter((n) => n.endsWith(".ndjson")).sort();
  const sths = [];
  for (const name of shards) {
    const text = await getText(`${repo}/checkpoints/${name}`);
    for (const line of text.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        sths.push({ shard: name, ...JSON.parse(t) });
      } catch {
        sths.push({ shard: name, parseError: true });
      }
    }
  }
  return { shards, sths };
}

// The newest published checkpoint a shard-sourced offline run can actually
// reproduce: the largest archived tree_size at or below the leaf count the shards
// carry. Pure, so the choice is testable without a network (archive.selftest.mjs).
export function pickCoveredCheckpoint(sths, covered) {
  let best = null;
  for (const s of sths) {
    if (s.parseError) continue;
    const size = Number(s.tree_size);
    if (size > covered) continue;
    if (!best || size > Number(best.tree_size)) best = s;
  }
  return best;
}

// Offline (no --api) the shards cannot be topped up from the API, so the checkpoint
// under test becomes the newest one they cover. Its signature is NOT pre-verified
// here — check 1 verifies whatever this returns, so a tampered archive line still
// fails loudly instead of being silently skipped over.
async function checkpointForShardCoverage(repo, covered) {
  let archive;
  try {
    archive = await fetchCheckpointArchive(repo);
  } catch {
    return null;
  }
  if (!archive || archive.rateLimited || !archive.sths) return null;
  return pickCoveredCheckpoint(archive.sths, covered);
}

// Verify the published checkpoint history lies on one append-only line: signatures,
// per-tree_size uniqueness, ts monotonicity, and every archived root replayed from
// today's leaves. `liveCp` is the repo/API tip; `cp` is the checkpoint under test,
// which an offline run may have stepped back from it. Returns the per-tree_size STH
// map for the Rekor check, or null when the archive could not be read.
async function verifyCheckpointArchive(repo, pubkey, cp, leaves, liveCp) {
  let archive;
  try {
    archive = await fetchCheckpointArchive(repo);
  } catch (e) {
    check(false, `checkpoint archive fetch: ${e.message}`, "archive");
    return null;
  }
  if (archive === null) {
    skipCheck("checkpoint-archive replay (--repo is not a raw.githubusercontent.com base)", "archive");
    return null;
  }
  if (archive.rateLimited) {
    skipCheck("checkpoint-archive replay (GitHub API rate-limited; set GITHUB_TOKEN to lift the quota)", "archive");
    return null;
  }
  const malformed = archive.sths.filter((s) => s.parseError).length;
  check(malformed === 0, `checkpoint archive parses (${archive.sths.length} STH line(s) in ${archive.shards.length} shard(s))`, "archive");

  // Per-tree_size uniqueness: two published STHs disagreeing on the same
  // tree_size is direct, signed equivocation evidence.
  const bySize = new Map();
  let conflicts = 0;
  for (const s of archive.sths) {
    if (s.parseError) continue;
    const size = String(s.tree_size);
    const prev = bySize.get(size);
    if (prev && (prev.root_hash !== s.root_hash || Number(prev.ts) !== Number(s.ts))) conflicts++;
    if (!prev) bySize.set(size, s);
  }
  check(conflicts === 0, `no two archived STHs disagree on one tree_size (${conflicts} conflict(s))`, "archive");

  let badSig = 0;
  const sigs = phase("verifying archived STHs");
  let sigDone = 0;
  for (const [size, s] of bySize) {
    const ok = await verifySth(pubkey, hexToBytes(s.signature), {
      treeSize: BigInt(size),
      rootHash: hexToBytes(s.root_hash),
      ts: Number(s.ts),
    });
    if (!ok) badSig++;
    sigs.tick(++sigDone, bySize.size);
  }
  sigs.end(bySize.size, bySize.size);
  check(badSig === 0, `every archived STH signature verifies (${bySize.size} checked, ${badSig} bad)`, "archive");

  const sizes = [...bySize.keys()].map(Number).sort((a, b) => a - b);
  let tsRegressions = 0;
  for (let i = 1; i < sizes.length; i++) {
    if (Number(bySize.get(String(sizes[i])).ts) < Number(bySize.get(String(sizes[i - 1])).ts)) tsRegressions++;
  }
  check(tsRegressions === 0, `archived STH timestamps are monotone in tree_size (${tsRegressions} regression(s))`, "archive");

  const maxSize = sizes.length ? sizes[sizes.length - 1] : 0;
  check(maxSize <= Number(liveCp.tree_size), `archive never exceeds the live tree (max archived ${maxSize} <= ${liveCp.tree_size})`, "archive");
  check(bySize.has(String(liveCp.tree_size)) && bySize.get(String(liveCp.tree_size)).root_hash === liveCp.root_hash, "the live checkpoint is present in the archive shards", "archive");

  // The replay: every archived root must be the root of TODAY's first
  // tree_size leaves — all published checkpoints on one append-only history.
  // Only sizes the leaves in hand reach can be replayed; an offline run stepped
  // back from the tip says how many it left alone rather than failing them.
  const replaySizes = sizes.filter((s) => s <= leaves.length);
  const skipped = sizes.length - replaySizes.length;
  const roots = await merkleRootsAtSizes(leaves, replaySizes);
  let rootMismatch = 0;
  for (const size of replaySizes) {
    const got = roots.get(size);
    if (!got || bytesToHex(got) !== bySize.get(String(size)).root_hash) {
      rootMismatch++;
      detail(`archive root mismatch at tree_size=${size}`);
    }
  }
  if (skipped > 0) detail(`${skipped} archived checkpoint(s) above the ${leaves.length} leaves in hand — not replayed`);
  check(rootMismatch === 0, `every archived root replays from today's leaves (${replaySizes.length} checkpoint(s), ${rootMismatch} mismatch)`, "archive");
  return bySize;
}

// --- Sigstore Rekor cross-check (default; --no-rekor to skip) ---------------

// Confirm the newest rekor/<tree_size>.json sidecar points at a real Rekor
// entry carrying exactly our signed STH bytes — i.e. an independently operated
// public log witnessed this checkpoint. Needs the archive STHs (ts+signature
// live there, not in the sidecar).
async function verifyRekor(repo, pubkey, cp, archiveBySize) {
  if (!archiveBySize) {
    skipCheck("Rekor cross-check (needs the checkpoint archive)", "rekor");
    return;
  }
  let listed;
  try {
    listed = await listRepoDir(repo, "rekor");
  } catch (e) {
    check(false, `rekor listing: ${e.message}`, "rekor");
    return;
  }
  if (listed === null || listed.rateLimited || listed.missing || (listed.names ?? []).length === 0) {
    skipCheck("Rekor cross-check (no rekor/ sidecars published)", "rekor");
    return;
  }
  const sizes = listed.names
    .filter((n) => /^\d+\.json$/.test(n))
    .map((n) => Number(n.slice(0, -5)))
    .filter((n) => n <= Number(cp.tree_size))
    .sort((a, b) => a - b);
  const newest = sizes[sizes.length - 1];
  if (!newest) {
    skipCheck("Rekor cross-check (no sidecar at or below the current tree)", "rekor");
    return;
  }

  // Local leg (no third party): the published sidecar must name the SAME root as
  // the archived checkpoint. That comparison is entirely repo-local, so a mismatch
  // is tamper evidence and a hard FAIL — independent of whether Rekor is reachable.
  let sidecar;
  try {
    sidecar = await getJson(`${repo}/rekor/${newest}.json`);
  } catch (e) {
    skipCheck(`Rekor cross-check (sidecar ${newest}.json fetch failed: ${e.message})`, "rekor");
    return;
  }
  const sth = archiveBySize.get(String(newest));
  check(!!sth && sidecar.root_hash === sth?.root_hash, `rekor sidecar ${newest} matches the archived checkpoint`, "rekor");
  if (!sth || sidecar.root_hash !== sth.root_hash) return;

  // Remote leg: resolve the entry in Sigstore Rekor. Because this check runs by
  // default, an unreachable Rekor (outage, or a Rekor-side migration) must NOT flip
  // the whole verdict to FAIL — it is not tamper evidence — so it downgrades to a
  // loud skip. Only a resolved entry whose bytes DISAGREE with our STH is a FAIL.
  // The Rekor base is PINNED, not taken from sidecar.rekor_url: the witness must be a
  // KNOWN independent log, not one the repo under test names (which it could point at a
  // server it controls).
  const rekorUrl = PINNED_REKOR_URL;
  let entryResp;
  try {
    entryResp = await getJson(`${rekorUrl}/api/v1/log/entries/${sidecar.rekor_uuid}`);
  } catch (e) {
    skipCheck(`Rekor entry resolution (${rekorUrl} unreachable: ${e.message})`, "rekor");
    return;
  }
  try {
    const entry = entryResp[sidecar.rekor_uuid] ?? Object.values(entryResp)[0];
    if (!entry?.body) throw new Error("entry has no body");
    const body = JSON.parse(Buffer.from(String(entry.body), "base64").toString("utf8"));
    const spec = body?.spec ?? {};
    const sthB = sthBytes(BigInt(newest), hexToBytes(sth.root_hash), Number(sth.ts));
    let artifactOk = false;
    if (spec.data?.content) {
      artifactOk = Buffer.from(String(spec.data.content), "base64").equals(Buffer.from(sthB));
    } else if (spec.data?.hash?.value) {
      artifactOk = String(spec.data.hash.value).toLowerCase() === bytesToHex(await sha256(sthB));
    }
    if (artifactOk) rekorEntryId = sidecar.rekor_uuid;
    check(artifactOk, `Rekor entry ${sidecar.rekor_uuid.slice(0, 12)}${ELL} holds the STH bytes of checkpoint ${newest}`, "rekor");
    const sigOk = spec.signature?.content ? Buffer.from(String(spec.signature.content), "base64").equals(Buffer.from(hexToBytes(sth.signature))) : false;
    check(sigOk, "Rekor entry carries our Ed25519 checkpoint signature", "rekor");
    const pem = spec.signature?.publicKey?.content ? Buffer.from(String(spec.signature.publicKey.content), "base64").toString("utf8") : "";
    check(pem.replace(/\s+/g, "").includes(pubkeyDerB64(pubkey).replace(/\s+/g, "")), "Rekor entry public key is the published log key", "rekor");
  } catch (e) {
    // A malformed/unexpected entry body is ambiguous (Rekor-side format drift),
    // not proof of tampering — skip loudly rather than fail the whole run.
    skipCheck(`Rekor entry parse (${e.message})`, "rekor");
  }
}

// SPKI DER (base64, no PEM armor) of the raw Ed25519 public key — what the PEM
// body inside the Rekor entry must contain.
function pubkeyDerB64(pubRawB64) {
  const prefix = hexToBytes("302a300506032b6570032100");
  const raw = Buffer.from(pubRawB64, "base64");
  return Buffer.concat([Buffer.from(prefix), raw]).toString("base64");
}


// --- raw-leaf sources ------------------------------------------------------

function padSeq(n) {
  return String(n).padStart(12, "0");
}

// RFC 4180 quoting for --counters: a target_id is an arbitrary site-derived string
// and commas do occur in them, so an unquoted dump would shift columns.
function csvField(value) {
  const s = String(value ?? "");
  return /[",\n\r]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

// Yield /log/entries-shaped rows [1..treeSize] from the API (paged) or from
// the log repo's entries/ shards (offline audit).
//
// The whole log is held in memory: the counter fold, the structural invariants and
// the wipe-completeness check each need the full entry set, and the archive replay
// needs every leaf hash. That is roughly a gigabyte of heap around a million
// leaves and it is the real ceiling here — past a few million, fold and verify
// leaf-by-leaf from a streamed source instead of materializing two arrays.
export async function fetchEntries(api, repo, entriesMode, treeSize, shardSize) {
  const rows = [];
  const fetching = phase(entriesMode === "repo" ? "reading entries shards" : "fetching leaves");
  if (entriesMode === "repo") {
    for (let start = 1; start <= treeSize; start += shardSize) {
      const path = `entries/${padSeq(start)}-${padSeq(start + shardSize - 1)}.ndjson`;
      let text;
      try {
        text = await getText(`${repo}/${path}`);
      } catch (e) {
        // A shard that is not there at all is the publisher's batching window, not
        // a broken mirror: appends are held back until they are worth a whole
        // re-upload, so a young log (a freshly reset staging one especially) has a
        // signed checkpoint and no shard yet. Stop reading and let the tail fill
        // from the API below — the same path a partially-mirrored log takes. Any
        // other transport failure still fails the run.
        if (e.status === 404) break;
        // The shard file name is DERIVED from --shard-size, so a wrong width asks
        // for a file that was never published. Say that instead of a stack trace.
        const hint = shardSize === DEFAULT_SHARD_SIZE ? "" : ` — the published shards are ${DEFAULT_SHARD_SIZE} leaves wide, --shard-size says ${shardSize}`;
        throw new Error(`entries shard ${path} could not be read (${e.message})${hint}`);
      }
      for (const line of text.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        const e = JSON.parse(t);
        if (Number(e.seq) <= treeSize) rows.push(e);
      }
      fetching.tick(rows.length, treeSize);
    }
    // The public shards can trail the live checkpoint by a batch of leaves,
    // so a shard-sourced read routinely stops short. Fill that tail from the API
    // (one page, against the ~treeSize/ENTRIES_PAGE an API-only run would spend),
    // so a shard-sourced audit still covers the checkpoint under test.
    const covered = rows.length ? Number(rows[rows.length - 1].seq) : 0;
    if (covered < treeSize) {
      if (!api) {
        // Offline: main() steps the audit back to a checkpoint this coverage
        // reproduces, so this is a note about the mirror, not a verdict.
        detail(`entries/ shards cover ${covered} of ${treeSize} leaves — the newest tail is not mirrored yet, and an offline audit cannot fill it`);
        fetching.end(rows.length, treeSize);
        return rows;
      }
      detail(`entries/ shards cover ${covered} of ${treeSize} leaves — filling the tail from the API`);
      for (let from = covered + 1; from <= treeSize; from += ENTRIES_PAGE) {
        const to = Math.min(from + ENTRIES_PAGE - 1, treeSize);
        rows.push(...((await getJson(`${api}/log/entries?from=${from}&to=${to}`)).entries ?? []));
        fetching.tick(rows.length, treeSize);
      }
    }
    fetching.end(rows.length, treeSize);
    return rows;
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

// Every op=4 tombstone the API lists, for the set comparison in check 4b.
//
// The bare feed answers the newest 1000 revocations plus `has_more`, so
// has_more === false means it IS the complete revoke set — one request instead of
// treeSize/ENTRIES_PAGE. That matters: revocations are sparse, and walking the
// range form over a million-leaf log spends a thousand metered requests to find a
// handful of leaves. The walk stays as the fallback for a log that really has
// accumulated more than a page of them.
//
// Set equality is preserved either way. Fetching only the ranges we already know
// contain an op=4 leaf would be cheaper still, but it could not see a revocation
// the API invents outside those windows — which is exactly what this check exists
// to catch.
export async function fetchRevocations(api, treeSize) {
  const bare = await getJson(`${api}/log/revocations`);
  if (!bare.has_more) {
    // The feed reads the live log, so it can carry leaves appended after the
    // checkpoint under audit. Without the clamp a revocation landing mid-run
    // would read as a set mismatch — a FAIL on an honest log.
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

// With --entries repo the API's own /log/entries is never read, so a regression
// there would pass unnoticed by a scheduled run that audits the shards. One page
// (the cheapest there is: seq 1..1000, immutable and CDN-cached) is compared
// against the shard-derived leaves — it costs a single request and catches both a
// broken endpoint and a disagreement between the two published sources.
export async function crossCheckEntriesSource(api, entries, treeSize) {
  const to = Math.min(ENTRIES_PAGE, treeSize);
  const served = (await getJson(`${api}/log/entries?from=1&to=${to}`)).entries ?? [];
  const mine = entries.slice(0, to);
  const agree = served.length === mine.length && mine.every((e, i) => String(served[i].seq) === String(e.seq) && served[i].leaf_hash === e.leaf_hash);
  return { agree, servedCount: served.length, expected: mine.length };
}

async function main() {
  const api = arg("--api");
  const repo = arg("--repo");
  const pubkey = arg("--pubkey") || PINNED_PUBKEY_B64;
  const wipeGraceHours = Number(arg("--wipe-grace-hours") ?? "48");
  const ots = process.argv.includes("--ots");
  const btcApi = arg("--btc-api");
  const otsExternal = arg("--ots-external");
  const entriesMode = arg("--entries") ?? "api";
  const shardSize = Number(arg("--shard-size") ?? DEFAULT_SHARD_SIZE);
  const statsReport = process.argv.includes("--stats");
  const countersReport = process.argv.includes("--counters");
  // Rekor cross-check is ON by default (it needs --repo for the sidecar); --no-rekor
  // opts out. `--rekor` is still accepted as an explicit no-op for back-compat.
  const rekorDisabled = process.argv.includes("--no-rekor");
  const maxAgeHours = Number(arg("--max-checkpoint-age-hours") ?? "168");
  const allowUnsignedVotes = process.argv.includes("--allow-unsigned-votes");
  const proofsDisabled = process.argv.includes("--no-proofs");
  const blindPubkey = arg("--blind-pubkey") ?? PINNED_BLIND_PUBKEY_SPKI_B64;
  const enrollVkHash = arg("--enroll-vk-hash") ?? PINNED_ENROLL_VK_SHA256;
  const saltCommitment = arg("--salt-commitment") ?? PINNED_SALT_COMMITMENT;
  const audiences = arg("--audiences") ? parseListFlag(arg("--audiences")) : PINNED_AUDIENCES;
  if (process.argv.includes("--help")) {
    console.log(USAGE);
    return;
  }
  const badArgs = argvErrors();
  if (badArgs.length) {
    console.error(`${badArgs.join("; ")}\n${USAGE}`);
    process.exit(2);
  }
  let issuers = PINNED_ISSUERS;
  try {
    if (arg("--issuers")) issuers = parseIssuersFlag(arg("--issuers"));
  } catch (e) {
    console.error(e.message);
    process.exit(2);
  }
  for (const [flag, value] of [
    ["--enroll-vk-hash", enrollVkHash],
    ["--salt-commitment", saltCommitment],
  ]) {
    if (value && !/^[0-9a-f]{64}$/i.test(value)) {
      console.error(`${flag} needs a 64-hex SHA-256`);
      process.exit(2);
    }
  }
  if (!Number.isFinite(maxAgeHours) || maxAgeHours < 0) {
    console.error("--max-checkpoint-age-hours needs a non-negative number (0 disables)");
    process.exit(2);
  }
  if (entriesMode !== "api" && entriesMode !== "repo") {
    console.error("--entries must be 'api' or 'repo'");
    process.exit(2);
  }
  if (!Number.isInteger(shardSize) || shardSize < 1) {
    console.error("--shard-size needs a positive integer");
    process.exit(2);
  }
  // --api is optional ONLY for the offline audit (--entries repo + --repo):
  // then the checkpoint comes from the repo's latest.json and every API-only
  // comparison is skipped.
  if (!api && !(entriesMode === "repo" && repo)) {
    console.error(USAGE);
    process.exit(2);
  }
  if (entriesMode === "repo" && !repo) {
    console.error("--entries repo needs --repo");
    process.exit(2);
  }
  if (!Number.isFinite(wipeGraceHours) || wipeGraceHours < 0) {
    console.error("--wipe-grace-hours needs a non-negative number");
    process.exit(2);
  }
  if (otsExternal && !ots) {
    console.error("--ots-external requires --ots");
    process.exit(2);
  }
  if (!pubkey) {
    console.error("no public key: pass --pubkey <base64> or set PINNED_PUBKEY_B64 in verify.mjs");
    process.exit(2);
  }

  beginAudit();
  const startedAt = Date.now();
  // A log that has never signed anything answers 404 no_checkpoint - the state a
  // brand-new or freshly reset environment is IN, not a break (the backend's own
  // smoke reads it the same way). There is nothing to replay and nothing to
  // contradict, so say so and stop; crashing here published "Independent
  // verification: FAIL" for an environment whose log was simply empty.
  if (api && (await emptyLog(api))) {
    out("the log has published no checkpoint yet (empty log) — nothing to verify");
    if (JSON_MODE) process.stdout.write(`${JSON.stringify({ result: "pass", tree_size: 0, ts: Date.now(), checks: { log: "empty" }, duration_sec: 0 })}\n`);
    else out("\nRESULT: PASS (empty log)");
    return;
  }
  // Offline mode reads the tip from the repo anchor itself (same
  // {tree_size, root_hash, ts, signature} shape as /log/checkpoint).
  const liveCp = api ? await getJson(`${api}/log/checkpoint`) : await getJson(`${repo}/checkpoints/latest.json`);
  let cp = liveCp;
  let treeSize = Number(cp.tree_size);
  out(`checkpoint: tree_size=${cp.tree_size} ts=${cp.ts}${api ? "" : " (from repo latest.json — offline audit)"}`);

  // Offline the raw leaves come first, because how far the shards reach decides
  // WHICH checkpoint this run can audit. With --api the tail is fetched instead,
  // so the tip stays the checkpoint under test and this whole branch is skipped.
  let preloaded = null;
  let uncovered = false;
  if (!api && entriesMode === "repo") {
    preloaded = await fetchEntries(api, repo, entriesMode, treeSize, shardSize);
    const covered = preloaded.length ? Number(preloaded[preloaded.length - 1].seq) : 0;
    if (covered < treeSize) {
      const stepped = await checkpointForShardCoverage(repo, covered);
      if (stepped) {
        cp = stepped;
        treeSize = Number(stepped.tree_size);
        preloaded = preloaded.filter((e) => Number(e.seq) <= treeSize);
        detail(`auditing published checkpoint tree_size=${treeSize} instead — the newest the shards fully cover (live tip ${liveCp.tree_size})`);
      } else {
        uncovered = true;
        detail(`no published checkpoint at or below ${covered} leaves — nothing in the shards can be replayed against a signed root`);
      }
    }
  }

  section("Checkpoint");

  // 1. signature
  const sigOk = await verifySth(pubkey, hexToBytes(cp.signature), {
    treeSize: BigInt(cp.tree_size),
    rootHash: hexToBytes(cp.root_hash),
    ts: cp.ts,
  });
  check(sigOk, "checkpoint Ed25519 signature", "signature");

  // 1b. freshness — a stale checkpoint means the record you are auditing may be
  // a frozen snapshot. A quiet log ages legitimately (checkpoints only advance
  // on new votes), so the threshold is generous and tunable; 0 disables.
  // Freshness is always judged on the TIP, never on a checkpoint an offline run
  // stepped back to — otherwise stepping back would manufacture staleness.
  if (maxAgeHours > 0) {
    const ageH = (Date.now() - Number(liveCp.ts)) / 3_600_000;
    // A FUTURE-dated ts makes ageH negative, which would sail under any positive
    // threshold — so an operator could forward-date the signed ts and defeat the
    // staleness check forever. The ts is part of the SIGNED tree head, so a wrong one is
    // the log's fault, not clock skew; allow a small tolerance, then treat "from the
    // future" as its own failure.
    const SKEW_H = 1;
    if (ageH < -SKEW_H) {
      check(false, `checkpoint ts is ${(-ageH).toFixed(1)}h in the FUTURE — the signed tree head is misdated (beyond ${SKEW_H}h clock-skew tolerance)`, "freshness");
    } else {
      check(ageH <= maxAgeHours, `checkpoint is fresh (${ageH.toFixed(1)}h old, threshold ${maxAgeHours}h — a quiet log ages legitimately; tune --max-checkpoint-age-hours)`, "freshness");
    }
  } else {
    record("freshness", "skip");
  }

  // 2. GitHub anchor cross-check. It compares two INDEPENDENT publications of the
  // same tree head, so it needs both: offline the anchor IS the checkpoint under
  // test, and comparing it with itself would print a PASS that proves nothing.
  if (repo && api) {
    try {
      const latest = await getJson(`${repo}/checkpoints/latest.json`);
      check(
        latest.root_hash === liveCp.root_hash && String(latest.tree_size) === String(liveCp.tree_size),
        `GitHub anchor matches signed root (tree_size=${latest.tree_size})`,
        "github_anchor",
      );
    } catch (e) {
      check(false, `GitHub anchor fetch: ${e.message}`, "github_anchor");
    }
  } else {
    skipCheck(`GitHub anchor cross-check (${repo ? "offline audit — the anchor is the checkpoint under test" : "no --repo"})`, "github_anchor");
  }

  section("Leaves & Merkle");

  // 3. refetch all leaves (API pages or repo shards), recompute leaf_hash +
  //    Merkle root
  const leaves = [];
  const entries = [];
  let leafMismatch = 0;
  const served = preloaded ?? (await fetchEntries(api, repo, entriesMode, treeSize, shardSize));
  const rehash = phase("recomputing leaf hashes");
  for (const e of served) {
    const leaf = await leafHashFromEntry(e);
    if (bytesToHex(leaf) !== e.leaf_hash) leafMismatch++;
    leaves.push(leaf);
    entries.push(e);
    rehash.tick(leaves.length, served.length);
  }
  rehash.end(leaves.length, served.length);
  check(leafMismatch === 0, `every recomputed leaf_hash matches the served leaf (${leafMismatch} mismatch)`, "leaf_hashes");
  if (uncovered) {
    // Nothing signed covers these leaves, so there is no root to compare them to.
    // That is a gap in what the mirror publishes, not evidence against the log.
    skipCheck(`Merkle root (the ${leaves.length} mirrored leaves reach no published checkpoint; pass --api, or audit a mirror that carries one)`, "merkle_root");
  } else {
    check(leaves.length === treeSize, `fetched all ${treeSize} leaves (got ${leaves.length}, source: ${entriesMode})`, "merkle_root");
    const root = await merkleRootFromLeaves(leaves);
    check(bytesToHex(root) === cp.root_hash, "recomputed Merkle root == checkpoint root_hash", "merkle_root");
  }

  // 3a. the published hash chain: the root pins WHICH leaves are in the tree, the
  //     chain pins their ORDER, and every /log/entries row publishes its entry_hash.
  const chain = await checkHashChain(entries, leaves);
  for (const v of chain.slice(0, 5)) detail(v);
  if (chain.length > 5) detail(`${ELL}and ${chain.length - 5} more`);
  check(chain.length === 0, `hash chain replays from genesis (${entries.length} leaves, ${chain.length} break(s))`, "hash_chain");

  section("Checkpoint archive");

  // 3b. checkpoint-archive replay: the whole PUBLISHED history must lie on one
  //     append-only line through today's leaves.
  let archiveBySize = null;
  if (repo) {
    archiveBySize = await verifyCheckpointArchive(repo, pubkey, cp, leaves, liveCp);
  } else {
    skipCheck("checkpoint-archive replay (no --repo)", "archive");
  }

  section("Independent witness");

  // 3c. (default; --no-rekor to skip) the newest checkpoint anchored to Sigstore Rekor
  //     really is there, carrying exactly our signed STH bytes. An unreachable Rekor
  //     downgrades to a skip inside verifyRekor; only disagreeing bytes are a hard fail.
  //     Judged on the TIP: the sidecar and the archive are both repo-local, so the
  //     newest witness is checkable even when the leaves stop short of it.
  if (!rekorDisabled && repo) {
    await verifyRekor(repo, pubkey, liveCp, archiveBySize);
  } else if (!repo && !rekorDisabled) {
    skipCheck("Rekor cross-check (no --repo)", "rekor");
  } else {
    record("rekor", "skip");
  }

  section("Entries cross-check");

  // 3d. entries-source cross-check — only meaningful when the leaves came from the
  //     repo shards; with --entries api check 3 already read every API page.
  if (api && entriesMode === "repo") {
    try {
      const x = await crossCheckEntriesSource(api, entries, treeSize);
      check(x.agree, `/log/entries agrees with the repo shards over the first ${x.expected} leaves (served ${x.servedCount})`, "entries_source");
    } catch (e) {
      check(false, `/log/entries cross-check: ${e.message}`, "entries_source");
    }
  } else {
    record("entries_source", "skip");
  }

  // --stats: informational per-day aggregate report, derived from the entries
  // alone (the same numbers anyone can recompute without the operator).
  if (statsReport) {
    const perDay = dailyAggregates(entries);
    raw("day,votes,unique_user_refs,revokes");
    for (const day of [...perDay.keys()].sort()) {
      const a = perDay.get(day);
      raw(`${day},${a.votes},${a.refs.size},${a.revokes}`);
    }
  }

  // 4. fold. Every counter Emojery publishes is re-derived here from leaves this
  // run already verified against the signed root, so an auditor can state the
  // totals themselves instead of quoting ours. There is deliberately no
  // comparison against the live API: /reactions/count is not part of the public
  // verification surface, and this tool's whole value is that its totals are
  // derived independently.
  const counts = foldCounters(entries);
  out(`folded ${counts.size} (site,target,reaction) counters from ${entries.length} events`);

  // --counters: the totals themselves, so the auditor publishes numbers rather than
  // a claim that numbers were computed. Zero-valued keys (added then removed, or
  // revoked away) are dropped — they are fold bookkeeping, not counts anyone shows.
  if (countersReport) {
    raw("site,target_id,reaction,count");
    for (const [key, value] of [...counts].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
      if (value <= 0) continue;
      const [site, target, reaction] = splitCounterKey(key);
      raw(`${csvField(site)},${csvField(target)},${csvField(reaction)},${value}`);
    }
  }

  section("Log semantics");

  // 4b. revocation audit surface: the public /log/revocations list must equal the
  //     set of op=4 tombstones we folded from the log.
  if (!api) {
    skipCheck("/log/revocations comparison (offline audit, no --api)", "revocations");
  } else {
    try {
      const revList = await fetchRevocations(api, treeSize);
      out(`revocations: ${revList.length} tombstone(s)`);
      for (const r of revList.slice(0, 5)) {
        detail(
          `revoke seq=${r.seq} -> revoke_seq=${r.revoke_seq} reason=${r.reason_code ?? "-"} target=${r.target?.site}/${r.target?.target_id}`,
        );
      }
      if (revList.length > 5) detail(`${ELL}and ${revList.length - 5} more`);
      const op4 = entries
        .filter((e) => e.op === 4)
        .map((e) => String(e.seq))
        .sort();
      const listed = revList.map((r) => String(r.seq)).sort();
      check(
        op4.length === listed.length && op4.every((s, i) => s === listed[i]),
        `/log/revocations matches op=4 leaves in the log (${op4.length})`,
        "revocations",
      );
    } catch (e) {
      check(false, `/log/revocations fetch: ${e.message}`, "revocations");
    }
  }

  // 5. structural consistency an honest log always satisfies: entries are
  //    well-formed and no per-(target,reaction) count is ever driven negative.
  const violations = checkStructuralInvariants(entries);
  for (const v of violations.slice(0, 20)) detail(v);
  if (violations.length > 20) detail(`${ELL}and ${violations.length - 20} more`);
  check(violations.length === 0, `structural invariants hold (${violations.length} violation(s))`, "invariants");

  // 5b. invariant F — account-wipe completeness. Revocations are whole-account,
  //     so a pseudonym with some but not all of its leaves revoked is flagged
  //     (after the grace window for wipes still in flight at checkpoint time).
  const wipe = checkWipeCompleteness(entries, Number(cp.ts), wipeGraceHours * 3_600_000);
  for (const v of wipe.slice(0, 20)) detail(v);
  if (wipe.length > 20) detail(`${ELL}and ${wipe.length - 20} more`);
  check(
    wipe.length === 0,
    `account wipes are complete (${wipe.length} violation(s); grace ${wipeGraceHours}h)`,
    "wipe_completeness",
  );

  section("Identity");

  // 5c. the identity track. Structure first (G/H/I over the entries alone), then the
  //     two signature checks, then the ENROLL proofs. An unsigned vote is a 1.0.0
  //     leaf: admitted while the compatibility window is open, a failure after it.
  const identity = await checkIdentityInvariants(entries);
  out(`identity: ${identity.enrolls} enroll, ${identity.issues} issue, ${identity.keys} key leaf(s); ${identity.signedVotes} signed and ${identity.unsignedVotes} unsigned vote(s)`);
  for (const v of identity.violations.slice(0, 20)) detail(v);
  if (identity.violations.length > 20) detail(`${ELL}and ${identity.violations.length - 20} more`);
  check(identity.violations.length === 0, `identity invariants hold (${identity.violations.length} violation(s))`, "identity_structure");
  if (identity.unsignedVotes > 0 && !allowUnsignedVotes) {
    check(false, `${identity.unsignedVotes} vote(s) carry no client signature (pass --allow-unsigned-votes while 1.0.0 clients are served)`, "identity_structure");
  }

  const signing = phase("verifying vote and key signatures");
  const sigs = await verifyIdentitySignatures(entries, { blindPubkeySpkiB64: blindPubkey }, (done, total) => signing.tick(done, total));
  signing.end(entries.length, entries.length);
  for (const v of sigs.voteViolations.slice(0, 10)) detail(v);
  if (sigs.voteViolations.length > 10) detail(`${ELL}and ${sigs.voteViolations.length - 10} more`);
  if (sigs.votesChecked === 0) skipCheck("vote signatures (no signed votes in the log yet)", "vote_signatures");
  else check(sigs.voteViolations.length === 0, `every signed vote verifies under its epoch key (${sigs.votesChecked} checked, ${sigs.voteViolations.length} bad)`, "vote_signatures");
  for (const v of sigs.keyViolations.slice(0, 10)) detail(v);
  if (sigs.keyViolations.length > 10) detail(`${ELL}and ${sigs.keyViolations.length - 10} more`);
  if (identity.keys === 0) skipCheck("epoch-key signatures (no KEY leaves in the log yet)", "key_signatures");
  else if (!blindPubkey) skipCheck(`epoch-key signatures (${sigs.keysSkipped} KEY leaf(s), no pinned blind key: set PINNED_BLIND_PUBKEY_SPKI_B64 or pass --blind-pubkey)`, "key_signatures");
  else check(sigs.keyViolations.length === 0, `every KEY leaf carries a valid blind RSA-PSS signature (${sigs.keysChecked} checked, ${sigs.keyViolations.length} bad)`, "key_signatures");

  if (proofsDisabled) {
    skipCheck("ENROLL proofs (--no-proofs)", "enroll_proofs");
  } else {
    let proving = null; // started on the first proof, so a log without ENROLL leaves shows no empty bar
    const proofs = await verifyEnrollProofs(entries, {
      repo,
      getJson,
      getBytes,
      vkSha256: enrollVkHash,
      saltCommitment,
      issuers,
      audiences,
      bbVersion: BB_JS_VERSION,
      onProgress: (done, total) => {
        proving ??= phase("verifying ENROLL proofs");
        proving.tick(done, total);
      },
    });
    proving?.end(proofs.checked, proofs.checked);
    for (const n of proofs.notes.slice(0, 20)) detail(n);
    if (proofs.notes.length > 20) detail(`${ELL}and ${proofs.notes.length - 20} more`);
    if (proofs.status === "skip") skipCheck(`ENROLL proofs (${proofs.reason})`, "enroll_proofs");
    else check(proofs.status === "pass", `every ENROLL proof verifies under the pinned verification key (${proofs.reason})`, "enroll_proofs");
  }

  // 6. optional OpenTimestamps → Bitcoin deep audit.
  if (ots) {
    section("Bitcoin anchor");
    await verifyOts(repo, pubkey, btcApi, otsExternal);
  } else record("ots", "skip");

  if (JSON_MODE) {
    process.stdout.write(
      JSON.stringify({
        result: failed ? "fail" : "pass",
        tree_size: cp.tree_size,
        ts: Date.now(),
        checks,
        duration_sec: Math.round((Date.now() - startedAt) / 1000),
      }) + "\n",
    );
  } else {
    const slug = repo ? githubSlugFromRawBase(repo) : null;
    verdict({
      ok: !failed,
      treeSize: cp.tree_size,
      rootHash: `${cp.root_hash.slice(0, 10)}${ELL}${cp.root_hash.slice(-6)}`,
      keyLabel: `${pubkey.slice(0, 10)}${ELL} ${pubkey === PINNED_PUBKEY_B64 ? "(pinned in verify.mjs)" : "(--pubkey)"}`,
      witnesses: [
        checks.github_anchor === "pass" ? "GitHub anchor" : null,
        rekorEntryId ? `Rekor ${rekorEntryId.slice(0, 12)}${ELL}` : null,
        btcBlockHeight ? `Bitcoin block ${btcBlockHeight}` : null,
      ],
      sources: [
        api ? new URL(api).host : "offline (API not contacted)",
        slug ? `${slug.owner}/${slug.repo}@${slug.ref}` : repo ? new URL(repo).host : null,
        entriesMode === "repo" ? "entry shards" : "API pages",
      ],
      elapsedSec: ((Date.now() - startedAt) / 1000).toFixed(1),
      reproduce: `node src/verify.mjs ${process.argv.slice(2).join(" ")}`,
    });
  }
  process.exitCode = failed ? 1 : 0;
}

// Import-safe: revocations.selftest.mjs imports the fetch helpers above, so the
// audit itself runs only when this file is the process entrypoint.
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((e) => {
    flush();
    // The message says what to fix; the stack says nothing a user of this tool acts
    // on, so it waits behind VERIFY_DEBUG=1 instead of burying the message.
    console.error(`verifier error: ${e?.message ?? e}`);
    if (process.env.VERIFY_DEBUG) console.error(e);
    // --json promises ONE machine-readable object on stdout. A crash before the summary
    // (network, a malformed shard) must still emit one, or a --json consumer sees empty
    // stdout and cannot tell "verification failed" from "the process produced nothing".
    if (JSON_MODE) process.stdout.write(`${JSON.stringify({ result: "fail", error: String(e?.message ?? e), checks })}\n`);
    process.exitCode = 1;
  });
}
