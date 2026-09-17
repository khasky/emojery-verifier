// SPDX-License-Identifier: GPL-3.0-or-later
// The checkpoint archive: every tree head ever published to checkpoints/*.ndjson must
// lie on one append-only history through today's leaves.

import { getText, listRepoDir } from "../http.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { detail, phase } from "../report.mjs";
import { bytesToHex, hexToBytes, merkleRootsAtSizes, verifySth } from "../transparency.mjs";

// Memoized: an offline run reads the archive twice (to pick the checkpoint the shards
// cover, then to replay it) and the listing is metered by GitHub.
let archiveCache = null;
async function fetchCheckpointArchive(repo) {
  if (archiveCache) return archiveCache;
  archiveCache = await readCheckpointArchive(repo);
  return archiveCache;
}

// Only the shards are merged; checkpoints/latest.json is the live anchor.
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

// The newest archived checkpoint at or below the leaf count the shards carry.
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

// The checkpoint an offline run audits when the shards trail the tip. Its signature
// is not pre-verified here: the signature check verifies whatever this returns, so a
// tampered archive line fails loudly.
export async function checkpointForShardCoverage(repo, covered) {
  let archive;
  try {
    archive = await fetchCheckpointArchive(repo);
  } catch {
    return null;
  }
  if (!archive || archive.rateLimited || !archive.sths) return null;
  return pickCoveredCheckpoint(archive.sths, covered);
}

// `liveCp` is the tip; `leaves` may stop short of it on an offline run. Returns the
// per-tree_size STH map for the Rekor check, or null when the archive is unreadable.
export async function verifyCheckpointArchive(repo, pubkey, leaves, liveCp) {
  if (!repo) {
    skipCheck("checkpoint-archive replay (no --repo)", "archive");
    return null;
  }
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

  // Two published STHs disagreeing on one tree_size is signed equivocation.
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

  // Only sizes the leaves in hand reach can be replayed; an offline run stepped back
  // from the tip reports how many it left alone.
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
  if (skipped > 0) detail(`${skipped} archived checkpoint(s) above the ${leaves.length} leaves in hand - not replayed`);
  check(rootMismatch === 0, `every archived root replays from today's leaves (${replaySizes.length} checkpoint(s), ${rootMismatch} mismatch)`, "archive");
  return bySize;
}
