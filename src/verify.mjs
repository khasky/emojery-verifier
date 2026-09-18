#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Entry point: parses the command line, runs the checks in order and prints the
// verdict (or the --json summary). Exit code 0 = PASS, 1 = FAIL, 2 = usage error.
//
// The values this deployment is verified against are pinned here and nowhere else,
// so a copy cannot drift. A fork or another deployment overrides them with flags.

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { checkConsistencyChain, checkpointForShardCoverage, verifyCheckpointArchive } from "./checks/archive.mjs";
import { checkCheckpointSignature, checkFreshness, checkGithubAnchor } from "./checks/checkpoint.mjs";
import { checkIdentityTrack } from "./checks/identity-track.mjs";
import { checkEntriesSource, checkHashChainReplay, checkMerkleRoot, fetchEntries, manifestBase, rehashLeaves } from "./checks/leaves.mjs";
import { verifyOts } from "./checks/ots.mjs";
import { verifyRekor } from "./checks/rekor.mjs";
import { checkRevocationFeed, checkStructure, checkWipes, reportFold } from "./checks/semantics.mjs";
import { HELP, parseCli, USAGE } from "./cli.mjs";
import { emptyLog, getJson, githubSlugFromRawBase } from "./http.mjs";
import { DEFAULT_ISSUERS } from "./identity.mjs";
import { checks, hasFailed, skipCheck } from "./outcomes.mjs";
import { configureReport, detail, flush, out, section, verdict } from "./report.mjs";

// The published log signing key (base64 raw Ed25519).
const PINNED_PUBKEY_B64 = "XeLiQ5CMhsjLmnQbIWSwWHNjcJg01Zs0veQDiwluT6c=";

// Identity-track pins. An empty one makes the check that needs it report a skip
// naming the pin. PINNED_ENROLL_VK_SHA256 is the SHA-256 of keys/enroll-v1.vk in the
// log repository; PINNED_BLIND_PUBKEY_SPKI_B64 is also published there as
// keys/blind-rsa-v1.json.
const PINNED_BLIND_PUBKEY_SPKI_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlbzZGsfKa/Yv3Kw2S4pa+h1k+NsIc4wxfZUNCZgZKfAKHCKqCxIEJrFPk9L1JYLMwCbStps3gkPT8eEtlAzReMZQfwuGvDymUqBXaKBRKMnxzQVSdNpnfQQFmvbomCvj69AcfjdYrJAoi05EltXrhoMGZyQkwtKKYAjZ2J8bZPuNvx0a0A2kpfz4l7vhaM55Dg3CWgwLkRasZyPen7ZaEYhvfTQ4Nf58wpf3+TJdFjwYxCBuBrcd9n13uGqSHRXWPDNu6CdzPRAO2a5Dw1YfnsT1+K8cqyMMe5lzTx7uZ5swsIW6crA0E38yKQdRYQ+djgWTpLNyk56CgE4YJMDsAQIDAQAB";
const PINNED_ENROLL_VK_SHA256 = "09d386a1e439aea0f122a9599ae2fbde5ea79f30bac3e5661c106014ee92bfbb";
const PINNED_SALT_COMMITMENT = "a36bc4182f1bad025d77733db207fe53a2a43d561c70b2fea65300a4fc338735";
const PINNED_AUDIENCES = [
  "368200727057-40v0prpc56gpqiv6oiu3rval6su4jbuf.apps.googleusercontent.com",
  "app.emojery.web",
  "54fe9a8a-4525-42b2-917a-49958391f7c9",
  "vjid5zxm5yuyf5moohb74waeaq2m38",
];
const PINNED_ISSUERS = DEFAULT_ISSUERS;

// keys/enroll-v1.json records the bb the operator proved with; a drift from the
// version pinned in package.json is reported next to the proof check.
const BB_JS_VERSION = createRequire(import.meta.url)("../package.json").dependencies["@aztec/bb.js"];

// Where the proof bodies are fetched from: the same host the shard bodies come from.
// A run that never needed the manifest still has to find them, so the lookup falls
// back to the repository's own mirrors.json.
async function proofsBaseFor(o) {
  try {
    return await manifestBase(o.repo, o.entriesBase);
  } catch {
    return null;
  }
}

async function main() {
  const parsed = parseCli(process.argv.slice(2));
  if (parsed.help) {
    console.log(HELP);
    return;
  }
  if (parsed.error) {
    console.error(`${parsed.error}\n${USAGE}`);
    process.exit(2);
  }
  const o = parsed.options;
  const pubkey = o.pubkey || PINNED_PUBKEY_B64;
  const blindPubkey = o.blindPubkey ?? PINNED_BLIND_PUBKEY_SPKI_B64;
  configureReport({ json: o.json });
  const startedAt = Date.now();

  // A log that has never signed anything answers 404 no_checkpoint: a brand-new or
  // freshly reset deployment, with nothing to replay and nothing to contradict.
  if (o.api && (await emptyLog(o.api))) {
    out("the log has published no checkpoint yet (empty log) - nothing to verify");
    if (o.json) process.stdout.write(`${JSON.stringify({ result: "pass", tree_size: 0, ts: Date.now(), checks: { log: "empty" }, duration_sec: 0 })}\n`);
    else out("\nRESULT: PASS (empty log)");
    return;
  }

  const liveCp = o.api ? await getJson(`${o.api}/log/checkpoint`) : await getJson(`${o.repo}/checkpoints/latest.json`);
  let cp = liveCp;
  let treeSize = Number(cp.tree_size);
  out(`checkpoint: tree_size=${cp.tree_size} ts=${cp.ts}${o.api ? "" : " (from repo latest.json - offline audit)"}`);

  // Offline, how far the shards reach decides which checkpoint this run can audit:
  // the newest published one they fully cover. With --api the missing tail is
  // fetched instead and the tip stays under test.
  const leafless = o.entriesMode === "none";
  let entries = null;
  let uncovered = false;
  if (!o.api && !leafless) {
    entries = await fetchEntries(o.api, o.repo, treeSize, { mode: o.entriesMode, base: o.entriesBase });
    const covered = entries.length ? Number(entries[entries.length - 1].seq) : 0;
    if (covered < treeSize) {
      const stepped = await checkpointForShardCoverage(o.repo, covered);
      if (stepped) {
        cp = stepped;
        treeSize = Number(stepped.tree_size);
        entries = entries.filter((e) => Number(e.seq) <= treeSize);
        detail(`auditing published checkpoint tree_size=${treeSize} instead - the newest the shards fully cover (live tip ${liveCp.tree_size})`);
      } else {
        uncovered = true;
        detail(`no published checkpoint at or below ${covered} leaves - nothing in the shards can be replayed against a signed root`);
      }
    }
  }

  section("Checkpoint");
  await checkCheckpointSignature(pubkey, cp);
  checkFreshness(liveCp, o.maxAgeHours);
  await checkGithubAnchor(o.repo, o.api, liveCp);

  // --entries none checks the signed checkpoints and the consistency proofs beside
  // them without downloading a leaf, which is seconds on a log of any size. The root
  // commits to whatever leaves the operator folded into it, so everything below that
  // reads a leaf is skipped and reported.
  section("Leaves & Merkle");
  let leaves = [];
  if (leafless) {
    skipCheck("leaf hashes, Merkle root and hash chain (--entries none)", "merkle_root");
  } else {
    entries ??= await fetchEntries(o.api, o.repo, treeSize, { mode: o.entriesMode, base: o.entriesBase });
    leaves = await rehashLeaves(entries);
    await checkMerkleRoot(leaves, cp, treeSize, o.entriesMode, uncovered);
    await checkHashChainReplay(entries, leaves);
  }

  section("Checkpoint archive");
  const archiveBySize = await verifyCheckpointArchive(o.repo, pubkey, leafless ? null : leaves, liveCp);
  if (archiveBySize) await checkConsistencyChain(archiveBySize);

  section("Independent witness");
  const rekorEntryId = await verifyRekor(o.repo, pubkey, liveCp, archiveBySize, o.rekorDisabled);

  section("Entries cross-check");
  if (leafless) {
    skipCheck("the entries cross-check, the counter fold, the revocation feed and invariants A-J (--entries none)", "leafless");
    detail("no leaf was read: the checkpoints and their consistency proofs are checked, the contents of the log are not");
  } else {
    await checkEntriesSource(o.api, o.entriesMode, entries, treeSize);
  }

  if (!leafless) {
    section("Log semantics");
    reportFold(entries);
    await checkRevocationFeed(o.api, entries, treeSize);
    checkStructure(entries);
    checkWipes(entries, cp, o.wipeGraceHours);

    section("Identity");
    await checkIdentityTrack(entries, {
      repo: o.repo,
      // The proof bodies sit beside the shard bodies, wherever those are served from.
      proofsBase: await proofsBaseFor(o),
      keysPerAccount: o.keysPerAccount,
      allowUnsignedVotes: o.allowUnsignedVotes,
      blindPubkey,
      proofsDisabled: o.proofsDisabled,
      enrollVkHash: o.enrollVkHash ?? PINNED_ENROLL_VK_SHA256,
      saltCommitment: o.saltCommitment ?? PINNED_SALT_COMMITMENT,
      issuers: o.issuers ?? PINNED_ISSUERS,
      audiences: o.audiences ?? PINNED_AUDIENCES,
      bbVersion: BB_JS_VERSION,
    });
  }

  if (o.ots) section("Bitcoin anchor");
  const btcBlockHeight = await verifyOts(o.repo, pubkey, { enabled: o.ots, btcApi: o.btcApi, otsExternal: o.otsExternal });

  const failed = hasFailed();
  if (o.json) {
    process.stdout.write(`${JSON.stringify({ result: failed ? "fail" : "pass", tree_size: cp.tree_size, ts: Date.now(), checks, duration_sec: Math.round((Date.now() - startedAt) / 1000) })}\n`);
  } else {
    const slug = o.repo ? githubSlugFromRawBase(o.repo) : null;
    verdict({
      ok: !failed,
      treeSize: cp.tree_size,
      rootHash: `${cp.root_hash.slice(0, 10)}...${cp.root_hash.slice(-6)}`,
      keyLabel: `${pubkey.slice(0, 10)}... ${pubkey === PINNED_PUBKEY_B64 ? "(pinned in verify.mjs)" : "(--pubkey)"}`,
      witnesses: [checks.github_anchor === "pass" ? "GitHub anchor" : null, rekorEntryId ? `Rekor ${rekorEntryId.slice(0, 12)}...` : null, btcBlockHeight ? `Bitcoin block ${btcBlockHeight}` : null],
      sources: [
        o.api ? new URL(o.api).host : "offline (API not contacted)",
        slug ? `${slug.owner}/${slug.repo}@${slug.ref}` : o.repo ? new URL(o.repo).host : null,
        { repo: "entry shards", manifest: "manifest + shard bodies", none: "no leaves read", api: "API pages" }[o.entriesMode],
      ],
      elapsedSec: ((Date.now() - startedAt) / 1000).toFixed(1),
      reproduce: `node src/verify.mjs ${process.argv.slice(2).join(" ")}`,
    });
  }
  process.exitCode = failed ? 1 : 0;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((e) => {
    flush();
    console.error(`verifier error: ${e?.message ?? e}`);
    if (process.env.VERIFY_DEBUG) console.error(e);
    // --json promises one object on stdout even when the run crashes before the summary.
    if (process.argv.includes("--json")) process.stdout.write(`${JSON.stringify({ result: "fail", error: String(e?.message ?? e), checks })}\n`);
    process.exitCode = 1;
  });
}
