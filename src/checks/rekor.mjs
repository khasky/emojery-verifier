// SPDX-License-Identifier: GPL-3.0-or-later
// The independent witness: the newest rekor/<tree_size>.json sidecar must point at a
// real Sigstore Rekor entry carrying exactly our signed tree-head bytes.

import { getJson, listRepoDir } from "../http.mjs";
import { check, record, skipCheck } from "../outcomes.mjs";
import { bytesToHex, hexToBytes, sha256, sthBytes } from "../transparency.mjs";

// Pinned rather than read from the sidecar: a compromised log repository could
// otherwise point the "independent" check at a server it controls. A fork on a
// different Rekor edits this, like the log key.
const PINNED_REKOR_URL = "https://rekor.sigstore.dev";

// SPKI DER (base64) of the raw Ed25519 public key, as the PEM inside the Rekor
// entry carries it.
function pubkeyDerB64(pubRawB64) {
  const prefix = hexToBytes("302a300506032b6570032100");
  const raw = Buffer.from(pubRawB64, "base64");
  return Buffer.concat([Buffer.from(prefix), raw]).toString("base64");
}

// Returns the witnessed Rekor entry id, or null. `archiveBySize` comes from the
// archive replay (ts and signature live there, not in the sidecar).
export async function verifyRekor(repo, pubkey, liveCp, archiveBySize, disabled) {
  if (disabled) {
    record("rekor", "skip");
    return null;
  }
  if (!repo) {
    skipCheck("Rekor cross-check (no --repo)", "rekor");
    return null;
  }
  if (!archiveBySize) {
    skipCheck("Rekor cross-check (needs the checkpoint archive)", "rekor");
    return null;
  }
  let listed;
  try {
    listed = await listRepoDir(repo, "rekor");
  } catch (e) {
    check(false, `rekor listing: ${e.message}`, "rekor");
    return null;
  }
  if (listed === null || listed.rateLimited || listed.missing || (listed.names ?? []).length === 0) {
    skipCheck("Rekor cross-check (no rekor/ sidecars published)", "rekor");
    return null;
  }
  const sizes = listed.names
    .filter((n) => /^\d+\.json$/.test(n))
    .map((n) => Number(n.slice(0, -5)))
    .filter((n) => n <= Number(liveCp.tree_size))
    .sort((a, b) => a - b);
  const newest = sizes[sizes.length - 1];
  if (!newest) {
    skipCheck("Rekor cross-check (no sidecar at or below the current tree)", "rekor");
    return null;
  }

  // Repo-local leg: the sidecar must name the same root as the archived checkpoint.
  // A mismatch is tamper evidence whether or not Rekor is reachable.
  let sidecar;
  try {
    sidecar = await getJson(`${repo}/rekor/${newest}.json`);
  } catch (e) {
    skipCheck(`Rekor cross-check (sidecar ${newest}.json fetch failed: ${e.message})`, "rekor");
    return null;
  }
  const sth = archiveBySize.get(String(newest));
  check(!!sth && sidecar.root_hash === sth?.root_hash, `rekor sidecar ${newest} matches the archived checkpoint`, "rekor");
  if (!sth || sidecar.root_hash !== sth.root_hash) return null;

  // Remote leg. An unreachable Rekor is an outage, not tamper evidence, so it
  // downgrades to a skip; only a resolved entry whose bytes disagree fails.
  let entryResp;
  try {
    entryResp = await getJson(`${PINNED_REKOR_URL}/api/v1/log/entries/${sidecar.rekor_uuid}`);
  } catch (e) {
    skipCheck(`Rekor entry resolution (${PINNED_REKOR_URL} unreachable: ${e.message})`, "rekor");
    return null;
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
    check(artifactOk, `Rekor entry ${sidecar.rekor_uuid.slice(0, 12)}... holds the STH bytes of checkpoint ${newest}`, "rekor");
    const sigOk = spec.signature?.content ? Buffer.from(String(spec.signature.content), "base64").equals(Buffer.from(hexToBytes(sth.signature))) : false;
    check(sigOk, "Rekor entry carries our Ed25519 checkpoint signature", "rekor");
    const pem = spec.signature?.publicKey?.content ? Buffer.from(String(spec.signature.publicKey.content), "base64").toString("utf8") : "";
    check(pem.replace(/\s+/g, "").includes(pubkeyDerB64(pubkey).replace(/\s+/g, "")), "Rekor entry public key is the published log key", "rekor");
    return artifactOk ? sidecar.rekor_uuid : null;
  } catch (e) {
    // A malformed entry body is Rekor-side format drift, not proof of tampering.
    skipCheck(`Rekor entry parse (${e.message})`, "rekor");
    return null;
  }
}
