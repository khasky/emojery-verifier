// SPDX-License-Identifier: GPL-3.0-or-later
// The deep audit (--ots): the matured OpenTimestamps proof anchors the signed
// checkpoint root in a Bitcoin block.

import { getJson, getRes } from "../http.mjs";
import { check, record } from "../outcomes.mjs";
import { runExternalOts, verifyDetachedOtsProof } from "../ots-bitcoin.mjs";
import { hexToBytes, verifySth } from "../transparency.mjs";

// Returns the anchoring Bitcoin block height, or null.
export async function verifyOts(repo, pubkey, { enabled, btcApi, otsExternal }) {
  if (!enabled) {
    record("ots", "skip");
    return null;
  }
  if (!repo) {
    check(false, "OTS: --ots needs --repo (the .ots proof lives in the log repo)", "ots");
    return null;
  }
  let latest;
  try {
    latest = await getJson(`${repo}/ots/latest.json`);
  } catch (e) {
    check(false, `OTS: no matured proof published yet (ots/latest.json: ${e.message})`, "ots");
    return null;
  }
  const t = String(latest.tree_size);
  let sidecar;
  try {
    sidecar = await getJson(`${repo}/ots/${t}.json`);
  } catch (e) {
    check(false, `OTS sidecar fetch: ${e.message}`, "ots");
    return null;
  }

  // root_hash is repo-controlled and, with --ots-external, becomes an argv of a
  // spawned process: it is validated as a 64-hex digest before either use.
  if (!/^[0-9a-f]{64}$/i.test(String(sidecar.root_hash ?? ""))) {
    check(false, "OTS sidecar root_hash is not a 64-hex digest", "ots");
    return null;
  }

  const sigOk = await verifySth(pubkey, hexToBytes(sidecar.signature), {
    treeSize: BigInt(sidecar.tree_size),
    rootHash: hexToBytes(sidecar.root_hash),
    ts: sidecar.ts,
  });
  check(sigOk, `OTS sidecar is a signed checkpoint STH (tree_size=${t})`, "ots");
  if (!sigOk) return null;

  let otsBytes;
  try {
    const res = await getRes(`${repo}/${sidecar.ots_path}`);
    if (!res.ok) throw new Error(`GET ${sidecar.ots_path} -> ${res.status}`);
    otsBytes = new Uint8Array(await res.arrayBuffer());
  } catch (e) {
    check(false, `OTS: fetch proof: ${e.message}`, "ots");
    return null;
  }

  let height = null;
  try {
    const result = await verifyDetachedOtsProof({ rootHashHex: sidecar.root_hash, otsBytes, btcApi });
    height = result.height;
    check(true, `OTS: signed root anchored in Bitcoin (block ${result.height})`, "ots");
    if (sidecar.btc_block_height != null) {
      // A multi-calendar proof anchors in several blocks and the sidecar records one of them.
      check(result.heights.includes(Number(sidecar.btc_block_height)), `OTS sidecar block height is anchored by the proof (${sidecar.btc_block_height})`, "ots");
    }
  } catch (e) {
    check(false, `OTS Bitcoin verification: ${e.message}`, "ots");
  }

  if (!otsExternal) return height;
  try {
    await runExternalOts({ command: otsExternal, rootHashHex: sidecar.root_hash, otsBytes });
    check(true, `OTS external verifier passed (${otsExternal})`, "ots_external");
  } catch (e) {
    check(false, `OTS external verifier: ${e.message}`, "ots_external");
  }
  return height;
}
