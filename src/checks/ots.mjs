// SPDX-License-Identifier: GPL-3.0-or-later
// The Bitcoin anchor (--ots): the newest matured OpenTimestamps proof anchors a signed
// checkpoint root in a Bitcoin block, and that proof is not falling behind the log.

import { getJson, getRes } from "../http.mjs";
import { check, record, skipCheck } from "../outcomes.mjs";
import { runExternalOts, verifyDetachedOtsProof } from "../ots-bitcoin.mjs";
import { hexToBytes, verifySth } from "../transparency.mjs";

const HOUR_MS = 3_600_000;

// What the absence or age of the matured proof means, given the newest checkpoint.
// A receipt takes hours to reach a block and the operator publishes the proof on a
// schedule after that, so a young log with no proof yet is a skip; past
// `maxLagHours` the pipeline that matures receipts is stuck, which is a failure
// whether the file is missing or merely old. Pure, so the selftest can pin the edges.
export function otsLagOutcome({ liveTs, proofTs, now, maxLagHours }) {
  const lagFrom = proofTs ?? null;
  const ageH = (now - Number(liveTs)) / HOUR_MS;
  if (lagFrom === null) {
    return ageH <= maxLagHours ? { status: "skip", reason: `no matured proof published yet (newest checkpoint ${ageH.toFixed(1)}h old, allowed ${maxLagHours}h)` } : { status: "fail", reason: `no matured proof although the newest checkpoint is ${ageH.toFixed(1)}h old (allowed ${maxLagHours}h) - the maturation pipeline is stalled` };
  }
  const lagH = (Number(liveTs) - Number(proofTs)) / HOUR_MS;
  return lagH <= maxLagHours ? { status: "pass", reason: `matured proof lags the newest checkpoint by ${Math.max(0, lagH).toFixed(1)}h (allowed ${maxLagHours}h)` } : { status: "fail", reason: `matured proof lags the newest checkpoint by ${lagH.toFixed(1)}h (allowed ${maxLagHours}h) - the maturation pipeline is stalled` };
}

// Returns the anchoring Bitcoin block height, or null.
export async function verifyOts(repo, pubkey, liveCp, { enabled, btcApi, otsExternal, maxLagHours }) {
  if (!enabled) {
    record("ots", "skip");
    return null;
  }
  if (!repo) {
    check(false, "OTS: --ots needs --repo (the .ots proof lives in the log repo)", "ots");
    return null;
  }
  const now = Date.now();
  const latestRes = await getRes(`${repo}/ots/latest.json`);
  if (latestRes.status === 404) {
    const o = otsLagOutcome({ liveTs: liveCp.ts, proofTs: null, now, maxLagHours });
    if (o.status === "skip") skipCheck(`OTS: ${o.reason}`, "ots");
    else check(false, `OTS: ${o.reason}`, "ots");
    return null;
  }
  if (!latestRes.ok) {
    check(false, `OTS: ots/latest.json -> ${latestRes.status}`, "ots");
    return null;
  }
  const latest = await latestRes.json();
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

  // The proof is judged against the tip, never against the checkpoint an offline run
  // stepped back to: what is being asked is whether maturation keeps up with the log.
  const lag = otsLagOutcome({ liveTs: liveCp.ts, proofTs: sidecar.ts, now, maxLagHours });
  check(lag.status === "pass", `OTS: ${lag.reason}`, "ots");

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
