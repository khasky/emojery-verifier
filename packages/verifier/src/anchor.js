// SPDX-License-Identifier: Apache-2.0
// Anchor files (docs/PROTOCOL.md §8): the log's checkpoint, Ed25519ph-signed by the log
// key and entered in a Rekor v2 shard as a hashedrekord. Everything is checked from the
// file alone; a live Rekor is never asked.

import { ed25519ph } from "@noble/curves/ed25519.js";
import { concat, decodeUtf8, equalBytes, fromBase64, leafHash, parseCheckpoint, sha512, utf8, verifyInclusion, verifyNote } from "@emojery/shared/core";

export const ANCHOR_KIND = "rekor-v2";
const SPKI_ED25519 = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const CLOCK_SKEW_S = 600;

export class AnchorError extends Error {
  name = "AnchorError";
}

/**
 * @typedef {object} Anchor
 * @property {"ok" | "unknown-kind"} status
 * @property {string} [note]
 * @property {{ origin: string, size: number, root: Uint8Array }} [checkpoint]
 * @property {number} [anchoredAt]
 * @property {string} [shard]
 * @property {boolean} [shardPinned]
 */

/** @param {boolean} ok @param {string} why */
function must(ok, why) {
  if (!ok) throw new AnchorError(why);
}

/** @param {string} text @param {string} name @param {Uint8Array} key @param {string} what */
async function note(text, name, key, what) {
  try {
    return parseCheckpoint(await verifyNote(text, name, key));
  } catch (e) {
    throw new AnchorError(`${what}: ${/** @type {Error} */ (e).message}`);
  }
}

/**
 * Checks one anchor file. Throws AnchorError on any contradiction; returns
 * `{ status: "unknown-kind" }` for a kind this verifier does not know (a WAIT, never a
 * failure).
 * @param {string} text the file
 * @param {{ logName: string, logKey: Uint8Array, shards: readonly { origin: string, publicKey: string }[], now?: number }} ctx
 * @returns {Promise<Anchor>}
 */
export async function checkAnchor(text, ctx) {
  /** @type {any} */
  let a;
  try {
    a = JSON.parse(text);
  } catch {
    throw new AnchorError("anchor is not JSON");
  }
  must(a && typeof a === "object", "anchor is not an object");
  if (a.kind !== ANCHOR_KIND) return { status: "unknown-kind" };
  must(typeof a.note === "string", "anchor has no note");
  const checkpoint = await note(a.note, ctx.logName, ctx.logKey, "log checkpoint");
  must(Number.isSafeInteger(a.anchoredAt) && a.anchoredAt > 0, "anchoredAt is not a positive integer");
  const now = ctx.now ?? Math.floor(Date.now() / 1000);
  must(a.anchoredAt <= now + CLOCK_SKEW_S, "anchoredAt is in the future");

  const r = a.rekor;
  must(r && typeof r.origin === "string" && typeof r.anchorSig === "string" && typeof r.entry === "string", "anchor has no Rekor entry");
  const noteBytes = utf8(a.note);
  const sig = fromBase64(r.anchorSig);
  must(sig.length === 64, "anchorSig is not 64 bytes");
  must(ed25519ph.verify(sig, noteBytes, ctx.logKey), "anchorSig is not an Ed25519ph signature of the note by the log key");

  const entryBytes = fromBase64(r.entry);
  /** @type {any} */
  let entry;
  try {
    entry = JSON.parse(decodeUtf8(entryBytes));
  } catch {
    throw new AnchorError("entry is not JSON");
  }
  const spec = entry?.spec?.hashedRekordV002;
  must(entry?.kind === "hashedrekord" && entry?.apiVersion === "0.0.2" && spec, "entry is not a hashedrekord v0.0.2");
  must(spec.data?.algorithm === "SHA2_512", "entry digest is not SHA2_512");
  must(equalBytes(fromBase64(spec.data.digest), await sha512(noteBytes)), "entry digest is not the note's");
  must(equalBytes(fromBase64(spec.signature?.content ?? ""), sig), "entry signature is not anchorSig");
  must(spec.signature?.verifier?.keyDetails === "PKIX_ED25519_PH", "entry key is not PKIX_ED25519_PH");
  must(equalBytes(fromBase64(spec.signature.verifier.publicKey?.rawBytes ?? ""), concat(SPKI_ED25519, ctx.logKey)), "entry key is not the log key");

  const shard = ctx.shards.find((s) => s.origin === r.origin);
  if (shard) {
    const p = r.inclusionProof;
    must(p && typeof p.checkpoint === "string" && Array.isArray(p.hashes), "anchor has no inclusion proof");
    const shardCheckpoint = await note(p.checkpoint, shard.origin, fromBase64(shard.publicKey), "shard checkpoint");
    must(shardCheckpoint.origin === shard.origin, "shard checkpoint names another origin");
    const index = Number(p.logIndex);
    must(Number.isSafeInteger(index) && String(index) === String(p.logIndex), "inclusion proof index is not an integer");
    try {
      await verifyInclusion(index, shardCheckpoint.size, await leafHash(entryBytes), p.hashes.map(fromBase64), shardCheckpoint.root);
    } catch (e) {
      throw new AnchorError(`entry is not in the shard: ${/** @type {Error} */ (e).message}`);
    }
  }
  return { status: "ok", note: a.note, checkpoint, anchoredAt: a.anchoredAt, shard: r.origin, shardPinned: Boolean(shard) };
}

/**
 * The anchor file a publisher writes from a Rekor v2 TransparencyLogEntry.
 * @param {string} note @param {number} anchoredAt @param {string} shard @param {string} anchorSig @param {any} tle
 */
export function anchorFile(note, anchoredAt, shard, anchorSig, tle) {
  const p = tle.inclusionProof;
  return JSON.stringify({
    kind: ANCHOR_KIND,
    note,
    anchoredAt,
    rekor: { origin: shard, logIndex: Number(tle.logIndex), anchorSig, entry: tle.canonicalizedBody, inclusionProof: { logIndex: p.logIndex, treeSize: p.treeSize, rootHash: p.rootHash, hashes: p.hashes, checkpoint: p.checkpoint.envelope } },
  });
}
