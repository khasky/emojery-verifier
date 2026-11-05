// SPDX-License-Identifier: Apache-2.0
// --full: replay the log from the first entry. Every bundle, every leaf through the fold
// (signatures, ENROLL proofs and provider keys, pairs), the hash tiles rebuilt from the
// leaves and compared with the published ones, the root against the checkpoint.

import { buildHashTiles, equalBytes, Fold, FoldError, fromBase64, fromHex, leafHash, sha256, subtreeFromLeafHashes, tileWidth, toBase64, toHex, treeRoot } from "@emojery/shared/core";
import { canonicalJwk, checkJwkFile, enrollPublicInputs, modulusHash, proofChecker, verificationKey } from "./enroll.js";
import { allAnchors, fastCheck, providerKey } from "./fast.js";
import { entries, generations, originAt, prefixFor, readTile } from "./log.js";
import { providerFor } from "./pins.js";
import { text } from "./source.js";

/**
 * @param {import("./fast.js").Ctx & { checkProofs?: boolean }} ctx
 * @param {import("./state.js").LogState | undefined} pinned
 */
export async function fullCheck(ctx, pinned) {
  const state = await fastCheck(ctx, pinned);
  const { report, pins } = ctx;
  if (report.failures.length) return state;
  const idx = await ctx.bucket.get("index.json");
  const gens = await generations(idx.ok ? text(idx) : null, ctx.logName, fromBase64(pins.logKeys[pins.logKeys.length - 1].publicKey));
  const prefix = `g${gens[gens.length - 1].generation}`;
  const cpRead = await ctx.bucket.get(`${prefix}/checkpoint`);
  if (!cpRead.ok) {
    report.warn("not checked: --full needs the current checkpoint");
    return state;
  }
  const size = Number(text(cpRead).split("\n")[1]);

  /** @type {Awaited<ReturnType<typeof proofChecker>> | null} */
  let prover = null;
  const checkProofs = ctx.checkProofs !== false;
  const salt = fromHex(pins.saltCommitment || "00".repeat(32));
  const fold = new Fold({
    logName: ctx.logName,
    originAt: (seq) => originAt(gens, seq),
    checkEnroll: async (leaf, seq) => {
      const provider = providerFor(pins, leaf.iss, leaf.aud);
      if (!provider) throw new Error(`iss ${leaf.iss} with aud ${leaf.aud} is not admitted in this log`);
      const where = await providerKey(ctx, gens, seq, provider, leaf.modulusHash);
      if (!checkProofs) return;
      const proofPath = `${prefixFor(gens, seq)}/proofs/${seq}`;
      const proof = await ctx.bucket.get(proofPath);
      if (!proof.ok) {
        report.warn(`not checked: ${proofPath} could not be read`);
        return;
      }
      if (!equalBytes(await sha256(proof.bytes), leaf.proofHash)) throw new Error(`${proofPath} does not hash to proof_hash`);
      if (!where) return;
      const modulus = await modulusFor(ctx, gens, provider, leaf.modulusHash);
      if (!modulus) return;
      const vkPin = pins.enroll[2];
      if (!vkPin) throw new Error("no verification key is pinned for ENROLL v2");
      prover ??= await proofChecker(await verificationKey(2, vkPin.vkSha256));
      const inputs = enrollPublicInputs({ modulus, iss: leaf.iss, aud: leaf.aud, nullifier: leaf.nullifier, saltCommitment: salt, accountPubkey: leaf.accountPubkey });
      if (!(await prover.verify(proof.bytes, inputs))) throw new Error("the ENROLL proof does not verify");
    },
  });

  /** @type {Uint8Array[]} */
  const hashes = [];
  try {
    for (let b = 0; b * 256 < size; b++) {
      const width = tileWidth(0, b, size);
      const r = await readTile(ctx.bucket, gens, "entries", 0, b, width);
      if (!r.ok) {
        report.warn(`not checked: ${r.path} could not be read; the replay stops at ${b * 256}`);
        return state;
      }
      for (const leaf of entries(r, width)) {
        hashes.push(await leafHash(leaf));
        try {
          await fold.apply(leaf);
        } catch (e) {
          if (e instanceof FoldError) report.fail(e.message);
          else throw e;
          return undefined;
        }
      }
    }
  } finally {
    await /** @type {any} */ (prover)?.close();
  }

  // The tree from the leaves, against the checkpoint and the published tiles.
  const root = await treeRoot(size, subtreeFromLeafHashes(hashes));
  const cpRoot = text(cpRead).split("\n")[2];
  if (toBase64(root) !== cpRoot) {
    report.fail(`the leaves do not hash to the checkpoint's root at ${size}`);
    return undefined;
  }
  for (const t of await buildHashTiles(hashes)) {
    const r = await readTile(ctx.bucket, gens, "hash", t.level, t.index, t.width);
    if (r.ok && !equalBytes(r.bytes, t.bytes)) report.fail(`${r.path} differs from the tile the leaves give`);
    else if (!r.ok) report.warn(`not checked: ${r.path} could not be read`);
  }
  const sub = subtreeFromLeafHashes(hashes);
  for (const a of await allAnchors(ctx, prefix, gens[gens.length - 1].origin)) {
    const c = /** @type {NonNullable<typeof a.checkpoint>} */ (a.checkpoint);
    if (c.size <= size && !equalBytes(await treeRoot(c.size, sub), c.root)) report.fail(`anchor ${c.size} names a root the leaves do not give`);
  }
  let enrolls = 0;
  for (const e of fold.enrolls.values()) if (e) enrolls++;
  report.note(`replayed ${size} leaves: ${enrolls} ENROLL, ${fold.accounts.size} pseudonyms, ${fold.counts.size} targets with reactions`);
  return report.failures.length ? undefined : state;
}

/**
 * The modulus bytes of a provider key the fold already found witnessed.
 * @param {import("./fast.js").Ctx} ctx @param {import("./log.js").Generation[]} gens
 * @param {import("./pins.js").Provider} provider @param {Uint8Array} hash
 */
async function modulusFor(ctx, gens, provider, hash) {
  const name = `${provider.id}/${toHex(hash)}.json`;
  for (const get of [() => ctx.mirror.get(`jwks/${name}`), () => ctx.bucket.get(`g${gens[gens.length - 1].generation}/jwks/${name}`)]) {
    const r = await get();
    if (r.ok) return checkJwkFile(text(r), hash);
  }
  if (ctx.getJson) {
    const live = await ctx.getJson(provider.jwksUri).catch(() => null);
    for (const k of live?.keys ?? []) {
      try {
        const { modulus } = canonicalJwk(k);
        if (equalBytes(await modulusHash(modulus), hash)) return modulus;
      } catch {}
    }
  }
  return null;
}

