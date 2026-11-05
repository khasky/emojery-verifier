// SPDX-License-Identifier: Apache-2.0
// Runs without state: --leaf (one entry, from a receipt) and --target (one target's
// count against the API's). Both trust only an anchored checkpoint.

import { compareBytes, decodeLeaf, enrollHash, equalBytes, Fold, FoldError, fromBase64, fromHex, inclusionProof, leafHash, OP, parseCheckpoint, reactMessage, retireMessage, sha256, subtreeFromTiles, targetKey, tileWidth, toHex, utf8, verifyInclusion, verifyNote } from "@emojery/shared/core";
import { checkAnchor } from "./anchor.js";
import { checkJwkFile, enrollPublicInputs, proofChecker, verificationKey } from "./enroll.js";
import { providerKey } from "./fast.js";
import { entries, generations, originAt, prefixFor, readTile } from "./log.js";
import { logKeyAt, providerFor, REKOR_SHARDS } from "./pins.js";
import { text } from "./source.js";

/**
 * The generations and the newest anchored checkpoint, or null after reporting.
 * @param {import("./fast.js").Ctx} ctx
 */
async function anchored(ctx) {
  const key = fromBase64(ctx.pins.logKeys[ctx.pins.logKeys.length - 1].publicKey);
  const idx = await ctx.bucket.get("index.json");
  const gens = await generations(idx.ok ? text(idx) : null, ctx.logName, key);
  const prefix = `g${gens[gens.length - 1].generation}`;
  const r = await ctx.bucket.get(`${prefix}/anchors/latest.json`);
  const m = r.ok ? r : await ctx.mirror.get(`${prefix}/anchors/latest.json`);
  if (!m.ok) {
    ctx.report.wait("no anchor could be read");
    return null;
  }
  const a = await checkAnchor(text(m), { logName: ctx.logName, logKey: key, shards: ctx.shards ?? REKOR_SHARDS, now: ctx.now });
  if (a.status !== "ok" || !a.checkpoint) {
    ctx.report.wait(`the newest anchor does not count (${a.status})`);
    return null;
  }
  return { gens, anchor: /** @type {{ origin: string, size: number, root: Uint8Array }} */ (a.checkpoint) };
}

/**
 * Reads leaf `seq` and proves it is in the anchored tree of `size` leaves.
 * @param {import("./fast.js").Ctx} ctx @param {import("./log.js").Generation[]} gens
 * @param {{ size: number, root: Uint8Array }} cp @param {number} seq
 */
async function provenLeaf(ctx, gens, cp, seq) {
  const b = Math.floor(seq / 256);
  const width = tileWidth(0, b, cp.size);
  const r = await readTile(ctx.bucket, gens, "entries", 0, b, width);
  if (!r.ok) throw new Error(`${r.path} could not be read`);
  const bytes = entries(r, width)[seq % 256];
  const subtree = subtreeFromTiles(cp.size, async (level, index, w) => {
    const t = await readTile(ctx.bucket, gens, "hash", level, index, w);
    if (!t.ok) throw new Error(`${t.path} could not be read`);
    return t.bytes;
  });
  await verifyInclusion(seq, cp.size, await leafHash(bytes), await inclusionProof(seq, cp.size, subtree), cp.root);
  return { bytes, leaf: decodeLeaf(bytes) };
}

/**
 * --leaf: one entry, its inclusion in the newest anchored checkpoint, and what it means.
 * @param {import("./fast.js").Ctx & { checkProofs?: boolean }} ctx
 * @param {{ seq: number, pubkey?: Uint8Array, counter?: number }} q
 */
export async function leafCheck(ctx, q) {
  const { report } = ctx;
  const a = await anchored(ctx);
  if (!a) return;
  if (q.seq >= a.anchor.size) {
    report.wait(`leaf ${q.seq} is not anchored yet (the newest anchor covers ${a.anchor.size})`);
    return;
  }
  let found;
  try {
    found = await provenLeaf(ctx, a.gens, a.anchor, q.seq);
  } catch (e) {
    report.fail(`leaf ${q.seq}: ${/** @type {Error} */ (e).message}`);
    return;
  }
  const { leaf } = found;
  report.note(`leaf ${q.seq} is in ${a.anchor.origin} under the anchor at size ${a.anchor.size}`);
  /** The ENROLL a leaf points at, proven too. @param {bigint} s */
  const enrollAt = async (s) => {
    const e = await provenLeaf(ctx, a.gens, a.anchor, Number(s));
    if (e.leaf.op !== OP.ENROLL) throw new Error(`enroll_seq ${s} is not an ENROLL`);
    return { ...e, hash: await enrollHash(e.bytes) };
  };
  try {
    if (leaf.op === OP.REACT) {
      if (!q.pubkey) throw new Error("--pubkey is required for a REACT");
      const e = await enrollAt(leaf.enrollSeq);
      if (!equalBytes(e.leaf.accountPubkey, q.pubkey)) throw new Error("the REACT belongs to another device key");
      const msg = reactMessage({ origin: originAt(a.gens, q.seq), enrollHash: e.hash, site: leaf.site, targetId: leaf.targetId, reaction: leaf.reaction, prevReaction: leaf.prevReaction, counter: leaf.counter });
      const key = await crypto.subtle.importKey("raw", q.pubkey, { name: "Ed25519" }, false, ["verify"]);
      if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, leaf.sig, msg))) throw new Error("the signature does not verify under this key");
      if (q.counter !== undefined && q.counter !== leaf.counter) throw new Error(`the leaf carries counter ${leaf.counter}, the receipt ${q.counter}`);
      report.note(`REACT on ${leaf.site}/${leaf.targetId}: ${leaf.prevReaction || "(none)"} → ${leaf.reaction || "(none)"}, counter ${leaf.counter}`);
    } else if (leaf.op === OP.ENROLL) {
      if (q.pubkey && !equalBytes(leaf.accountPubkey, q.pubkey)) throw new Error("the ENROLL registers another device key");
      const provider = providerFor(ctx.pins, leaf.iss, leaf.aud);
      if (!provider) throw new Error(`iss ${leaf.iss} with aud ${leaf.aud} is not admitted in this log`);
      const where = await providerKey(ctx, a.gens, q.seq, provider, leaf.modulusHash);
      if (ctx.checkProofs !== false) {
        const path = `${prefixFor(a.gens, q.seq)}/proofs/${q.seq}`;
        const p = await ctx.bucket.get(path);
        if (!p.ok) throw new Error(`${path} could not be read`);
        if (!equalBytes(await sha256(p.bytes), leaf.proofHash)) throw new Error(`${path} does not hash to proof_hash`);
        const mod = await ctx.mirror.get(`jwks/${provider.id}/${toHex(leaf.modulusHash)}.json`);
        const own = mod.ok ? mod : await ctx.bucket.get(`${prefixFor(a.gens, q.seq)}/jwks/${provider.id}/${toHex(leaf.modulusHash)}.json`);
        if (own.ok && where) {
          const modulus = await checkJwkFile(text(own), leaf.modulusHash);
          const checker = await proofChecker(await verificationKey(2, ctx.pins.enroll[2].vkSha256));
          try {
            const ok = await checker.verify(p.bytes, enrollPublicInputs({ modulus, iss: leaf.iss, aud: leaf.aud, nullifier: leaf.nullifier, saltCommitment: fromHex(ctx.pins.saltCommitment), accountPubkey: leaf.accountPubkey }));
            if (!ok) throw new Error("the ENROLL proof does not verify");
          } finally {
            await checker.close();
          }
        } else report.warn("not checked: the provider key file could not be read, the proof was not verified");
      }
      report.note(`ENROLL through ${provider.id}; this checks one registration, not whether the account was deleted later (that is --full)`);
    } else if (leaf.op === OP.REVOKE) {
      if (q.pubkey) {
        const e = await enrollAt(leaf.enrollSeq);
        if (!equalBytes(e.leaf.accountPubkey, q.pubkey)) report.note("the REVOKE is not of this device key's registration");
      }
      report.note(`REVOKE: ${leaf.reasonCode}, decision ${toHex(leaf.caseId)}`);
    } else {
      const e = await enrollAt(leaf.enrollSeq);
      if (leaf.reason === "self") {
        const key = await crypto.subtle.importKey("raw", e.leaf.accountPubkey, { name: "Ed25519" }, false, ["verify"]);
        if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, leaf.sig, retireMessage(ctx.logName, e.hash)))) throw new Error("the RETIRE signature does not verify");
      }
      report.note(`RETIRE: ${leaf.reason}${leaf.caseId.length ? `, decision ${toHex(leaf.caseId)}` : ""}`);
    }
  } catch (e) {
    report.fail(`leaf ${q.seq}: ${/** @type {Error} */ (e).message}`);
  }
}

/**
 * --target: replay the log for the named targets and compare with the API at one size.
 * @param {import("./fast.js").Ctx & { fetchCounts: (site: string, targetId: string) => Promise<{ counts: Record<string, number>, total: number, size: number | null, origin: string | null }> }} ctx
 * @param {{ site: string, targetId: string }[]} targets
 */
export async function targetCheck(ctx, targets) {
  const { report } = ctx;
  const a = await anchored(ctx);
  if (!a) return;
  const prefix = `g${a.gens[a.gens.length - 1].generation}`;
  const cpRead = await ctx.bucket.get(`${prefix}/checkpoint`);
  if (!cpRead.ok) {
    report.wait("the current checkpoint could not be read");
    return;
  }
  const raw = text(cpRead);
  const head = parseCheckpoint(raw.slice(0, raw.indexOf("\n\n") + 1));
  const cpKey = logKeyAt(ctx.pins, head.size);
  if (!cpKey) throw new Error(`no pinned log key covers size ${head.size}`);
  const cp = parseCheckpoint(await verifyNote(raw, ctx.logName, fromBase64(cpKey.publicKey)));
  const answers = await Promise.all(targets.map((t) => ctx.fetchCounts(t.site, t.targetId)));
  const wanted = new Set(targets.map((t) => targetKey(t.site, t.targetId)));
  /** @type {Map<string, { reasons: Map<string, number>, cases: Set<string>, retired: number, retireCases: Set<string> }>} */
  const removals = new Map(targets.map((t) => [targetKey(t.site, t.targetId), { reasons: new Map(), cases: new Set(), retired: 0, retireCases: new Set() }]));
  const fold = new Fold({ logName: ctx.logName, originAt: (s) => originAt(a.gens, s), keepTarget: (s, t) => wanted.has(targetKey(s, t)) });
  const stopAt = Math.max(...answers.map((x) => x.size ?? cp.size));
  if (stopAt > cp.size) {
    report.wait(`the API answers at size ${stopAt}, beyond the checkpoint ${cp.size}; rerun later`);
    return;
  }
  /** @type {Map<number, { counts: any, total: number }>} */
  const snapshots = new Map();
  const sizes = new Set(answers.map((x) => x.size ?? cp.size));
  try {
    for (let b = 0; b * 256 < stopAt; b++) {
      const width = tileWidth(0, b, cp.size);
      const r = await readTile(ctx.bucket, a.gens, "entries", 0, b, width);
      if (!r.ok) {
        report.warn(`not checked: ${r.path} could not be read`);
        return;
      }
      for (const bytes of entries(r, width)) {
        if (fold.size >= stopAt) break;
        const leaf = decodeLeaf(bytes);
        if (leaf.op === OP.REVOKE || leaf.op === OP.RETIRE) {
          const e = fold.enrolls.get(Number(leaf.enrollSeq));
          const acc = e && fold.accounts.get(e.nullifier);
          for (const [k, pair] of acc?.pairs ?? []) {
            const st = removals.get(k);
            if (!st || pair.reaction === "") continue;
            if (leaf.op === OP.REVOKE) {
              st.reasons.set(leaf.reasonCode, (st.reasons.get(leaf.reasonCode) ?? 0) + 1);
              st.cases.add(toHex(leaf.caseId));
            } else if (leaf.reason !== "self") {
              st.retired++;
              st.retireCases.add(toHex(leaf.caseId));
            }
          }
        }
        await fold.apply(bytes);
        if (sizes.has(fold.size)) snapshots.set(fold.size, Object.fromEntries(targets.map((t) => [targetKey(t.site, t.targetId), fold.targetCounts(t.site, t.targetId)])));
      }
    }
  } catch (e) {
    if (e instanceof FoldError) report.fail(e.message);
    else throw e;
    return;
  }
  for (const [i, t] of targets.entries()) {
    const ans = answers[i];
    const key = targetKey(t.site, t.targetId);
    const at = ans.size ?? cp.size;
    if (ans.size === null) report.warn(`${t.site}/${t.targetId}: the API answer names no log size; compared at ${cp.size}`);
    if (ans.origin !== null && ans.origin !== a.anchor.origin) {
      report.fail(`${t.site}/${t.targetId}: the API counts ${ans.origin}, the log is ${a.anchor.origin}`);
      continue;
    }
    const mine = at === 0 ? { top: [], total: 0 } : snapshots.get(at)?.[key];
    if (!mine) {
      report.warn(`${t.site}/${t.targetId}: no fold at size ${at}`);
      continue;
    }
    const served = Object.entries(ans.counts).sort((x, y) => y[1] - x[1] || compareBytes(utf8(x[0]), utf8(y[0])));
    const same = mine.total === ans.total && served.length === mine.top.length && served.every(([r, n], j) => mine.top[j][0] === r && mine.top[j][1] === n);
    if (!same) report.fail(`${t.site}/${t.targetId} at size ${at}: the API serves ${JSON.stringify(ans.counts)} total ${ans.total}, the log gives ${JSON.stringify(Object.fromEntries(mine.top))} total ${mine.total}`);
    else report.note(`${t.site}/${t.targetId} at size ${at}: ${mine.total} reactions, the API agrees`);
    const st = /** @type {NonNullable<ReturnType<typeof removals.get>>} */ (removals.get(key));
    const revoked = [...st.reasons].map(([r, n]) => `${r} ${n}`).join(", ");
    if (revoked) report.note(`${t.site}/${t.targetId}: revoked ${revoked} in ${st.cases.size} decision(s)`);
    if (st.retired) report.note(`${t.site}/${t.targetId}: ${st.retired} pair(s) emptied by operator deletions in ${st.retireCases.size} decision(s)`);
  }
}
