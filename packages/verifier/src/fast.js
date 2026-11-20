// SPDX-License-Identifier: Apache-2.0
// The default run: seconds, tens of kilobytes. Reads the generations, the anchors since
// the last pin and the current checkpoint, checks them against Rekor, the mirror's
// history and the pinned state through hash tiles, and pins the newest anchor.

import { consistencyProof, decodeLeaf, equalBytes, fromBase64, OP, parseCheckpoint, subtreeFromTiles, tileWidth, toBase64, toHex, treeRoot, verifyConsistency, verifyNote } from "@emojery/shared/core";
import { AnchorError, checkAnchor } from "./anchor.js";
import { canonicalJwk, checkJwkFile, modulusHash } from "./enroll.js";
import { entries, generations, readTile } from "./log.js";
import { logKeyAt, providerFor, REKOR_SHARDS } from "./pins.js";
import { text } from "./source.js";

const DAY_S = 24 * 3600;
const WITHHELD_AFTER_S = 7 * DAY_S;
const UNWITNESSED_FOR_S = 7 * DAY_S;
const MAX_CHAIN = 256;

/**
 * @typedef {object} Ctx
 * @property {string} logName
 * @property {import("./pins.js").LogPins} pins
 * @property {{ get: (p: string) => Promise<import("./source.js").ReadResult> }} bucket
 * @property {{ get: (p: string) => Promise<import("./source.js").ReadResult> }} mirror
 * @property {import("./report.js").Report} report
 * @property {number} now Unix seconds
 * @property {(url: string) => Promise<any>} [getJson] for live provider JWKS
 * @property {readonly { origin: string, publicKey: string }[]} [shards] Rekor shard pins; default REKOR_SHARDS
 *
 * @typedef {import("./anchor.js").Anchor & { checkpoint: { origin: string, size: number, root: Uint8Array } }} GoodAnchor
 */

/** @param {import("./pins.js").LogPins} pins @param {number} size */
function keyFor(pins, size) {
  const k = logKeyAt(pins, size);
  if (!k) throw new Error(`no pinned log key covers size ${size}`);
  return fromBase64(k.publicKey);
}

/**
 * Reads `path` from the bucket, falling back to the mirror when the bucket does not
 * answer. Returns { text, from } | { missing: true } | { unavailable: true }.
 * @param {Ctx} ctx @param {string} path @param {boolean} [mirrorToo]
 */
async function readEither(ctx, path, mirrorToo = true) {
  const r = await ctx.bucket.get(path);
  if (r.ok) return { text: text(r), from: "bucket" };
  if (!mirrorToo) return r.missing ? { missing: true } : { unavailable: true };
  const m = await ctx.mirror.get(path);
  if (m.ok) return { text: text(m), from: "mirror" };
  if (r.missing) return { missing: true };
  return { unavailable: true };
}

/** The size an anchor file claims, before anything is verified. @param {string} fileText */
function claimedSize(fileText) {
  try {
    const n = JSON.parse(fileText).note;
    return parseCheckpoint(n.slice(0, n.indexOf("\n\n") + 1)).size;
  } catch {
    return 0;
  }
}

/** @param {Ctx} ctx @param {string} fileText @param {string} where @returns {Promise<import("./anchor.js").Anchor | null>} */
async function anchorOrFail(ctx, fileText, where) {
  try {
    return await checkAnchor(fileText, { logName: ctx.logName, logKey: keyFor(ctx.pins, claimedSize(fileText)), shards: ctx.shards ?? REKOR_SHARDS, now: ctx.now });
  } catch (e) {
    if (e instanceof AnchorError) ctx.report.fail(`${where}: ${e.message}`);
    else throw e;
    return null;
  }
}

/**
 * The anchors of one generation from its newest back along `prev`, newest first, down
 * to and including the first one at or below `stopAt`. Each must verify, be of this
 * origin, shrink in size and not grow in anchoredAt. `complete` is true when the walk
 * reached `stopAt` or the generation's first anchor, false when a read cut it short.
 * @param {Ctx} ctx @param {string} prefix @param {string} origin @param {import("./anchor.js").Anchor} newest @param {number} stopAt
 */
async function anchorChain(ctx, prefix, origin, newest, stopAt) {
  /** @type {import("./anchor.js").Anchor[]} */
  const chain = [newest];
  let cur = newest;
  for (let i = 0; i < MAX_CHAIN && cur.prev && /** @type {any} */ (cur.checkpoint).size > stopAt; i++) {
    const path = `${prefix}/anchors/${cur.prev}.json`;
    const r = await readEither(ctx, path);
    if (r.text === undefined) {
      if (r.missing) ctx.report.fail(`the anchor chain is broken: ${path} is named by a newer anchor and served by no one`);
      else ctx.report.warn(`not checked: ${path} could not be read`);
      return { chain, complete: false };
    }
    const a = await anchorOrFail(ctx, r.text, path);
    if (!a?.checkpoint) return { chain, complete: false };
    if (a.checkpoint.origin !== origin || a.checkpoint.size !== cur.prev) {
      ctx.report.fail(`${path} holds the checkpoint of ${a.checkpoint.origin} at ${a.checkpoint.size}`);
      return { chain, complete: false };
    }
    if (/** @type {number} */ (a.anchoredAt) > /** @type {number} */ (cur.anchoredAt)) ctx.report.fail(`${path} is dated after the anchor that follows it`);
    chain.push(a);
    cur = a;
  }
  return { chain, complete: !cur.prev || /** @type {any} */ (cur.checkpoint).size <= stopAt };
}

/**
 * @param {Ctx} ctx @param {import("./state.js").LogState | undefined} pinned
 * @returns {Promise<import("./state.js").LogState | undefined>} the state to save, undefined to keep the old one
 */
export async function fastCheck(ctx, pinned) {
  const { pins, report, logName } = ctx;
  if (pins.logKeys.length === 0) throw new Error(`no log key is pinned for ${logName} yet`);
  const newestKey = fromBase64(pins.logKeys[pins.logKeys.length - 1].publicKey);

  // 1. Generations; the mirror's records must be a prefix of the bucket's.
  const idxBucket = await ctx.bucket.get("index.json");
  const idxMirror = await ctx.mirror.get("index.json");
  let indexText = idxBucket.ok ? text(idxBucket) : idxMirror.ok ? text(idxMirror) : null;
  if (!idxBucket.ok && !idxBucket.missing) report.warn("index.json could not be read from the bucket");
  if (idxMirror.ok && idxBucket.ok) {
    const b = JSON.parse(text(idxBucket)).records ?? [];
    const m = JSON.parse(text(idxMirror)).records ?? [];
    if (m.length > b.length || m.some((r, i) => r.note !== b[i]?.note)) {
      report.fail("the bucket's index.json lacks a record the mirror holds: a rewind hidden from some readers");
      indexText = text(idxMirror);
    }
  } else if (idxMirror.ok && idxBucket.missing && (JSON.parse(text(idxMirror)).records ?? []).length > 0) {
    report.fail("the bucket serves no index.json while the mirror holds rewind records");
  }
  const gens = await generations(indexText, logName, newestKey);
  const cur = gens[gens.length - 1];
  const prefix = `g${cur.generation}`;

  // 2. The newest anchor, and the chain back to the pin.
  /** @type {GoodAnchor | null} */
  let anchor = null;
  /** @type {import("./anchor.js").Anchor[]} */
  let chain = [];
  const anchorRead = await readEither(ctx, `${prefix}/anchors/latest.json`);
  if (anchorRead.text !== undefined) {
    const a = await anchorOrFail(ctx, anchorRead.text, `${prefix}/anchors/latest.json`);
    if (a?.status === "unknown-kind") report.wait("the newest anchor is of a kind this verifier does not know; update the verifier");
    else if (a?.status === "future") report.note(`the newest anchor is dated ahead of this clock; it does not count`);
    else if (a?.status === "unpinned") report.note(`the newest anchor is in shard ${a.shard}, which this verifier does not pin; it does not count`);
    else if (a?.checkpoint && a.checkpoint.origin !== cur.origin) report.fail(`the newest anchor is for ${a.checkpoint.origin}, the current origin is ${cur.origin}`);
    else if (a?.checkpoint) {
      anchor = /** @type {GoodAnchor} */ (a);
      const stopAt = pinned?.origin === cur.origin ? pinned.size : 0;
      const walked = await anchorChain(ctx, prefix, cur.origin, a, stopAt);
      chain = walked.chain;
      if (pinned?.origin === cur.origin && pinned.size <= anchor.checkpoint.size) {
        const hit = chain.find((x) => x.checkpoint?.size === pinned.size);
        if (!hit && walked.complete) report.fail(`the pinned anchor ${pinned.size} is not on the chain of anchors`);
        if (hit?.checkpoint && !equalBytes(hit.checkpoint.root, fromBase64(pinned.root))) report.fail(`anchor ${pinned.size} now has another root than the one pinned`);
        if (hit && /** @type {number} */ (hit.anchoredAt) !== pinned.anchoredAt) report.fail(`anchor ${pinned.size} now has another anchoredAt than the one pinned`);
      }
    }
  } else if (anchorRead.unavailable) report.warn("not checked: the newest anchor could not be read");

  // 3. The current checkpoint.
  const cpRead = await readEither(ctx, `${prefix}/checkpoint`, false);
  /** @type {{ origin: string, size: number, root: Uint8Array } | null} */
  let cp = null;
  if (cpRead.text !== undefined) {
    try {
      const head = parseCheckpoint(cpRead.text.slice(0, cpRead.text.indexOf("\n\n") + 1));
      cp = parseCheckpoint(await verifyNote(cpRead.text, logName, keyFor(pins, head.size)));
    } catch (e) {
      report.fail(`the current checkpoint does not verify: ${/** @type {Error} */ (e).message}`);
    }
    if (cp && cp.origin !== cur.origin) {
      report.fail(`the current checkpoint is for ${cp.origin}, index.json says ${cur.origin}`);
      cp = null;
    }
  } else report.warn("not checked: the current checkpoint could not be read from the bucket; using the newest anchor");
  if (!cp && anchor) cp = anchor.checkpoint;
  if (!cp) {
    if (!report.failures.length) report.note("the log has no checkpoint yet");
    return undefined;
  }
  if (anchor && cp.size < anchor.checkpoint.size) {
    report.wait(`the bucket serves checkpoint ${cp.size}, older than anchor ${anchor.checkpoint.size} (a stale cache)`);
    cp = anchor.checkpoint;
  }

  // 4. Hash tiles of the current tree: its root, the chain of anchors, the pin.
  const subtree = tileSubtree(ctx, gens, cp.size);
  const tilesOk = await tileCheck(ctx, async () => {
    if (!equalBytes(await treeRoot(cp.size, subtree), cp.root)) throw new TileContradiction(`hash tiles do not add up to the root of checkpoint ${cp.size}`);
    let next = cp;
    for (const a of chain) {
      if (a.checkpoint && a.checkpoint.size > 0) await consistent(subtree, a.checkpoint, next, `anchor ${a.checkpoint.size} and checkpoint ${next.size}`);
      if (a.checkpoint) next = a.checkpoint;
    }
    if (pinned?.origin === cur.origin && pinned.size > 0 && pinned.size <= next.size) await consistent(subtree, { size: pinned.size, root: fromBase64(pinned.root) }, next, "the pinned checkpoint and the anchors since");
  }, anchor);

  // 5. The mirror's history of anchors.
  if (anchor) await mirrorCheck(ctx, prefix, anchor, /** @type {number} */ (chain[chain.length - 1].anchoredAt), subtree, cp);
  else {
    const m = await ctx.mirror.get(`${prefix}/anchors/latest.json`);
    if (!m.ok && !m.missing) report.wait("the mirror could not be read");
  }

  // 6. Closed generations.
  for (const g of gens.slice(0, -1)) await closedGeneration(ctx, gens, g, subtree, cp, pinned);

  // 7. The pinned state.
  if (pinned && tilesOk && pinned.origin === cur.origin && anchor && pinned.size > anchor.checkpoint.size) {
    report.wait(`the newest anchor (${anchor.checkpoint.size}) is older than the pinned checkpoint (${pinned.size})`);
    if (pinned.size <= cp.size) await tileCheck(ctx, () => consistent(subtree, anchor.checkpoint, { size: pinned.size, root: fromBase64(pinned.root) }, "the newest anchor and the pinned checkpoint"), anchor);
  } else if (pinned && pinned.origin !== cur.origin && !gens.some((g) => g.origin === pinned.origin)) {
    report.fail(`the pinned origin ${pinned.origin} is neither current nor closed by a rewind record`);
  }

  // 8. Provider keys of the ENROLLs anchored since the pin.
  if (anchor && tilesOk) {
    const from = pinned?.origin === cur.origin ? Math.min(pinned.size, anchor.checkpoint.size) : 0;
    await newEnrollKeys(ctx, gens, chain, from, anchor.checkpoint.size);
  }

  // 9. The unanchored tail.
  const anchoredSize = anchor?.checkpoint.size ?? 0;
  /** @type {{ size: number, firstSeen: number } | null} */
  let tail = null;
  if (cp.size > anchoredSize) {
    const prev = pinned?.origin === cur.origin ? pinned.tail : null;
    tail = prev && prev.size > anchoredSize ? prev : { size: cp.size, firstSeen: ctx.now };
    if (ctx.now - tail.firstSeen > 2 * pins.anchorIntervalS) report.wait(`leaves past ${anchoredSize} have been published without an anchor for more than two anchor intervals`);
    else report.note(`${cp.size - anchoredSize} leaves are published and not anchored yet`);
  }

  if (report.failures.length) return undefined;
  if (!anchor) return pinned ? { ...pinned, tail } : undefined;
  if (pinned?.origin === cur.origin && pinned.size > anchor.checkpoint.size) return { ...pinned, tail };
  return { origin: cur.origin, size: anchor.checkpoint.size, root: toBase64(anchor.checkpoint.root), anchoredAt: /** @type {number} */ (anchor.anchoredAt), tail };
}

class TileContradiction extends Error {}
class TileWithheld extends Error {}
class TileUnreadable extends Error {}

/** @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {number} size */
function tileSubtree(ctx, gens, size) {
  let servedAny = false;
  return subtreeFromTiles(size, async (level, index, width) => {
    const r = await readTile(ctx.bucket, gens, "hash", level, index, width);
    if (r.ok) {
      servedAny = true;
      return r.bytes;
    }
    if (r.missing && servedAny) throw new TileWithheld(r.path);
    throw new TileUnreadable(r.path);
  });
}

/**
 * Runs a check over tiles and sorts its failure: a contradiction fails the run, a tile
 * the bucket withholds while serving its neighbours fails it once the anchor over it is a
 * week old, anything unreadable is a note.
 * @param {Ctx} ctx @param {() => Promise<void>} fn @param {import("./anchor.js").Anchor | null} anchor
 */
async function tileCheck(ctx, fn, anchor) {
  try {
    await fn();
    return true;
  } catch (e) {
    const err = /** @type {Error} */ (e);
    if (err instanceof TileWithheld) {
      if (anchor?.anchoredAt && ctx.now - anchor.anchoredAt > WITHHELD_AFTER_S) ctx.report.fail(`data withheld: ${err.message} is not served while its neighbours are, under an anchor older than 7 days`);
      else ctx.report.warn(`not checked: ${err.message} is not served`);
    } else if (err instanceof TileUnreadable) ctx.report.warn(`not checked: ${err.message} could not be read`);
    else ctx.report.fail(err.message);
    return false;
  }
}

/**
 * @param {import("@emojery/shared/core").SubtreeHash} subtree
 * @param {{ size: number, root: Uint8Array }} a @param {{ size: number, root: Uint8Array }} b @param {string} what
 */
async function consistent(subtree, a, b, what) {
  try {
    await verifyConsistency(a.size, b.size, await consistencyProof(a.size, b.size, subtree), a.root, b.root);
  } catch (e) {
    if (e instanceof TileWithheld || e instanceof TileUnreadable) throw e;
    throw new TileContradiction(`${what} are not consistent: ${/** @type {Error} */ (e).message}`);
  }
}

/**
 * @param {Ctx} ctx @param {string} prefix @param {GoodAnchor} anchor @param {number} oldestUnseen anchoredAt of the oldest anchor walked
 * @param {import("@emojery/shared/core").SubtreeHash} subtree @param {{ size: number }} cp
 */
async function mirrorCheck(ctx, prefix, anchor, oldestUnseen, subtree, cp) {
  const s = anchor.checkpoint;
  const latest = await ctx.mirror.get(`${prefix}/anchors/latest.json`);
  if (!latest.ok) {
    if (!latest.missing) ctx.report.wait("the mirror could not be read: the anchor is not checked against the shared history");
    else if (ctx.now - oldestUnseen > 4 * ctx.pins.anchorIntervalS) ctx.report.wait(`the mirror still holds no anchor of ${s.origin}`);
    else ctx.report.warn(`the mirror holds no anchor of ${s.origin} yet`);
    return;
  }
  const L = await anchorOrFail(ctx, text(latest), `mirror ${prefix}/anchors/latest.json`);
  if (!L?.checkpoint) return;
  const same = await ctx.mirror.get(`${prefix}/anchors/${s.size}.json`);
  if (same.ok) {
    const m = await anchorOrFail(ctx, text(same), `mirror ${prefix}/anchors/${s.size}.json`);
    if (m?.checkpoint && !equalBytes(m.checkpoint.root, s.root)) ctx.report.fail(`the mirror holds anchor ${s.size} with another root: a split view`);
    else if (m?.note !== anchor.note) ctx.report.fail(`the mirror holds another anchor file for size ${s.size}`);
    return;
  }
  if (L.checkpoint.size < s.size) {
    const behind = /** @type {number} */ (anchor.anchoredAt) - /** @type {number} */ (L.anchoredAt);
    if (behind > 4 * ctx.pins.anchorIntervalS) ctx.report.wait(`the mirror is ${behind} s behind the bucket's newest anchor: anchors above ${L.checkpoint.size} are not in the shared history yet`);
    else ctx.report.warn(`the mirror lags: its newest anchor is ${L.checkpoint.size}, the bucket's is ${s.size}`);
    if (s.size <= cp.size) await tileCheck(ctx, () => consistent(subtree, L.checkpoint, s, "the mirror's newest anchor and the bucket's"), anchor);
    return;
  }
  const gap = /** @type {number} */ (L.anchoredAt) - /** @type {number} */ (anchor.anchoredAt);
  if (gap >= 2 * ctx.pins.anchorIntervalS) ctx.report.fail(`anchor ${s.size} is missing from the mirror, whose newest anchor ${L.checkpoint.size} is ${gap} s newer: an anchor kept out of the shared history`);
  else ctx.report.warn(`anchor ${s.size} is not in the mirror yet`);
}

/**
 * A rewind drops leaves and never rewrites them: the closed generation's tree runs from
 * (N, rootN) to (M, rootM), its anchors agree with that, and the new tree starts at rootN.
 * @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {import("./log.js").Generation} g
 * @param {import("@emojery/shared/core").SubtreeHash} subtree @param {{ size: number, root: Uint8Array }} cp
 * @param {import("./state.js").LogState | undefined} pinned
 */
async function closedGeneration(ctx, gens, g, subtree, cp, pinned) {
  const r = g.rewind;
  const prefix = `g${g.generation}`;
  if (r.n <= cp.size) {
    await tileCheck(ctx, async () => {
      if (!equalBytes(await treeRoot(r.n, subtree), r.rootN)) throw new TileContradiction(`the rewind that closed ${g.origin} names rootN that is not the current tree at ${r.n}`);
    }, null);
  }
  // The closed generation as it stood at M, from its own tiles.
  const closed = gens.slice(0, gens.indexOf(g) + 1).map((x, i, a) => (i === a.length - 1 ? { ...x, end: null } : x));
  const old = tileSubtree(ctx, closed, r.m);
  await tileCheck(ctx, async () => {
    if (!equalBytes(await treeRoot(r.m, old), r.rootM)) throw new TileContradiction(`the closed ${g.origin} tiles do not add up to rootM at ${r.m}`);
    if (r.n > 0) await consistent(old, { size: r.n, root: r.rootN }, { size: r.m, root: r.rootM }, `rootN and rootM of the rewind that closed ${g.origin}`);
  }, null);
  let anchored = null;
  const last = await ctx.mirror.get(`${prefix}/anchors/latest.json`);
  if (last.ok) anchored = await anchorOrFail(ctx, text(last), `mirror ${prefix}/anchors/latest.json`);
  const a = anchored?.checkpoint;
  if (a && a.size <= r.m) {
    await tileCheck(ctx, async () => {
      if (a.size <= r.n) await consistent(old, a, { size: r.n, root: r.rootN }, `the last anchor of ${g.origin} and rootN`);
      else await consistent(old, a, { size: r.m, root: r.rootM }, `the last anchor of ${g.origin} and rootM`);
    }, null);
  }
  const known = Math.max(a?.size ?? 0, pinned?.origin === g.origin ? pinned.size : 0);
  if (r.m < known) ctx.report.fail(`the rewind that closed ${g.origin} says M = ${r.m}, below size ${known} that ${g.origin} reached`);
  const dropped = r.m - r.n;
  const droppedAnchored = Math.max(0, (a?.size ?? 0) - r.n);
  ctx.report.note(`${g.origin} closed on ${new Date(r.at).toISOString().slice(0, 10)} at size ${r.n} (${r.reason}); ${dropped} later entries were not carried over, ${droppedAnchored} of them anchored`);
  if (dropped > 0) ctx.report.warn(`a rewind dropped ${dropped} published entries of ${g.origin}, ${droppedAnchored} of them anchored`);
}

/**
 * Checks that every ENROLL in [from, to) names an admitted provider and a provider key a
 * witness has seen.
 * @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {import("./anchor.js").Anchor[]} chain
 * @param {number} from @param {number} to
 */
async function newEnrollKeys(ctx, gens, chain, from, to) {
  for (let b = Math.floor(from / 256); b * 256 < to; b++) {
    const width = tileWidth(0, b, to);
    const r = await readTile(ctx.bucket, gens, "entries", 0, b, width);
    if (!r.ok) {
      ctx.report.warn(`not checked: ${r.path} could not be read`);
      continue;
    }
    let leaves;
    try {
      leaves = entries(r, width);
    } catch (e) {
      ctx.report.fail(`${r.path}: ${/** @type {Error} */ (e).message}`);
      continue;
    }
    for (let i = 0; i < leaves.length; i++) {
      const seq = b * 256 + i;
      if (seq < from) continue;
      let leaf;
      try {
        leaf = decodeLeaf(leaves[i]);
      } catch (e) {
        ctx.report.fail(`leaf ${seq}: ${/** @type {Error} */ (e).message}`);
        continue;
      }
      if (leaf.op !== OP.ENROLL) continue;
      const provider = providerFor(ctx.pins, leaf.iss, leaf.aud);
      if (!provider) {
        ctx.report.fail(`leaf ${seq}: ENROLL from iss ${leaf.iss} and aud ${leaf.aud}, which this log does not admit`);
        continue;
      }
      // The first anchor over the leaf: the smallest anchor of the chain above seq.
      let first = null;
      for (const a of chain) if (a.checkpoint && a.checkpoint.size > seq) first = a;
      await providerKey(ctx, gens, seq, provider, leaf.modulusHash, /** @type {number | undefined} */ (first?.anchoredAt));
    }
  }
}

/**
 * Where the modulus `hash` of `provider` is witnessed (§10), or null after reporting.
 * @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {number} seq
 * @param {import("./pins.js").Provider} provider @param {Uint8Array} hash @param {number} [firstAnchoredAt]
 */
export async function providerKey(ctx, gens, seq, provider, hash, firstAnchoredAt) {
  const name = `${provider.id}/${toHex(hash)}.json`;
  const witnessed = await ctx.mirror.get(`jwks/${name}`);
  if (witnessed.ok) {
    try {
      await checkJwkFile(text(witnessed), hash);
      return "mirror";
    } catch (e) {
      ctx.report.fail(`mirror jwks/${name}: ${/** @type {Error} */ (e).message}`);
      return null;
    }
  }
  if (ctx.getJson) {
    try {
      const live = await ctx.getJson(provider.jwksUri);
      for (const k of live?.keys ?? []) {
        try {
          if (equalBytes(await modulusHash(canonicalJwk(k).modulus), hash)) return "live";
        } catch {}
      }
    } catch {}
  }
  const own = await ctx.bucket.get(`g${gens[gens.length - 1].generation}/jwks/${name}`);
  if (own.ok) {
    try {
      await checkJwkFile(text(own), hash);
    } catch (e) {
      ctx.report.fail(`jwks/${name}: ${/** @type {Error} */ (e).message}`);
      return null;
    }
    if (firstAnchoredAt !== undefined && ctx.now - firstAnchoredAt > UNWITNESSED_FOR_S) {
      ctx.report.fail(`leaf ${seq}: provider key ${name} is still witnessed by no one a week after the ENROLL was anchored`);
      return null;
    }
    ctx.report.warn(`leaf ${seq}: provider key ${name} is not witnessed yet: it is only in the publisher's own files`);
    return "bucket";
  }
  if (!witnessed.missing || !own.missing) {
    ctx.report.warn(`not checked: provider key ${name} of leaf ${seq} could not be read`);
    return null;
  }
  ctx.report.fail(`leaf ${seq}: ENROLL names provider key ${name}, which no witness and no file holds`);
  return null;
}

/**
 * Every anchor of the current generation, newest first, walked along prev to the first.
 * @param {Ctx} ctx @param {string} prefix @param {string} origin
 */
export async function allAnchors(ctx, prefix, origin) {
  const r = await readEither(ctx, `${prefix}/anchors/latest.json`);
  if (r.text === undefined) return [];
  const a = await anchorOrFail(ctx, r.text, `${prefix}/anchors/latest.json`);
  if (!a?.checkpoint) return [];
  return (await anchorChain(ctx, prefix, origin, a, 0)).chain;
}
