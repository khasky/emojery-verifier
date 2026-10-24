// SPDX-License-Identifier: Apache-2.0
// The default run: seconds, tens of kilobytes. Reads the generations, the newest anchor
// and the current checkpoint, checks them against Rekor, the mirror's history and the
// pinned state through hash tiles, and pins the new anchored checkpoint.

import { consistencyProof, decodeLeaf, equalBytes, fromBase64, OP, parseCheckpoint, subtreeFromTiles, tileWidth, toBase64, toHex, treeRoot, verifyConsistency, verifyNote } from "@emojery/shared/core";
import { AnchorError, checkAnchor } from "./anchor.js";
import { canonicalJwk, checkJwkFile, modulusHash } from "./enroll.js";
import { entries, generations, readTile } from "./log.js";
import { logKeyAt, providerFor, REKOR_SHARDS } from "./pins.js";
import { text } from "./source.js";

const WITHHELD_AFTER_S = 7 * 24 * 3600;

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
 */

/** @param {import("./pins.js").LogPins} pins @param {number} size */
function keyFor(pins, size) {
  const k = logKeyAt(pins, size);
  if (!k) throw new Error(`no pinned log key covers size ${size}`);
  return fromBase64(k.publicKey);
}

/**
 * Reads `path` from the bucket, falling back to the mirror when the bucket does not
 * answer. Returns { text } | { missing: true } | { unavailable: true }.
 * @param {Ctx} ctx @param {string} path @param {boolean} [mirrorToo]
 */
async function readEither(ctx, path, mirrorToo = true) {
  const r = await ctx.bucket.get(path);
  if (r.ok) return { text: text(r), from: "bucket" };
  if (!mirrorToo) return r.missing ? { missing: true } : { unavailable: true };
  const m = await ctx.mirror.get(path);
  if (m.ok) return { text: text(m), from: "mirror" };
  if (r.missing && (m.missing || !m.ok)) return { missing: true };
  return { unavailable: true };
}

/**
 * @param {Ctx} ctx @param {import("./state.js").LogState | undefined} pinned
 * @returns {Promise<import("./state.js").LogState | undefined>} the state to save, undefined to keep the old one
 */
export async function fastCheck(ctx, pinned) {
  const { pins, report, logName } = ctx;
  if (pins.logKeys.length === 0) throw new Error(`no log key is pinned for ${logName} yet`);
  const newestKey = fromBase64(pins.logKeys[pins.logKeys.length - 1].publicKey);

  // 1. Generations.
  const idx = await readEither(ctx, "index.json");
  if (idx.unavailable) report.warn("not checked: index.json could not be read; assuming no rewind");
  const gens = await generations(idx.text ?? null, logName, newestKey);
  const cur = gens[gens.length - 1];
  const prefix = `g${cur.generation}`;

  // 2. The newest anchor.
  const anchorRead = await readEither(ctx, `${prefix}/anchors/latest.json`);
  /** @type {import("./anchor.js").Anchor | null} */
  let anchor = null;
  if (anchorRead.text !== undefined) {
    anchor = await anchorOrFail(ctx, anchorRead.text, `${prefix}/anchors/latest.json`);
    if (anchor?.status === "unknown-kind") {
      report.wait("the newest anchor is of a kind this verifier does not know; update the verifier");
      anchor = null;
    } else if (anchor && anchor.checkpoint?.origin !== cur.origin) {
      report.fail(`the newest anchor is for ${anchor.checkpoint?.origin}, the current origin is ${cur.origin}`);
      anchor = null;
    }
  } else if (anchorRead.unavailable) report.warn("not checked: the newest anchor could not be read");
  if (anchor && !anchor.shardPinned) report.warn(`anchor not verified in Rekor: shard ${anchor.shard} is not pinned in this verifier`);

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
  if (!cp && anchor?.checkpoint) cp = anchor.checkpoint;
  if (!cp) {
    if (!anchor && !report.failures.length) report.note("the log has no checkpoint yet");
    return undefined;
  }
  if (anchor?.checkpoint && cp.size < anchor.checkpoint.size) {
    report.wait(`the bucket serves checkpoint ${cp.size}, older than anchor ${anchor.checkpoint.size} (a stale cache)`);
    cp = anchor.checkpoint;
  }

  // 4. Hash tiles of the current tree: root, then consistency with the anchor and the pin.
  const subtree = tileSubtree(ctx, gens, cp.size);
  const tilesOk = await tileCheck(ctx, async () => {
    if (!equalBytes(await treeRoot(cp.size, subtree), cp.root)) throw new TileContradiction(`hash tiles do not add up to the root of checkpoint ${cp.size}`);
    if (anchor?.checkpoint && anchor.checkpoint.size > 0) await consistent(subtree, anchor.checkpoint, cp, "the newest anchor and the current checkpoint");
  }, anchor);

  // 5. The mirror's history of anchors.
  if (anchor?.checkpoint) await mirrorCheck(ctx, prefix, anchor, subtree, cp);

  // 6. Closed generations.
  for (const g of gens.slice(0, -1)) await closedGeneration(ctx, gens, g, subtree, cp, pinned);

  // 7. The pinned state.
  if (pinned && tilesOk) {
    if (pinned.origin === cur.origin && anchor?.checkpoint) {
      const p = { size: pinned.size, root: fromBase64(pinned.root) };
      if (p.size <= anchor.checkpoint.size) await tileCheck(ctx, () => consistent(subtree, p, anchor.checkpoint, "the pinned checkpoint and the newest anchor"), anchor);
      else {
        report.wait(`the newest anchor (${anchor.checkpoint.size}) is older than the pinned checkpoint (${p.size})`);
        if (p.size <= cp.size) await tileCheck(ctx, () => consistent(subtree, anchor.checkpoint, p, "the newest anchor and the pinned checkpoint"), anchor);
      }
    } else if (pinned.origin !== cur.origin && !gens.some((g) => g.origin === pinned.origin)) {
      report.fail(`the pinned origin ${pinned.origin} is neither current nor closed by a rewind record`);
    }
  }

  // 8. Provider keys of the ENROLLs anchored since the pin.
  if (anchor?.checkpoint && tilesOk) {
    const from = pinned?.origin === cur.origin ? Math.min(pinned.size, anchor.checkpoint.size) : 0;
    await newEnrollKeys(ctx, gens, from, anchor.checkpoint.size);
  }

  // 9. The unanchored tail.
  const anchoredSize = anchor?.checkpoint?.size ?? 0;
  /** @type {{ size: number, firstSeen: number } | null} */
  let tail = null;
  if (cp.size > anchoredSize) {
    const prev = pinned?.origin === cur.origin ? pinned.tail : null;
    tail = prev && prev.size > anchoredSize ? prev : { size: cp.size, firstSeen: ctx.now };
    if (ctx.now - tail.firstSeen > 2 * pins.anchorIntervalS) report.wait(`leaves past ${anchoredSize} have been published without an anchor for more than two anchor intervals`);
    else report.note(`${cp.size - anchoredSize} leaves are published and not anchored yet`);
  }

  if (report.failures.length || !anchor?.checkpoint) return undefined;
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
 * the bucket withholds while serving its neighbours fails it once the first anchor over
 * it is a week old, anything unreadable is a note.
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

/** @param {Ctx} ctx @param {string} fileText @param {string} where */
async function anchorOrFail(ctx, fileText, where) {
  const size = (() => {
    try {
      return parseCheckpoint(JSON.parse(fileText).note.split("\n\n")[0] + "\n").size;
    } catch {
      return 0;
    }
  })();
  try {
    return await checkAnchor(fileText, { logName: ctx.logName, logKey: keyFor(ctx.pins, size), shards: ctx.shards ?? REKOR_SHARDS, now: ctx.now });
  } catch (e) {
    if (e instanceof AnchorError) ctx.report.fail(`${where}: ${e.message}`);
    else throw e;
    return null;
  }
}

/**
 * @param {Ctx} ctx @param {string} prefix @param {import("./anchor.js").Anchor} anchor
 * @param {import("@emojery/shared/core").SubtreeHash} subtree @param {{ size: number }} cp
 */
async function mirrorCheck(ctx, prefix, anchor, subtree, cp) {
  const s = /** @type {NonNullable<typeof anchor.checkpoint>} */ (anchor.checkpoint);
  const latest = await ctx.mirror.get(`${prefix}/anchors/latest.json`);
  if (!latest.ok) {
    ctx.report.warn("anchor checked by one path: the mirror could not be read");
    return;
  }
  const L = await anchorOrFail(ctx, text(latest), `mirror ${prefix}/anchors/latest.json`);
  if (!L?.checkpoint) return;
  const same = await ctx.mirror.get(`${prefix}/anchors/${s.size}.json`);
  if (same.ok) {
    const m = await anchorOrFail(ctx, text(same), `mirror ${prefix}/anchors/${s.size}.json`);
    if (m?.checkpoint && !equalBytes(m.checkpoint.root, s.root)) ctx.report.fail(`the mirror holds anchor ${s.size} with another root: a split view`);
    return;
  }
  if (L.checkpoint.size < s.size) {
    ctx.report.warn(`the mirror lags: its newest anchor is ${L.checkpoint.size}, the bucket's is ${s.size}`);
    if (s.size <= cp.size) await tileCheck(ctx, () => consistent(subtree, L.checkpoint, s, "the mirror's newest anchor and the bucket's"), anchor);
    return;
  }
  const gap = /** @type {number} */ (L.anchoredAt) - /** @type {number} */ (anchor.anchoredAt);
  if (gap >= 2 * ctx.pins.anchorIntervalS) ctx.report.fail(`anchor ${s.size} is missing from the mirror, whose newest anchor ${L.checkpoint.size} is ${gap} s newer: an anchor kept out of the shared history`);
  else ctx.report.warn(`anchor ${s.size} is not in the mirror yet`);
}

/**
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
  let anchored = null;
  const last = await ctx.mirror.get(`${prefix}/anchors/latest.json`);
  if (last.ok) anchored = await anchorOrFail(ctx, text(last), `mirror ${prefix}/anchors/latest.json`);
  const known = Math.max(anchored?.checkpoint?.size ?? 0, pinned?.origin === g.origin ? pinned.size : 0);
  if (r.m < known) ctx.report.fail(`the rewind that closed ${g.origin} says M = ${r.m}, below size ${known} that ${g.origin} reached`);
  const dropped = r.m - r.n;
  const droppedAnchored = Math.max(0, (anchored?.checkpoint?.size ?? 0) - r.n);
  ctx.report.note(`${g.origin} closed on ${new Date(r.at).toISOString().slice(0, 10)} at size ${r.n} (${r.reason}); ${dropped} later entries were not carried over, ${droppedAnchored} of them anchored`);
  if (dropped > 0) ctx.report.warn(`a rewind dropped ${dropped} published entries of ${g.origin}, ${droppedAnchored} of them anchored`);
}

/**
 * Checks that every ENROLL in [from, to) names a provider and a provider key a witness
 * has seen.
 * @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {number} from @param {number} to
 */
async function newEnrollKeys(ctx, gens, from, to) {
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
      await providerKey(ctx, gens, seq, provider, leaf.modulusHash);
    }
  }
}

/**
 * @param {Ctx} ctx @param {import("./log.js").Generation[]} gens @param {number} seq
 * @param {import("./pins.js").Provider} provider @param {Uint8Array} hash
 */
export async function providerKey(ctx, gens, seq, provider, hash) {
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
      ctx.report.warn(`leaf ${seq}: provider key ${name} is not witnessed: it is only in the publisher's own files`);
      return "bucket";
    } catch (e) {
      ctx.report.fail(`jwks/${name}: ${/** @type {Error} */ (e).message}`);
      return null;
    }
  }
  if (!witnessed.missing || !own.missing) {
    ctx.report.warn(`not checked: provider key ${name} of leaf ${seq} could not be read`);
    return null;
  }
  ctx.report.fail(`leaf ${seq}: ENROLL names provider key ${name}, which no witness and no file holds`);
  return null;
}
