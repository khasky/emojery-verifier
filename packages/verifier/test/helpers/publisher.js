// SPDX-License-Identifier: Apache-2.0
// A publisher in memory, for tests: seals leaves, publishes tiles and checkpoints the
// way docs/PROTOCOL.md describes, anchors in a fake Rekor shard, mirrors anchors and
// rewinds. Files land in two Maps, the bucket and the mirror, served by `host()`.

import { ed25519, ed25519ph } from "@noble/curves/ed25519.js";
import { buildHashTiles, checkpointText, concat, consistencyProof, encodeEntryBundle, entriesPath, hashTilePath, inclusionProof, leafHash, noteKeyId, rewindText, sha512, subtreeFromLeafHashes, TILE_WIDTH, toBase64, treeRoot, utf8 } from "@emojery/shared/core";
import { anchorFile } from "../../src/anchor.js";

const SPKI = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

/** @param {string} text @param {string} name @param {Uint8Array} sk @param {Uint8Array} pk */
export async function sign(text, name, sk, pk) {
  const sig = ed25519.sign(utf8(text), sk);
  return `${text}\n— ${name} ${toBase64(concat(await noteKeyId(name, pk), sig))}\n`;
}

export function keyPair() {
  const sk = ed25519.utils.randomSecretKey();
  return { sk, pk: ed25519.getPublicKey(sk) };
}

/** A Rekor v2 shard that accepts hashedrekord entries. */
export class FakeShard {
  constructor(origin = "shard.test") {
    this.origin = origin;
    this.key = keyPair();
    /** @type {Uint8Array[]} */
    this.leafHashes = [];
  }

  get pin() {
    return { origin: this.origin, publicKey: toBase64(this.key.pk) };
  }

  /** @param {string} note @param {Uint8Array} anchorSig @param {Uint8Array} logPk */
  async add(note, anchorSig, logPk) {
    const body = { apiVersion: "0.0.2", kind: "hashedrekord", spec: { hashedRekordV002: { data: { algorithm: "SHA2_512", digest: toBase64(await sha512(utf8(note))) }, signature: { content: toBase64(anchorSig), verifier: { keyDetails: "PKIX_ED25519_PH", publicKey: { rawBytes: toBase64(concat(SPKI, logPk)) } } } } } };
    const bytes = utf8(JSON.stringify(body));
    const index = this.leafHashes.length;
    this.leafHashes.push(await leafHash(bytes));
    const size = this.leafHashes.length;
    const sub = subtreeFromLeafHashes(this.leafHashes);
    const root = await treeRoot(size, sub);
    const proof = await inclusionProof(index, size, sub);
    const checkpoint = await sign(checkpointText({ origin: this.origin, size, root }), this.origin, this.key.sk, this.key.pk);
    return { logIndex: String(index), canonicalizedBody: toBase64(bytes), inclusionProof: { logIndex: String(index), treeSize: String(size), rootHash: toBase64(root), hashes: proof.map(toBase64), checkpoint: { envelope: checkpoint } } };
  }
}

export class Publisher {
  /** @param {{ logName?: string, shard?: FakeShard }} [o] */
  constructor(o = {}) {
    this.logName = o.logName ?? "log-staging.emojery.app";
    this.key = keyPair();
    this.shard = o.shard ?? new FakeShard();
    this.generation = 0;
    /** @type {Uint8Array[]} */
    this.leaves = [];
    /** @type {Uint8Array[]} */
    this.hashes = [];
    /** @type {Map<string, Uint8Array>} */
    this.bucket = new Map();
    /** @type {Map<string, Uint8Array>} */
    this.mirror = new Map();
    /** @type {{ kind: string, note: string }[]} */
    this.records = [];
    /** Leaves below this were written under an older generation's prefix. */
    this.prefixes = [{ generation: 0, start: 0 }];
    /** Size of the newest anchor of the current generation. */
    this.lastAnchor = null;
  }

  get origin() {
    return `${this.logName}/g${this.generation}`;
  }

  get pins() {
    return { logKeys: [{ publicKey: toBase64(this.key.pk), fromSize: 0 }], enroll: {}, saltCommitment: "", providers: [], mirror: "", bucket: "", api: "", anchorIntervalS: 1800 };
  }

  /** @param {Uint8Array[]} leaves */
  async seal(leaves) {
    for (const l of leaves) {
      this.leaves.push(l);
      this.hashes.push(await leafHash(l));
    }
  }

  /** The prefix for an object whose last leaf is `last`. @param {number} last */
  prefixOf(last) {
    for (let i = this.prefixes.length - 1; i > 0; i--) if (last >= this.prefixes[i].start) return `g${this.prefixes[i].generation}`;
    return `g${this.prefixes[0].generation}`;
  }

  /** Writes bundles, hash tiles and the checkpoint for the current size. */
  async publish() {
    const n = this.leaves.length;
    for (let b = 0; b * TILE_WIDTH < n; b++) {
      const slice = this.leaves.slice(b * TILE_WIDTH, (b + 1) * TILE_WIDTH);
      const p = this.prefixOf(b * TILE_WIDTH + slice.length - 1);
      this.bucket.set(`${p}/${entriesPath(b, slice.length)}`, encodeEntryBundle(slice));
      if (slice.length === TILE_WIDTH) for (const k of [...this.bucket.keys()]) if (k.startsWith(`${p}/${entriesPath(b)}.p/`)) this.bucket.delete(k);
    }
    for (const t of await buildHashTiles(this.hashes)) {
      const last = (t.index * TILE_WIDTH + t.width) * 2 ** (8 * t.level) - 1;
      this.bucket.set(`${this.prefixOf(last)}/${hashTilePath(t.level, t.index, t.width)}`, t.bytes);
      if (t.width === TILE_WIDTH) for (const k of [...this.bucket.keys()]) if (k.startsWith(`${this.prefixOf(last)}/${hashTilePath(t.level, t.index)}.p/`)) this.bucket.delete(k);
    }
    this.bucket.set(`g${this.generation}/checkpoint`, utf8(await this.checkpointNote()));
  }

  async root(size = this.leaves.length) {
    return treeRoot(size, subtreeFromLeafHashes(this.hashes));
  }

  async checkpointNote(size = this.leaves.length) {
    return sign(checkpointText({ origin: this.origin, size, root: await this.root(size) }), this.logName, this.key.sk, this.key.pk);
  }

  /** Anchors the current checkpoint; returns the anchor file text. @param {number} anchoredAt */
  async anchor(anchoredAt) {
    const note = await this.checkpointNote();
    const anchorSig = ed25519ph.sign(utf8(note), this.key.sk);
    const tle = await this.shard.add(note, anchorSig, this.key.pk);
    const file = anchorFile(note, anchoredAt, this.shard.origin, toBase64(anchorSig), tle, this.lastAnchor);
    this.lastAnchor = this.leaves.length;
    const g = `g${this.generation}`;
    this.bucket.set(`${g}/anchors/${this.leaves.length}.json`, utf8(file));
    this.bucket.set(`${g}/anchors/latest.json`, utf8(file));
    return file;
  }

  /** Copies the bucket's anchors and index.json to the mirror. */
  syncMirror() {
    for (const [k, v] of this.bucket) if (/\/anchors\//.test(k) || k === "index.json") this.mirror.set(k, v);
  }

  /**
   * Closes the current generation at N and opens the next.
   * @param {number} n @param {string} reason
   */
  async rewind(n, reason) {
    const m = this.leaves.length;
    const rec = { origin: `${this.logName}/g${this.generation + 1}`, forkedFrom: this.origin, at: 1790000000000, n, rootN: await this.root(n), m, rootM: await this.root(m), reason };
    this.records.push({ kind: "rewind", note: await sign(rewindText(rec), this.logName, this.key.sk, this.key.pk) });
    this.bucket.set("index.json", utf8(JSON.stringify({ records: this.records })));
    this.generation++;
    this.lastAnchor = null;
    this.prefixes.push({ generation: this.generation, start: n });
    this.leaves.length = n;
    this.hashes.length = n;
  }

  /** A host over one of the Maps. @param {"bucket" | "mirror"} which */
  host(which) {
    const files = this[which];
    return {
      /** @param {string} p */
      get: async (p) => {
        const b = files.get(p);
        return b ? { ok: true, bytes: b, headers: new Headers() } : { ok: false, missing: true, status: 404 };
      },
    };
  }

  /** Consistency proof between two sizes of the current tree. @param {number} m @param {number} n */
  consistency(m, n) {
    return consistencyProof(m, n, subtreeFromLeafHashes(this.hashes));
  }
}
