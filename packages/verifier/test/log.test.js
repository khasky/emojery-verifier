// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeEntryBundle, rewindText, signNote } from "@emojery/shared/core";
import { entries, generations, originAt, prefixFor, readTile } from "../src/log.js";

const LOG = "log.emojery.app";
const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
const root = new Uint8Array(32);

const rewind = (k, n, m) => signNote(rewindText({ origin: `${LOG}/g${k + 1}`, forkedFrom: `${LOG}/g${k}`, at: 1790000000000 + k, n, rootN: root, m, rootM: root, reason: "drill" }), LOG, kp.privateKey, pub);
const index = async (...recs) => JSON.stringify({ records: await Promise.all(recs.map(async ([k, n, m]) => ({ kind: "rewind", note: await rewind(k, n, m) }))) });

test("no index.json: one generation", async () => {
  const g = await generations(null, LOG, pub);
  assert.deepEqual(g, [{ origin: `${LOG}/g0`, generation: 0, start: 0, end: null }]);
  assert.equal(originAt(g, 5), `${LOG}/g0`);
});

test("one rewind: leaves below N stay in g0", async () => {
  const g = await generations(await index([0, 100, 150]), LOG, pub);
  assert.equal(g.length, 2);
  assert.equal(g[0].end, 150);
  assert.equal(originAt(g, 99), `${LOG}/g0`);
  assert.equal(originAt(g, 100), `${LOG}/g1`);
  assert.equal(prefixFor(g, 99), "g0");
  assert.equal(prefixFor(g, 100), "g1");
});

test("a deeper second rewind takes back part of the first prefix", async () => {
  const g = await generations(await index([0, 100, 150], [1, 50, 120]), LOG, pub);
  assert.deepEqual(g.map((x) => x.start), [0, 100, 50]);
  assert.equal(originAt(g, 30), `${LOG}/g0`);
  assert.equal(originAt(g, 70), `${LOG}/g2`);
  assert.equal(originAt(g, 120), `${LOG}/g2`);
  assert.equal(prefixFor(g, 49), "g0");
  assert.equal(prefixFor(g, 50), "g2");
});

test("records that do not chain, or are not signed by the log, are refused", async () => {
  await assert.rejects(generations(await index([1, 10, 20]), LOG, pub), /forks from/);
  await assert.rejects(generations(await index([0, 10, 20], [0, 10, 20]), LOG, pub), /forks from/);
  const other = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const otherPub = new Uint8Array(await crypto.subtle.exportKey("raw", other.publicKey));
  await assert.rejects(generations(await index([0, 10, 20]), LOG, otherPub));
  await assert.rejects(generations(JSON.stringify({ records: [{ kind: "erasure", note: "x" }] }), LOG, pub), /unknown kind/);
});

test("tiles: the full object first, a partial at the right edge, under the right prefix", async () => {
  const g = await generations(await index([0, 257, 400]), LOG, pub);
  const leaves = Array.from({ length: 3 }, (_, i) => new Uint8Array([i]));
  const served = new Map([
    ["g0/tile/entries/000", encodeEntryBundle(Array.from({ length: 256 }, () => new Uint8Array([9])))],
    ["g1/tile/entries/001.p/3", encodeEntryBundle(leaves)],
  ]);
  const asked = [];
  const bucket = {
    get: async (p) => {
      asked.push(p);
      const b = served.get(p);
      return b ? { ok: true, bytes: b, headers: new Headers() } : { ok: false, missing: true, status: 404 };
    },
  };
  const full = await readTile(bucket, g, "entries", 0, 0, 256);
  assert.equal(full.path, "g0/tile/entries/000");
  const edge = await readTile(bucket, g, "entries", 0, 1, 3);
  assert.equal(edge.path, "g1/tile/entries/001.p/3");
  assert.deepEqual(entries(edge, 3), leaves);
  const gone = await readTile(bucket, g, "hash", 0, 2, 256);
  assert.equal(gone.ok, false);
  assert.equal(gone.missing, true);
  assert.deepEqual(asked, ["g0/tile/entries/000", "g1/tile/entries/001.p/3", "g1/tile/0/002"]);
});
