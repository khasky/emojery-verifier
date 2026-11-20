// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { EncodingError, toHex, u32 } from "../src/core/bytes.js";
import { leafHash } from "../src/core/messages.js";
import { buildHashTiles, decodeEntryBundle, encodeEntryBundle, entriesPath, hashTilePath, subtreeFromTiles, tileIndexPath, tileWidth } from "../src/core/tiles.js";
import { inclusionProof, subtreeFromLeafHashes, treeRoot, verifyInclusion } from "../src/core/tree.js";

test("tile index paths", () => {
  assert.equal(tileIndexPath(0), "000");
  assert.equal(tileIndexPath(255), "255");
  assert.equal(tileIndexPath(1000), "x001/000");
  assert.equal(tileIndexPath(1234067), "x001/x234/067");
  assert.equal(hashTilePath(0, 1234067), "tile/0/x001/x234/067");
  assert.equal(hashTilePath(1, 0, 5), "tile/1/000.p/5");
  assert.equal(entriesPath(1234), "tile/entries/x001/234");
  assert.equal(entriesPath(0, 1), "tile/entries/000.p/1");
  assert.throws(() => entriesPath(0, 0), RangeError);
  assert.throws(() => entriesPath(0, 257), RangeError);
});

test("tile widths at the sizes the gate names", () => {
  const widths = (size) => {
    const out = [];
    for (let level = 0; tileWidth(level, 0, size) > 0; level++) {
      const last = Math.floor((Math.floor(size / 256 ** level) - 1) / 256);
      out.push(`${level}:${last}:${tileWidth(level, last, size)}`);
    }
    return out.join(" ");
  };
  assert.equal(widths(1), "0:0:1");
  assert.equal(widths(255), "0:0:255");
  assert.equal(widths(256), "0:0:256 1:0:1");
  assert.equal(widths(257), "0:1:1 1:0:1");
  assert.equal(widths(65537), "0:256:1 1:0:256 2:0:1");
  assert.equal(widths(16777217), "0:65536:1 1:255:256 2:0:256 3:0:1");
});

test("entry bundles round-trip and reject a wrong count or a cut", () => {
  const leaves = [new Uint8Array([1, 2, 3]), new Uint8Array(0), new Uint8Array(300).fill(7)];
  const b = encodeEntryBundle(leaves);
  assert.equal(toHex(b.subarray(0, 5)), "0003010203");
  assert.deepEqual(decodeEntryBundle(b, 3), leaves);
  assert.throws(() => decodeEntryBundle(b, 2), EncodingError);
  assert.throws(() => decodeEntryBundle(b.subarray(0, b.length - 1), 3), EncodingError);
});

for (const size of [1, 255, 256, 257, 65537]) {
  test(`root and proofs from tiles equal those from leaves, size ${size}`, async () => {
    const hashes = await Promise.all(Array.from({ length: size }, (_, i) => leafHash(u32(i))));
    const tiles = new Map((await buildHashTiles(hashes)).map((t) => [`${t.level}/${t.index}/${t.width}`, t.bytes]));
    const fromTiles = subtreeFromTiles(size, async (level, index, width) => {
      const b = tiles.get(`${level}/${index}/${width}`);
      if (!b) throw new Error(`missing tile ${level}/${index}/${width}`);
      return b;
    });
    const fromLeaves = subtreeFromLeafHashes(hashes);
    const root = await treeRoot(size, fromLeaves);
    assert.deepEqual(await treeRoot(size, fromTiles), root);
    for (const i of [0, Math.floor(size / 2), size - 1]) {
      const proof = await inclusionProof(i, size, fromTiles);
      assert.deepEqual(proof, await inclusionProof(i, size, fromLeaves));
      await verifyInclusion(i, size, hashes[i], proof, root);
    }
  });
}
