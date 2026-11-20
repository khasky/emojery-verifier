// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { sha256, toBase64Url, toHex, utf8 } from "@emojery/shared/core";
import { canonicalJwk, recordRun, snapshotJwks } from "../src/mirror.js";
import { Report } from "../src/report.js";
import { Publisher } from "./helpers/publisher.js";

const leaf = (i) => utf8(`leaf ${i}`);

async function withDir(fn) {
  const dir = await mkdtemp(join(tmpdir(), "mirror-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const run = (dir, pub, verdict = "PASS") => {
  const report = new Report();
  if (verdict === "FAIL") report.fail("something");
  return recordRun({ dir, bucket: pub.host("bucket"), logName: pub.logName, logKey: pub.key.pk, report, state: { origin: pub.origin, size: pub.leaves.length }, jwksAdded: [], now: new Date("2026-10-24T06:00:00Z") });
};

test("copies new anchors along prev, once, and moves latest.json", async () => {
  await withDir(async (dir) => {
    const pub = new Publisher();
    await pub.seal([leaf(0), leaf(1)]);
    await pub.publish();
    await pub.anchor(1_790_000_000);
    await pub.seal([leaf(2)]);
    await pub.publish();
    await pub.anchor(1_790_001_800);

    const first = await run(dir, pub);
    assert.equal(first.anchors, 2);
    assert.equal(first.message, `sync PASS ${pub.origin} 3`);
    assert.deepEqual((await readdir(join(dir, "g0/anchors"))).sort(), ["2.json", "3.json", "latest.json"]);
    assert.equal(await readFile(join(dir, "g0/anchors/latest.json"), "utf8"), await readFile(join(dir, "g0/anchors/3.json"), "utf8"));

    const again = await run(dir, pub);
    assert.equal(again.anchors, 0);
    const lines = (await readFile(join(dir, "verdicts/2026-10.ndjson"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(lines.length, 2);
    assert.deepEqual(Object.keys(lines[0]), ["at", "verdict", "origin", "size", "notes", "jwksAdded"]);
  });
});

test("keeps a differing anchor beside the mirror's copy and fails the run", async () => {
  await withDir(async (dir) => {
    const pub = new Publisher();
    await pub.seal([leaf(0)]);
    await pub.publish();
    await pub.anchor(1_790_000_000);
    await run(dir, pub);
    const held = await readFile(join(dir, "g0/anchors/1.json"), "utf8");

    // The bucket now serves another anchor at the same size.
    await pub.anchor(1_790_000_100);
    const report = new Report();
    await recordRun({ dir, bucket: pub.host("bucket"), logName: pub.logName, logKey: pub.key.pk, report, state: { origin: pub.origin, size: 1 }, jwksAdded: [], now: new Date() });
    assert.equal(report.verdict, "FAIL");
    assert.equal(await readFile(join(dir, "g0/anchors/1.json"), "utf8"), held);
    assert.equal(await readFile(join(dir, "g0/anchors/latest.json"), "utf8"), held);
    const files = await readdir(join(dir, "g0/anchors"));
    assert.equal(files.filter((f) => f.startsWith("1.conflict-")).length, 1);
  });
});

test("copies index.json only on PASS and mirrors every generation's anchors", async () => {
  await withDir(async (dir) => {
    const pub = new Publisher();
    await pub.seal([leaf(0), leaf(1)]);
    await pub.publish();
    await pub.anchor(1_790_000_000);
    await pub.rewind(1, "test");
    await pub.seal([leaf(9)]);
    await pub.publish();
    await pub.anchor(1_790_003_600);

    await run(dir, pub, "FAIL");
    await assert.rejects(readFile(join(dir, "index.json")));
    assert.ok(await readFile(join(dir, "g0/anchors/2.json")));
    assert.ok(await readFile(join(dir, "g1/anchors/2.json")));
    await run(dir, pub, "PASS");
    assert.ok(await readFile(join(dir, "index.json")));
  });
});

test("snapshots the providers' new RSA keys and reports what it added", async () => {
  await withDir(async (dir) => {
    const n = toBase64Url(new Uint8Array([1, 2, 3, 4]));
    const keys = { keys: [{ kty: "RSA", n, e: "AQAB", kid: "a" }, { kty: "EC", x: "x" }] };
    const providers = [{ id: "test", iss: "https://issuer.test", aud: [], jwksUri: "https://issuer.test/jwks" }];
    const added = await snapshotJwks(dir, providers, async () => keys, () => {});
    const name = toHex(await sha256(new Uint8Array([1, 2, 3, 4])));
    const bytes = await readFile(join(dir, `jwks/test/${name}.json`), "utf8");
    assert.equal(bytes, canonicalJwk({ n, e: "AQAB" }));
    assert.deepEqual(added, [toHex(await sha256(utf8(bytes)))]);
    assert.deepEqual(await snapshotJwks(dir, providers, async () => keys, () => {}), []);
    const notes = [];
    await snapshotJwks(dir, providers, async () => {
      throw new Error("down");
    }, (s) => notes.push(s));
    assert.deepEqual(notes, ["jwks of test: down"]);
  });
});
