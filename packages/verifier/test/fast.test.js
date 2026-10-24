// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeLeaf, OP, utf8 } from "@emojery/shared/core";
import { fastCheck } from "../src/fast.js";
import { Report } from "../src/report.js";
import { Publisher } from "./helpers/publisher.js";

const NOW = 1792800000;
// Opaque leaves are enough here: the fast run decodes only the leaves in the new range,
// and these tests keep that range empty or ENROLL-free by pinning first.
const junk = (n, from = 0) => Array.from({ length: n }, (_, i) => encodeLeaf({ op: OP.REVOKE, enrollSeq: BigInt(from + i), reasonCode: 'automation', caseId: new Uint8Array(16), banUntil: 0 }));

async function run(p, pinned, now = NOW) {
  const report = new Report();
  const ctx = { logName: p.logName, pins: p.pins, bucket: p.host("bucket"), mirror: p.host("mirror"), report, now, shards: [p.shard.pin] };
  const state = await fastCheck(ctx, pinned);
  return { report, state };
}

/** A log of `n` leaves, published, anchored, mirrored, and a state pinned on it. */
async function honest(n = 300) {
  const p = new Publisher();
  await p.seal(junk(n));
  await p.publish();
  await p.anchor(NOW - 60);
  p.syncMirror();
  return p;
}

test("an honest log passes and pins its anchor", async () => {
  const p = await honest();
  const { report, state } = await run(p);
  assert.equal(report.verdict, "PASS", report.toText());
  assert.equal(state.size, 300);
  assert.equal(state.origin, "log-staging.emojery.app/g0");
});

test("growth after a pin stays consistent", async () => {
  const p = await honest();
  const first = await run(p);
  await p.seal(junk(500, 300));
  await p.publish();
  await p.anchor(NOW);
  p.syncMirror();
  const { report, state } = await run(p, first.state);
  assert.equal(report.verdict, "PASS", report.toText());
  assert.equal(state.size, 800);
});

test("a rewritten history fails against the pin", async () => {
  const p = await honest();
  const first = await run(p);
  const q = new Publisher();
  q.key = p.key;
  q.shard = p.shard;
  await q.seal([...junk(299), encodeLeaf({ op: OP.REVOKE, enrollSeq: 9n, reasonCode: 'forged', caseId: new Uint8Array(16), banUntil: 1 })]);
  await q.seal(junk(10, 300));
  await q.publish();
  await q.anchor(NOW);
  q.syncMirror();
  const { report } = await run(q, first.state);
  assert.equal(report.verdict, "FAIL");
  assert.match(report.failures.join("\n"), /not consistent/);
});

test("a hash tile that does not match the checkpoint fails", async () => {
  const p = await honest();
  const tile = p.bucket.get("g0/tile/0/001.p/44");
  const bad = new Uint8Array(tile);
  bad[0] ^= 1;
  p.bucket.set("g0/tile/0/001.p/44", bad);
  const { report } = await run(p);
  assert.equal(report.verdict, "FAIL");
});

test("a split view: the mirror holds another anchor of the same size", async () => {
  const p = await honest();
  const q = new Publisher();
  q.key = p.key;
  q.shard = p.shard;
  await q.seal([...junk(299), encodeLeaf({ op: OP.REVOKE, enrollSeq: 9n, reasonCode: 'other', caseId: new Uint8Array(16), banUntil: 1 })]);
  await q.publish();
  await q.anchor(NOW - 60);
  p.mirror.set("g0/anchors/300.json", q.bucket.get("g0/anchors/300.json"));
  p.mirror.set("g0/anchors/latest.json", q.bucket.get("g0/anchors/latest.json"));
  const { report } = await run(p);
  assert.equal(report.verdict, "FAIL");
  assert.match(report.failures.join("\n"), /split view/);
});

test("a mirror that lags is a note; an anchor kept out of the mirror fails", async () => {
  const p = await honest();
  await p.seal(junk(10, 300));
  await p.publish();
  await p.anchor(NOW - 30);
  const lag = await run(p);
  assert.equal(lag.report.verdict, "PASS", lag.report.toText());
  assert.match(lag.report.warnings.join("\n"), /mirror lags/);
  // The mirror moves on past 310 without ever holding anchor 310.
  const skipped = p.bucket.get("g0/anchors/310.json");
  await p.seal(junk(10, 310));
  await p.publish();
  await p.anchor(NOW + 4000);
  p.syncMirror();
  p.mirror.delete("g0/anchors/310.json");
  p.bucket.set("g0/anchors/latest.json", skipped);
  p.bucket.set("g0/checkpoint", utf8(await p.checkpointNote(320)));
  const { report } = await run(p, undefined, NOW + 4100);
  assert.equal(report.verdict, "FAIL", report.toText());
  assert.match(report.failures.join("\n"), /missing from the mirror/);
});

test("an unanchored tail is a note, then a WAIT after two intervals", async () => {
  const p = await honest();
  const first = await run(p);
  await p.seal(junk(5, 300));
  await p.publish();
  const soon = await run(p, first.state, NOW + 60);
  assert.equal(soon.report.verdict, "PASS");
  const later = await run(p, soon.state, NOW + 60 + 2 * 1800 + 1);
  assert.equal(later.report.verdict, "WAIT", later.report.toText());
});

test("an unknown anchor kind waits", async () => {
  const p = await honest();
  const a = JSON.parse(new TextDecoder().decode(p.bucket.get("g0/anchors/latest.json")));
  a.kind = "future-v9";
  p.bucket.set("g0/anchors/latest.json", utf8(JSON.stringify(a)));
  p.mirror.clear();
  const { report } = await run(p);
  assert.equal(report.verdict, "WAIT", report.toText());
});

test("a rewind is reported; the shared prefix keeps its old paths", async () => {
  const p = await honest(600);
  const first = await run(p);
  await p.rewind(512, "database incident");
  await p.seal(junk(20, 1000));
  await p.publish();
  await p.anchor(NOW);
  p.syncMirror();
  const { report, state } = await run(p, first.state);
  assert.equal(report.verdict, "PASS", report.toText());
  assert.match(report.info.join("\n"), /g0 closed .* at size 512 \(database incident\); 88 later entries were not carried over, 88 of them anchored/);
  assert.match(report.warnings.join("\n"), /dropped 88/);
  assert.equal(state.origin, "log-staging.emojery.app/g1");
  assert.ok(p.bucket.has("g0/tile/entries/001"));
  assert.ok(p.bucket.has("g1/tile/entries/002.p/20"));
});

test("a rewind that understates M fails", async () => {
  const p = await honest(600);
  const first = await run(p);
  const realM = p.leaves.length;
  p.leaves.length = 550;
  p.hashes.length = 550;
  await p.rewind(512, "database incident");
  assert.notEqual(realM, 550);
  await p.seal(junk(5, 1000));
  await p.publish();
  await p.anchor(NOW);
  p.syncMirror();
  const { report } = await run(p, first.state);
  assert.equal(report.verdict, "FAIL", report.toText());
  assert.match(report.failures.join("\n"), /M = 550/);
});

