// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fromBase64 } from "@emojery/shared/core";
import { AnchorError, anchorFile, checkAnchor } from "../src/anchor.js";

// A real Rekor v2 answer from the sigstage shard log2025-alpha3, for a throwaway log key.
const f = JSON.parse(readFileSync(new URL("./fixtures/rekor-v2-fixture.json", import.meta.url), "utf8"));
const SHARD = { origin: "log2025-alpha3.rekor.sigstage.dev", publicKey: "lD3dVc8yaP25mPtT/sJ59D3LLxGBgW/qYrM6x6KmOqk=" };
const ctx = { logName: f.logName, logKey: fromBase64(f.logPublicKey), shards: [SHARD], now: 1792800000 };
const file = anchorFile(f.note, 1792790000, SHARD.origin, f.anchorSig, f.response);
const mutate = (fn) => {
  const a = JSON.parse(file);
  fn(a);
  return JSON.stringify(a);
};

test("a real Rekor v2 anchor verifies", async () => {
  const a = await checkAnchor(file, ctx);
  assert.equal(a.status, "ok");
  assert.equal(a.shardPinned, true);
  assert.equal(a.checkpoint.origin, "log-staging.emojery.app/g0");
  assert.equal(a.checkpoint.size, 1);
});

test("an unknown kind waits, an unpinned shard is reported", async () => {
  assert.deepEqual(await checkAnchor(mutate((a) => (a.kind = "sigsum-v1")), ctx), { status: "unknown-kind" });
  const a = await checkAnchor(file, { ...ctx, shards: [] });
  assert.equal(a.shardPinned, false);
});

test("every contradiction fails", async () => {
  const otherSig = Buffer.from(fromBase64(f.anchorSig).map((b, i) => (i === 0 ? b ^ 1 : b))).toString("base64");
  const cases = {
    "note edited": mutate((a) => (a.note = a.note.replace("\n1\n", "\n2\n"))),
    "anchorSig of another message": mutate((a) => (a.rekor.anchorSig = otherSig)),
    "entry from another anchor": mutate((a) => (a.rekor.entry = Buffer.from(Buffer.from(a.rekor.entry, "base64").toString().replace("SHA2_512", "SHA2_256")).toString("base64"))),
    "inclusion index moved": mutate((a) => (a.rekor.inclusionProof.logIndex = String(Number(a.rekor.inclusionProof.logIndex) - 1))),
    "anchoredAt in the future": mutate((a) => (a.anchoredAt = ctx.now + 3600)),
    "anchoredAt missing": mutate((a) => delete a.anchoredAt),
  };
  for (const [why, text] of Object.entries(cases)) await assert.rejects(checkAnchor(text, ctx), AnchorError, why);
  await assert.rejects(checkAnchor(file, { ...ctx, logKey: new Uint8Array(32).fill(7) }), undefined, "another log key");
  await assert.rejects(checkAnchor(file, { ...ctx, shards: [{ ...SHARD, publicKey: "t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=" }] }), undefined, "another shard key");
});
