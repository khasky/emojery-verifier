// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { isSmallOrderKey } from "@emojery/shared/core";

// The shared package hardcodes the small-order encodings; derive them independently.
test("every torsion point is a small-order key and ordinary keys are not", () => {
  const P = ed25519.Point;
  const t8 = P.fromHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
  assert.ok(t8.multiplyUnsafe(8n).is0() && !t8.multiplyUnsafe(4n).is0());
  let q = P.ZERO;
  for (let k = 0; k < 8; k++) {
    assert.ok(q.isSmallOrder());
    assert.ok(isSmallOrderKey(q.toBytes()), q.toHex());
    q = q.add(t8);
  }
  for (let i = 0; i < 64; i++) assert.ok(!isSmallOrderKey(ed25519.getPublicKey(ed25519.utils.randomSecretKey())));
});
