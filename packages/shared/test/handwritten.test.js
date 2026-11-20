// SPDX-License-Identifier: Apache-2.0
// The oracle is the text, not the code: these vectors were typed from docs/PROTOCOL.md.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { concat, fromHex, lp32, sha256, toHex, utf8 } from "../src/core/index.js";
import { decodeLeaf, encodeLeaf } from "../src/core/leaf.js";
import { reactMessage, refreshMessage, retireMessage } from "../src/core/messages.js";

const v = JSON.parse(readFileSync(new URL("../vectors/handwritten/leaves.json", import.meta.url), "utf8"));
const BYTES = new Set(["sig", "caseId", "nullifier", "modulusHash", "accountPubkey", "proofHash", "enrollHash"]);

/** @param {Record<string, any>} f */
function fields(f) {
  return Object.fromEntries(Object.entries(f).map(([k, x]) => [k, BYTES.has(k) ? fromHex(x) : k === "enrollSeq" ? BigInt(x) : x]));
}

test("every handwritten leaf: the encoder gives its bytes, the decoder its fields", () => {
  for (const leaf of v.leaves) {
    const want = leaf.parts.join("");
    assert.equal(want.length / 2, leaf.length, leaf.name);
    assert.equal(toHex(encodeLeaf(fields(leaf.fields))), want, leaf.name);
    assert.deepEqual(decodeLeaf(fromHex(want)), fields(leaf.fields), leaf.name);
  }
});

test("every handwritten signed message", () => {
  for (const m of v.messages) {
    const f = fields(m.fields);
    const got = m.kind === "react" ? reactMessage(/** @type {any} */ (f)) : m.kind === "retire" ? retireMessage(f.logName, f.enrollHash) : refreshMessage(f.logName, BigInt(f.exp));
    assert.equal(toHex(got), m.parts.join(""), m.name);
  }
});

test("the nullifier preimage and its hash", async () => {
  const n = v.nullifier;
  const pre = concat(utf8("emojery-nullifier-v1"), lp32(n.iss), lp32(n.sub), lp32(n.aud), fromHex(n.salt));
  assert.equal(toHex(pre), n.parts.join(""));
  assert.equal(toHex(await sha256(pre)), n.sha256);
});
