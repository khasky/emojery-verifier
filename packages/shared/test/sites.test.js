// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { badgePath, countsPath, parseBadgePath, parseCountsPath } from "../src/api/index.js";
import { utf8 } from "../src/core/bytes.js";
import { isPaletteReaction, PALETTE, PALETTE_SHA256 } from "../src/palette/index.js";
import { isValidTargetId, SITE_NAMES, SITES, siteForUrl, targetIdFromUrl, targetUrl } from "../src/sites/index.js";

const vectors = JSON.parse(readFileSync(new URL("../vectors/targets.json", import.meta.url), "utf8"));

test("every derive vector yields its id, from the site and from the host", () => {
  for (const v of vectors.derive) {
    assert.equal(targetIdFromUrl(v.site, v.url), v.targetId, v.url);
    assert.equal(siteForUrl(v.url), v.site, v.url);
  }
});

test("every noTarget vector yields nothing", () => {
  for (const v of vectors.noTarget) assert.equal(targetIdFromUrl(v.site, v.url), null, v.url);
});

test("id patterns", () => {
  for (const v of vectors.valid) assert.ok(isValidTargetId(v.site, v.targetId), `${v.site} ${v.targetId}`);
  for (const v of vectors.invalid) assert.ok(!isValidTargetId(v.site, v.targetId), `${v.site} ${JSON.stringify(v.targetId)}`);
});

test("a derived id leads back to a URL that derives it again", () => {
  for (const v of vectors.derive) {
    const back = targetUrl(v.site, v.targetId);
    if (back && SITES[v.site].fromUrl) assert.equal(targetIdFromUrl(v.site, back), v.targetId, back);
  }
});

test("host lists are disjoint and every id fits the log's limits", () => {
  const seen = new Map();
  for (const name of SITE_NAMES) {
    assert.match(name, /^[a-z0-9]{1,32}$/);
    for (const h of SITES[name].hosts) {
      assert.ok(!seen.has(h), `${h} in ${seen.get(h)} and ${name}`);
      seen.set(h, name);
    }
  }
  for (const v of [...vectors.derive, ...vectors.valid]) {
    const n = utf8(v.targetId).length;
    assert.ok(n >= 1 && n <= 256);
  }
});

test("counts and badge paths both decode to the same key", () => {
  for (const v of [...vectors.derive, ...vectors.valid]) {
    const counts = countsPath(v.site, v.targetId);
    assert.match(counts, /^\/v2\/counts\/[a-z0-9]+\/[A-Za-z0-9_-]+\.json$/);
    assert.deepEqual(parseCountsPath(counts), { site: v.site, targetId: v.targetId });
    assert.deepEqual(parseBadgePath(badgePath(v.site, v.targetId, "svg")), { site: v.site, targetId: v.targetId, ext: "svg" });
  }
  assert.equal(countsPath("github", "khasky/emojery"), "/v2/counts/github/a2hhc2t5L2Vtb2plcnk.json");
  for (const bad of ["/v2/counts/github/a2hhc2t5L2Vtb2plcnk=.json", "/v2/counts/github/a2hhc2t5L2Vtb2plcnk.json/", "/v2/counts/github/a2hhc2t5L2Vtb2plcn.json", "/v2/counts/github/.json", "/v2/counts/github/a2hhc2t5L2Vtb2plcnk*.json", "/v2/counts/nosuch/MQ.json", "/v2/counts/github/S2hhc2t5L0Vtb2plcnk.json"]) {
    assert.equal(parseCountsPath(bad), null, bad);
  }
  assert.throws(() => countsPath("github", "Khasky/Emojery"), RangeError);
  assert.equal(parseBadgePath("/badge/github/Khasky/Emojery.svg"), null);
});

test("the palette: RGI, fully qualified, unique, pinned by its hash", () => {
  assert.equal(PALETTE.length, new Set(PALETTE).size);
  for (const r of PALETTE) {
    assert.match(r, /^\p{RGI_Emoji}$/v);
    assert.ok(utf8(r).length <= 64);
  }
  assert.equal(createHash("sha256").update(PALETTE.join("\n")).digest("hex"), PALETTE_SHA256);
  assert.ok(isPaletteReaction("❤️"));
  for (const bad of ["❤", "#️⃣", "\uD83D", "🔥 ", "🎉🎉", "👍🏽"]) assert.ok(!isPaletteReaction(bad), JSON.stringify(bad));
});
