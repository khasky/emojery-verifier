import assert from "node:assert/strict";
import { test } from "node:test";
import { LOG_NAMES, PROVIDERS } from "@emojery/shared/api";
import { fromBase64 } from "@emojery/shared/core";
import { LOGS, logKeyAt, pinsFor, providerFor } from "../src/pins.js";

for (const [deployment, logName] of /** @type {["production" | "staging", string][]} */ (Object.entries(LOG_NAMES))) {
  test(`the ${deployment} pins accept exactly the client ids the shared provider table offers`, () => {
    const pins = pinsFor(logName);
    for (const p of PROVIDERS[deployment]) {
      const found = providerFor(pins, p.iss, p.clientId);
      if (p.clientId) assert.equal(found?.id, p.id, `${p.id} is pinned`);
      else assert.equal(found, null, `${p.id} has no client id and accepts none`);
    }
    assert.equal(providerFor(pins, "https://accounts.google.com", "another-client"), null);
  });

  test(`the ${deployment} pins hold a 32-byte log key from size 0 and a 32-byte salt commitment`, () => {
    const pins = pinsFor(logName);
    assert.equal(pins.logKeys[0].fromSize, 0);
    for (const k of pins.logKeys) assert.equal(fromBase64(k.publicKey).length, 32);
    assert.match(pins.saltCommitment, /^[0-9a-f]{64}$/);
    assert.match(pins.enroll[2].vkSha256, /^[0-9a-f]{64}$/);
  });
}

test("every pinned log is a deployment's log name", () => {
  assert.deepEqual(Object.keys(LOGS).sort(), Object.values(LOG_NAMES).sort());
});

test("the production log reads its own bucket, mirror and API under its own key", () => {
  const pins = pinsFor("log.emojery.app");
  assert.equal(logKeyAt(pins, 0)?.publicKey, "z0z5ZBrlz67P2+FD+kz5ayXyFQyCCB2rQzPxPUtery4=");
  assert.equal(pins.saltCommitment, "f4e779a98fcb7f5fb74bcd31c0332ac0f1db6e32829505b8ab3e6de178f60157");
  assert.equal(pins.bucket, "https://log.emojery.app");
  assert.equal(pins.mirror, "https://raw.githubusercontent.com/khasky/emojery-tlog/main");
  assert.equal(pins.api, "https://api.emojery.app");
  assert.equal(providerFor(pins, "https://api-staging.emojery.app/test-oidc", "emojery-staging-test"), null, "the staging test issuer is not accepted in production");
});

test("no two deployments share a log key, a salt commitment or a mirror", () => {
  const [a, b] = Object.values(LOGS);
  assert.notEqual(a.logKeys[0].publicKey, b.logKeys[0].publicKey);
  assert.notEqual(a.saltCommitment, b.saltCommitment);
  assert.notEqual(a.mirror, b.mirror);
  assert.notEqual(a.bucket, b.bucket);
  assert.notEqual(a.api, b.api);
});
