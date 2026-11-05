import assert from "node:assert/strict";
import { test } from "node:test";
import { PROVIDERS } from "@emojery/shared/api";
import { pinsFor, providerFor } from "../src/pins.js";

test("the staging pins accept exactly the client ids the shared provider table offers", () => {
  const pins = pinsFor("log-staging.emojery.app");
  for (const p of PROVIDERS.staging) {
    const found = providerFor(pins, p.iss, p.clientId);
    if (p.clientId) assert.equal(found?.id, p.id, `${p.id} is pinned`);
    else assert.equal(found, null, `${p.id} has no client id and accepts none`);
  }
  assert.equal(providerFor(pins, "https://accounts.google.com", "another-client"), null);
});
