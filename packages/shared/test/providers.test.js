import assert from "node:assert/strict";
import { test } from "node:test";
import { offeredIn, offeredProviders, PRODUCTION_PROVIDERS, PROVIDERS, providerByToken, providerIn, STAGING_PROVIDERS } from "../src/api/index.js";

test("production offers no test issuer and nothing without a client id", () => {
  assert.deepEqual(
    offeredProviders("production").map((p) => p.id),
    ["google", "microsoft", "apple"],
  );
  assert.ok(!PROVIDERS.production.some((p) => p.id === "test"));
});

test("staging adds the test issuer", () => {
  assert.deepEqual(
    offeredProviders("staging").map((p) => p.id),
    ["google", "microsoft", "apple", "test"],
  );
});

test("a token is matched by its exact iss and aud", () => {
  assert.equal(providerByToken("production", "https://accounts.google.com", PROVIDERS.production[0].clientId)?.id, "google");
  assert.equal(providerByToken("production", "accounts.google.com", PROVIDERS.production[0].clientId), null);
  assert.equal(providerByToken("production", "https://api-staging.emojery.app/test-oidc", "emojery-staging-test"), null);
  const microsoft = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0";
  assert.equal(providerByToken("staging", microsoft, "9df5358c-98b0-43fd-a6cc-e1f373243e9d")?.id, "microsoft");
  assert.equal(providerByToken("staging", microsoft, "54fe9a8a-4525-42b2-917a-49958391f7c9"), null);
});

test("Apple returns through the deployment's own API host", () => {
  assert.equal(PROVIDERS.production.find((p) => p.id === "apple")?.redirectUri, "https://api.emojery.app/v2/auth/apple/return");
  assert.equal(PROVIDERS.staging.find((p) => p.id === "apple")?.redirectUri, "https://api-staging.emojery.app/v2/auth/apple/return");
});

test("each deployment table is its own export, and the list helpers agree with the named ones", () => {
  assert.equal(PROVIDERS.production, PRODUCTION_PROVIDERS);
  assert.equal(PROVIDERS.staging, STAGING_PROVIDERS);
  assert.deepEqual(offeredIn(STAGING_PROVIDERS), offeredProviders("staging"));
  assert.equal(providerIn(STAGING_PROVIDERS, "https://api-staging.emojery.app/test-oidc", "emojery-staging-test")?.id, "test");
  assert.ok(Object.isFrozen(STAGING_PROVIDERS) && STAGING_PROVIDERS.every((p) => Object.isFrozen(p)));
});
