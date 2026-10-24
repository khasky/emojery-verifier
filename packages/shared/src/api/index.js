// SPDX-License-Identifier: Apache-2.0
// The public client contract that is not the log itself: log names per deployment,
// the canonical paths of counts and badges, and the public catalog of restriction
// reasons.

import { decodeUtf8, EncodingError, fromBase64Url, toBase64Url, utf8 } from "../core/bytes.js";
import { isSite, isValidTargetId } from "../sites/index.js";

export const LOG_NAMES = Object.freeze({ production: "log.emojery.app", staging: "log-staging.emojery.app" });

/**
 * The origin a client starts from before a sign-in tells it otherwise.
 * @param {"production" | "staging"} deployment
 */
export function initialOrigin(deployment) {
  return `${LOG_NAMES[deployment]}/g0`;
}

/** Restriction reasons a REVOKE and a 403 may carry; the catalog only grows. */
export const RESTRICTION_REASONS = Object.freeze(["coordinated_voting", "multiple_accounts", "automation", "abuse_other"]);

/**
 * `/v2/counts/<site>/<base64url(target_id)>.json`: one path segment over an alphabet no
 * URL normaliser rewrites, so one target has one cache key.
 * @param {string} site @param {string} targetId
 */
export function countsPath(site, targetId) {
  if (!isValidTargetId(site, targetId)) throw new RangeError(`not a target of ${site}`);
  return `/v2/counts/${site}/${toBase64Url(utf8(targetId))}.json`;
}

/**
 * The inverse of countsPath, or null for any path countsPath would not produce.
 * @param {string} path
 */
export function parseCountsPath(path) {
  const m = /^\/v2\/counts\/([a-z0-9]{1,32})\/([A-Za-z0-9_-]+)\.json$/.exec(path);
  if (!m || !isSite(m[1])) return null;
  let targetId;
  try {
    targetId = decodeUtf8(fromBase64Url(m[2]));
  } catch (e) {
    if (e instanceof EncodingError) return null;
    throw e;
  }
  if (!isValidTargetId(m[1], targetId) || countsPath(m[1], targetId) !== path) return null;
  return { site: m[1], targetId };
}

/**
 * `/badge/<site>/<target_id>.<svg|json>` with the raw id (a GitHub id keeps its slash).
 * @param {string} site @param {string} targetId @param {"svg" | "json"} ext
 */
export function badgePath(site, targetId, ext) {
  if (!isValidTargetId(site, targetId)) throw new RangeError(`not a target of ${site}`);
  if (ext !== "svg" && ext !== "json") throw new RangeError("badge is svg or json");
  return `/badge/${site}/${targetId}.${ext}`;
}

/**
 * The inverse of badgePath, or null.
 * @param {string} path
 */
export function parseBadgePath(path) {
  const m = /^\/badge\/([a-z0-9]{1,32})\/(.+)\.(svg|json)$/.exec(path);
  if (!m || !isValidTargetId(m[1], m[2])) return null;
  return { site: m[1], targetId: m[2], ext: /** @type {"svg" | "json"} */ (m[3]) };
}

/**
 * @typedef {object} Provider
 * @property {string} id
 * @property {string} iss exact issuer, one form
 * @property {string} jwksUri
 * @property {string} clientId the `aud` of its id_tokens; an empty one is not offered
 * @property {string} authorize authorization endpoint the client opens
 * @property {string} responseType
 * @property {string} [responseMode]
 * @property {string} [scope] absent: no scope parameter is sent
 * @property {string} [redirectUri] a registered web page that forwards the fragment
 */

const GOOGLE_CLIENT_ID = "368200727057-40v0prpc56gpqiv6oiu3rval6su4jbuf.apps.googleusercontent.com";
// The personal-account registration is created before genesis; until then Microsoft is not offered.
const MICROSOFT_CLIENT_ID = "";
const APPLE_SERVICES_ID = "app.emojery.web";

/** @param {string} apiBase @returns {Provider[]} */
function realProviders(apiBase) {
  return [
    { id: "google", iss: "https://accounts.google.com", jwksUri: "https://www.googleapis.com/oauth2/v3/certs", clientId: GOOGLE_CLIENT_ID, authorize: "https://accounts.google.com/o/oauth2/v2/auth", responseType: "id_token", scope: "openid" },
    {
      id: "microsoft",
      // The personal-account tenant only; a work or school account has another issuer.
      iss: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
      jwksUri: "https://login.microsoftonline.com/consumers/discovery/v2.0/keys",
      clientId: MICROSOFT_CLIENT_ID,
      authorize: "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize",
      responseType: "id_token",
      responseMode: "fragment",
      scope: "openid",
    },
    { id: "apple", iss: "https://appleid.apple.com", jwksUri: "https://appleid.apple.com/auth/keys", clientId: APPLE_SERVICES_ID, authorize: "https://appleid.apple.com/auth/authorize", responseType: "code id_token", responseMode: "fragment", redirectUri: `${apiBase}/v2/auth/apple/return` },
  ];
}

/**
 * The sign-in providers per deployment, fixed in code: a change is a release. Staging adds
 * its test issuer. The Worker checks `iss` and `aud` against this table, the client builds
 * its sign-in list from it, the verifier pins the same values.
 */
export const PROVIDERS = Object.freeze({
  production: Object.freeze(realProviders("https://api.emojery.app").map((p) => Object.freeze(p))),
  staging: Object.freeze(
    [
      ...realProviders("https://api-staging.emojery.app"),
      {
        id: "test",
        iss: "https://api-staging.emojery.app/test-oidc",
        jwksUri: "https://api-staging.emojery.app/test-oidc/.well-known/jwks.json",
        clientId: "emojery-staging-test",
        authorize: "https://api-staging.emojery.app/test-oidc/authorize",
        responseType: "id_token",
        responseMode: "fragment",
        scope: "openid",
      },
    ].map((p) => Object.freeze(p)),
  ),
});

/**
 * The providers a client offers: those with a client id.
 * @param {"production" | "staging"} deployment
 */
export function offeredProviders(deployment) {
  return PROVIDERS[deployment].filter((p) => p.clientId !== "");
}

/**
 * The provider an id_token names by its exact `iss` and `aud`, or null.
 * @param {"production" | "staging"} deployment @param {string} iss @param {string} aud
 */
export function providerByToken(deployment, iss, aud) {
  return PROVIDERS[deployment].find((p) => p.iss === iss && p.clientId !== "" && p.clientId === aud) ?? null;
}
