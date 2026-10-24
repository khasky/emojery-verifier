// SPDX-License-Identifier: Apache-2.0
// Trust anchors (docs/PROTOCOL.md §11), in code and per log name. Nothing here is read
// from a file the operator publishes: a pin changes only with a release of this
// verifier, which the reader installs on purpose.

/**
 * @typedef {object} Provider
 * @property {string} id
 * @property {string} iss exact issuer, one form
 * @property {readonly string[]} aud accepted client ids
 * @property {string} jwksUri
 *
 * @typedef {object} RekorShard
 * @property {string} origin the shard's checkpoint origin and key name
 * @property {string} publicKey base64 of the raw 32-byte Ed25519 key
 * @property {string} from ISO date the shard opened
 * @property {string | null} until ISO date it closed, null while open
 *
 * @typedef {object} LogPins
 * @property {{ publicKey: string, fromSize: number }[]} logKeys raw 32-byte Ed25519 keys, base64, with the first size each covers
 * @property {Record<number, { vkSha256: string }>} enroll verification-key hash per ENROLL version
 * @property {string} saltCommitment hex
 * @property {readonly Provider[]} providers
 * @property {string} mirror raw base URL of the log's mirror repository
 * @property {string} bucket base URL of the log's files
 * @property {string} api base URL of the counts API
 * @property {number} anchorIntervalS
 */

/** @type {readonly RekorShard[]} */
export const REKOR_SHARDS = Object.freeze([
  // sigstore/root-signing targets/trusted_root.json
  { origin: "log2025-1.rekor.sigstore.dev", publicKey: "t8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=", from: "2025-09-23", until: null },
]);

const GOOGLE = { id: "google", iss: "https://accounts.google.com", jwksUri: "https://www.googleapis.com/oauth2/v3/certs" };
// The personal-account tenant only; a work or school account has another issuer.
const MICROSOFT = { id: "microsoft", iss: "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0", jwksUri: "https://login.microsoftonline.com/consumers/discovery/v2.0/keys" };
const APPLE = { id: "apple", iss: "https://appleid.apple.com", jwksUri: "https://appleid.apple.com/auth/keys" };

/** @type {Readonly<Record<string, LogPins>>} */
export const LOGS = Object.freeze({
  // Client ids and the salt commitment are filled in when the staging providers exist.
  "log-staging.emojery.app": {
    logKeys: [{ publicKey: "P37N5YTTgfbn4L1oW4lLnQM7BsHQEYgY4QpnkYLNEaM=", fromSize: 0 }],
    enroll: { 2: { vkSha256: "ba44c95ba2fef66e7eff5b15590a9d5f55dae324239873180384f7d7a5a4321a" } },
    saltCommitment: "",
    providers: [
      { ...GOOGLE, aud: [] },
      { ...MICROSOFT, aud: [] },
      { ...APPLE, aud: [] },
      { id: "test", iss: "https://api-staging.emojery.app/test-oidc", aud: [], jwksUri: "https://api-staging.emojery.app/test-oidc/.well-known/jwks.json" },
    ],
    mirror: "https://raw.githubusercontent.com/khasky/emojery-tlog-staging/main",
    bucket: "https://log-staging.emojery.app",
    api: "https://api-staging.emojery.app",
    anchorIntervalS: 1800,
  },
});

/** @param {string} logName */
export function pinsFor(logName) {
  const p = LOGS[logName];
  if (!p) throw new Error(`no pins for log ${logName}`);
  return p;
}

/**
 * The log key that covers `size`: the last key whose fromSize is at most size.
 * @param {LogPins} pins @param {number} size
 */
export function logKeyAt(pins, size) {
  let key = null;
  for (const k of pins.logKeys) if (k.fromSize <= size) key = k;
  return key;
}

/** @param {LogPins} pins @param {string} iss @param {string} aud */
export function providerFor(pins, iss, aud) {
  return pins.providers.find((p) => p.iss === iss && p.aud.includes(aud)) ?? null;
}
