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
