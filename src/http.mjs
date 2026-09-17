// SPDX-License-Identifier: GPL-3.0-or-later
// HTTP access to the public API, the log repo and the GitHub listing API.

import { detail } from "./report.mjs";

// A full audit of a large log is thousands of metered requests, and a bare throw on
// the first 429 loses the whole run with no resume. Retry-After is honoured when
// sent, otherwise exponential backoff.
const RETRY_STATUS = new Set([429, 500, 502, 503, 504]);
export const RETRY_MAX = 4;
const RETRY_AFTER_CAP_S = 60;

export async function getRes(url, attempt = 0) {
  const res = await fetch(url);
  if (res.ok || attempt >= RETRY_MAX || !RETRY_STATUS.has(res.status)) return res;
  const after = Number(res.headers.get("retry-after"));
  const waitMs = Number.isFinite(after) && after > 0 ? Math.min(after, RETRY_AFTER_CAP_S) * 1000 : 2 ** attempt * 1000;
  detail(`${res.status} on ${new URL(url).pathname} - retry ${attempt + 1}/${RETRY_MAX} in ${waitMs / 1000}s`);
  await new Promise((r) => setTimeout(r, waitMs));
  return getRes(url, attempt + 1);
}

export async function getJson(url) {
  const res = await getRes(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

export async function getBytes(url) {
  const res = await getRes(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

// The status rides on the error so a caller can tell an unpublished file (404)
// from a broken mirror.
export async function getText(url) {
  const res = await getRes(url);
  if (!res.ok) {
    const err = new Error(`GET ${url} -> ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return res.text();
}

// Whether the API serves a log with no checkpoint at all. Only a 404 whose body is
// the documented no_checkpoint error counts, so a 404 from a dropped route, a proxy
// or a mistyped --api still fails the run.
export async function emptyLog(api) {
  const res = await getRes(`${api}/log/checkpoint`);
  if (res.status !== 404) return false;
  const body = await res.json().catch(() => null);
  return body?.error === "no_checkpoint";
}

export function githubSlugFromRawBase(repo) {
  const m = /^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)\/?$/.exec(repo);
  return m ? { owner: m[1], repo: m[2], ref: m[3] } : null;
}

// File names in a log-repo directory. Returns { names }, { rateLimited: true } when
// GitHub throttles the listing, { missing: true } for an absent directory, or null
// for a non-GitHub base. GITHUB_TOKEN lifts the unauthenticated quota.
//
// The Contents API caps a listing at 1000 entries without paginating; past that the
// directory is re-listed through the Git Trees API, and a Trees listing that itself
// truncates is flagged so a completeness check is never read as exhaustive.
export async function listRepoDir(repo, dir) {
  const slug = githubSlugFromRawBase(repo);
  if (!slug) return null;
  const headers = { accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
  const listUrl = `https://api.github.com/repos/${slug.owner}/${slug.repo}/contents/${dir}?ref=${slug.ref}`;
  const res = await fetch(listUrl, { headers });
  if (res.status === 403 || res.status === 429) return { rateLimited: true };
  if (res.status === 404) return { missing: true };
  if (!res.ok) throw new Error(`GET ${listUrl} -> ${res.status}`);
  const listing = await res.json();
  const names = (Array.isArray(listing) ? listing : []).map((f) => f.name).filter((n) => typeof n === "string");
  if (names.length >= 1000) {
    const viaTree = await listRepoDirViaTree(slug, dir, headers);
    if (viaTree) return viaTree;
  }
  return { names };
}

async function listRepoDirViaTree(slug, dir, headers) {
  const base = `https://api.github.com/repos/${slug.owner}/${slug.repo}/git/trees`;
  const rootRes = await fetch(`${base}/${encodeURIComponent(slug.ref)}`, { headers });
  if (!rootRes.ok) return null;
  const root = await rootRes.json();
  const entry = (root.tree ?? []).find((e) => e.path === dir && e.type === "tree");
  if (!entry?.sha) return null;
  const dirRes = await fetch(`${base}/${entry.sha}`, { headers });
  if (!dirRes.ok) return null;
  const tree = await dirRes.json();
  const names = (tree.tree ?? []).filter((e) => e.type === "blob" && typeof e.path === "string").map((e) => e.path);
  if (tree.truncated) {
    detail(`NOTE: ${dir}/ listing truncated by the GitHub Trees API - the archive/rekor completeness check covers the listed subset only`);
    return { names, truncated: true };
  }
  return { names };
}
