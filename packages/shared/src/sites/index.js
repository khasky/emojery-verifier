// SPDX-License-Identifier: Apache-2.0
// The rules of every site Emojery reacts on: where it runs, how a page URL becomes a
// target_id, what a target_id may look like, and how to get back to the page. The
// extension derives ids with these functions, the publisher accepts only ids that match
// `idPattern`, and the site and the admin panel link back with `targetUrl`. A target_id
// is the only user-influenced text in the public log, so it is a platform id and nothing
// else: no slugs, no free text, one spelling per item.
//
// A verifier does not apply these rules to published leaves (docs/PROTOCOL.md §3.5).

/**
 * @typedef {object} Site
 * @property {ReadonlySet<string>} hosts exact host names; never a pattern
 * @property {((url: URL) => string | null) | null} fromUrl URL → id, null when the URL
 *   is not a target; null for a site whose id comes from the page, not the URL
 * @property {RegExp} idPattern the only shapes an id may take
 * @property {(id: string) => string | null} toUrl id → page URL, null when one-way
 */

const RESERVED_GITHUB = new Set(["about", "codespaces", "collections", "contact", "events", "explore", "features", "issues", "login", "logout", "marketplace", "new", "notifications", "organizations", "orgs", "pricing", "pulls", "search", "settings", "signup", "site", "sponsors", "topics", "trending"]);
const RESERVED_GITLAB = new Set(["-", "admin", "dashboard", "explore", "groups", "help", "oauth", "profile", "projects", "search", "users"]);

/** @param {string} id */
const encodePath = (id) => id.split("/").map(encodeURIComponent).join("/");

/** @param {RegExpMatchArray | null} m @param {number} i */
const group = (m, i) => m?.[i] ?? null;

/** @type {Readonly<Record<string, Site>>} */
export const SITES = Object.freeze({
  x: {
    hosts: new Set(["x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com"]),
    fromUrl: (url) => group(url.pathname.match(/^\/[A-Za-z0-9_]{1,20}\/status\/([1-9][0-9]{0,18})(?:\/(?:analytics|photo\/\d+|video\/\d+))?\/?$/), 1),
    idPattern: /^[1-9][0-9]{0,18}$/,
    toUrl: (id) => `https://x.com/i/status/${id}`,
  },
  youtube: {
    hosts: new Set(["youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be"]),
    fromUrl: (url) => {
      const id = url.hostname === "youtu.be" ? group(url.pathname.match(/^\/([A-Za-z0-9_-]{11})(?:\/|$)/), 1) : ((url.pathname === "/watch" ? url.searchParams.get("v") : null) ?? group(url.pathname.match(/^\/(?:shorts|embed|live)\/([A-Za-z0-9_-]{11})(?:\/|$)/), 1));
      return id && /^[A-Za-z0-9_-]{11}$/.test(id) ? id : null;
    },
    idPattern: /^[A-Za-z0-9_-]{11}$/,
    toUrl: (id) => `https://www.youtube.com/watch?v=${id}`,
  },
  reddit: {
    hosts: new Set(["reddit.com", "www.reddit.com", "redd.it"]),
    fromUrl: (url) => {
      // A comment permalink (/r/<sub>/comments/<id>/<slug>/<comment>/) names its post too.
      const id = url.hostname === "redd.it" ? group(url.pathname.match(/^\/([A-Za-z0-9]{1,13})\/?$/), 1) : group(url.pathname.match(/^\/(?:r|user)\/[^/]+\/comments\/([A-Za-z0-9]{1,13})(?:\/|$)/i) ?? url.pathname.match(/^\/(?:comments|gallery)\/([A-Za-z0-9]{1,13})(?:\/|$)/i), 1);
      return id ? `t3_${id.toLowerCase()}` : null;
    },
    idPattern: /^t3_[0-9a-z]{1,13}$/,
    toUrl: (id) => `https://www.reddit.com/comments/${id.slice(3)}/`,
  },
  instagram: {
    hosts: new Set(["instagram.com", "www.instagram.com"]),
    fromUrl: (url) => {
      const m = url.pathname.match(/^\/(?:[A-Za-z0-9._]{1,30}\/)?(p|reel|reels|tv)\/([A-Za-z0-9_-]{1,64})(?:\/|$)/);
      if (!m || (m[1] === "reels" && m[2] === "audio")) return null;
      return m[2];
    },
    idPattern: /^[A-Za-z0-9_-]{1,64}$/,
    toUrl: (id) => `https://www.instagram.com/p/${id}/`,
  },
  threads: {
    hosts: new Set(["threads.com", "www.threads.com", "threads.net", "www.threads.net"]),
    fromUrl: (url) => group(url.pathname.match(/^\/@[A-Za-z0-9._]{1,30}\/post\/([A-Za-z0-9_-]{1,64})(?:\/|$)/) ?? url.pathname.match(/^\/t\/([A-Za-z0-9_-]{1,64})\/?$/), 1),
    idPattern: /^[A-Za-z0-9_-]{1,64}$/,
    toUrl: (id) => `https://www.threads.com/t/${id}`,
  },
  github: {
    hosts: new Set(["github.com"]),
    // GitHub names are case-insensitive, so the id is lowercase: Khasky/Emojery and
    // khasky/emojery are one repository and one key.
    fromUrl: (url) => {
      const m = url.pathname.match(/^\/([^/]+)\/([^/]+?)\/?$/);
      if (!m) return null;
      const owner = m[1].toLowerCase();
      const repo = m[2].toLowerCase();
      if (RESERVED_GITHUB.has(owner)) return null;
      const id = `${owner}/${repo}`;
      return SITES.github.idPattern.test(id) ? id : null;
    },
    idPattern: /^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}\/(?!\.{1,2}$)[a-z0-9._-]{1,100}$/,
    toUrl: (id) => `https://github.com/${encodePath(id)}`,
  },
  amazon: {
    hosts: new Set(["www.amazon.com", "www.amazon.co.uk", "www.amazon.de", "www.amazon.fr", "www.amazon.it", "www.amazon.es", "www.amazon.ca", "www.amazon.com.au", "www.amazon.co.jp", "www.amazon.in", "www.amazon.com.br", "www.amazon.com.mx", "smile.amazon.com"]),
    fromUrl: (url) => {
      for (const re of [/\/dp\/([A-Z0-9]{10})(?:[/?]|$)/i, /\/gp\/product\/([A-Z0-9]{10})(?:[/?]|$)/i, /\/product\/([A-Z0-9]{10})(?:[/?]|$)/i]) {
        const id = group(url.pathname.match(re), 1);
        if (id) return id.toUpperCase();
      }
      return null;
    },
    idPattern: /^[A-Z0-9]{10}$/,
    toUrl: (id) => `https://www.amazon.com/dp/${id}`,
  },
  rottentomatoes: {
    hosts: new Set(["www.rottentomatoes.com"]),
    fromUrl: (url) => {
      const p = url.pathname.toLowerCase();
      const movie = group(p.match(/^\/m\/([a-z0-9_-][a-z0-9_.-]{0,119})\/?$/), 1);
      if (movie) return `m/${movie}`;
      const tv = p.match(/^\/tv\/([a-z0-9_-][a-z0-9_.-]{0,119})(?:\/(s\d{1,3})(?:\/(e\d{1,4}))?)?\/?$/);
      if (!tv) return null;
      return `tv/${tv[1]}${tv[2] ? `/${tv[2]}` : ""}${tv[3] ? `/${tv[3]}` : ""}`;
    },
    idPattern: /^(?:m\/[a-z0-9_-][a-z0-9_.-]{0,119}|tv\/[a-z0-9_-][a-z0-9_.-]{0,119}(?:\/s\d{1,3}(?:\/e\d{1,4})?)?)$/,
    toUrl: (id) => `https://www.rottentomatoes.com/${encodePath(id)}`,
  },
  tmdb: {
    hosts: new Set(["www.themoviedb.org"]),
    fromUrl: (url) => {
      const m = url.pathname.match(/^\/(movie|tv|collection)\/([1-9][0-9]{0,11})(?:-[^/]*)?\/?$/);
      return m ? `${m[1]}/${m[2]}` : null;
    },
    idPattern: /^(?:movie|tv|collection)\/[1-9][0-9]{0,11}$/,
    toUrl: (id) => `https://www.themoviedb.org/${id}`,
  },
  imdb: {
    hosts: new Set(["www.imdb.com"]),
    // IMDb ids keep their zero padding: tt0959621 is the title, tt959621 is not.
    fromUrl: (url) => group(url.pathname.toLowerCase().match(/^\/title\/(tt[0-9]{7,10})\/?$/), 1),
    idPattern: /^tt[0-9]{7,10}$/,
    toUrl: (id) => `https://www.imdb.com/title/${id}/`,
  },
  metacritic: {
    hosts: new Set(["www.metacritic.com"]),
    fromUrl: (url) => {
      const product = url.pathname.match(/^\/(movie|game)\/([a-z0-9-]{1,120})\/?$/);
      if (product) return `${product[1]}/${product[2]}`;
      const tv = url.pathname.match(/^\/tv\/([a-z0-9-]{1,120})(?:\/(season-[1-9][0-9]{0,2}))?\/?$/);
      if (!tv) return null;
      return `tv/${tv[1]}${tv[2] ? `/${tv[2]}` : ""}`;
    },
    idPattern: /^(?:(?:movie|game)\/[a-z0-9-]{1,120}|tv\/[a-z0-9-]{1,120}(?:\/season-[1-9][0-9]{0,2})?)$/,
    toUrl: (id) => `https://www.metacritic.com/${id}/`,
  },
  opencritic: {
    hosts: new Set(["opencritic.com"]),
    fromUrl: (url) => group(url.pathname.match(/^\/game\/([1-9][0-9]{0,11})\/[^/]+\/?$/), 1),
    idPattern: /^[1-9][0-9]{0,11}$/,
    // The site needs a slug segment the id does not carry.
    toUrl: () => null,
  },
  gitlab: {
    hosts: new Set(["gitlab.com"]),
    // The canonical id is the numeric project id the page carries; the URL gives only
    // the path form, which the extension uses when the page has no id.
    fromUrl: null,
    idPattern: /^(?:[1-9][0-9]{0,11}|(?!\.{1,2}(?:\/|$))[A-Za-z0-9_][A-Za-z0-9._-]{0,254}(?:\/(?!\.{1,2}(?:\/|$))[A-Za-z0-9_][A-Za-z0-9._-]{0,254})+)$/,
    toUrl: (id) => (/^[0-9]+$/.test(id) ? null : `https://gitlab.com/${encodePath(id)}`),
  },
  facebook: {
    hosts: new Set(["facebook.com", "www.facebook.com", "m.facebook.com"]),
    // Four forms, all read from the page: a numeric post id, a pfbid, photo:<fbid> for a
    // photo with no post of its own, and url:<28 base36> - a hash of the post URL when
    // the post shows neither a permalink nor an fbid.
    fromUrl: null,
    idPattern: /^(?:[1-9][0-9]{5,24}|pfbid[A-Za-z0-9]{20,100}|photo:[1-9][0-9]{5,24}|url:[0-9a-z]{28})$/,
    toUrl: (id) => {
      if (id.startsWith("url:")) return null;
      if (id.startsWith("photo:")) return `https://www.facebook.com/photo/?fbid=${id.slice(6)}`;
      return `https://www.facebook.com/${id}`;
    },
  },
});

export const SITE_NAMES = Object.freeze(Object.keys(SITES));

/** @param {string} site */
export function isSite(site) {
  return Object.hasOwn(SITES, site);
}

/**
 * The site whose host list holds this URL's host, or null.
 * @param {string} rawUrl
 */
export function siteForUrl(rawUrl) {
  const url = URL.canParse(rawUrl) ? new URL(rawUrl) : null;
  if (!url || url.protocol !== "https:") return null;
  for (const name of SITE_NAMES) if (SITES[name].hosts.has(url.hostname)) return name;
  return null;
}

/**
 * URL → target_id for a site, or null: unknown site, a host outside the site's list, a
 * URL that is not a target, or a site whose id comes from the page.
 * @param {string} site @param {string} rawUrl
 */
export function targetIdFromUrl(site, rawUrl) {
  if (!isSite(site)) return null;
  const rule = SITES[site];
  const url = URL.canParse(rawUrl) ? new URL(rawUrl) : null;
  if (!url || url.protocol !== "https:" || !rule.hosts.has(url.hostname) || !rule.fromUrl) return null;
  const id = rule.fromUrl(url);
  return id !== null && rule.idPattern.test(id) ? id : null;
}

/**
 * True when `targetId` is a valid id of `site`: the publisher's acceptance rule.
 * @param {string} site @param {string} targetId
 */
export function isValidTargetId(site, targetId) {
  return isSite(site) && typeof targetId === "string" && SITES[site].idPattern.test(targetId);
}

/**
 * The page of a target, or null where the id does not lead back to one.
 * @param {string} site @param {string} targetId
 */
export function targetUrl(site, targetId) {
  return isValidTargetId(site, targetId) ? SITES[site].toUrl(targetId) : null;
}
