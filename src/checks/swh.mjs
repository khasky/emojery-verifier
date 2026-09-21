// SPDX-License-Identifier: GPL-3.0-or-later
// The archival witness (--swh): Software Heritage, an independently operated archive,
// holds a recent copy of the log repository, and the copy is a state this repository
// really had. Read from SWH's own public API, never from anything the operator wrote:
// a file in the log repo saying "archived" is a claim, the archive's visit record is
// the fact.

import { githubSlugFromRawBase } from "../http.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { detail } from "../report.mjs";

const SWH_API = "https://archive.softwareheritage.org/api/1";
const DAY_MS = 86_400_000;
// SWH fronts its site with a challenge for browser-shaped user agents; a plain client
// naming itself and asking for JSON is answered directly.
const SWH_HEADERS = { accept: "application/json", "user-agent": "emojery-verifier" };

// The newest completed visit, and whether it is recent enough. Pure, for the selftest.
export function pickSwhVisit(visits, now, maxAgeDays) {
  const full = (Array.isArray(visits) ? visits : []).filter((v) => v?.status === "full" && v?.snapshot && v?.date).sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
  const newest = full[0] ?? null;
  if (!newest) return { visit: null, fresh: false, ageDays: null };
  const ageDays = (now - Date.parse(newest.date)) / DAY_MS;
  return { visit: newest, fresh: ageDays <= maxAgeDays, ageDays };
}

async function swhJson(url) {
  const res = await fetch(url, { headers: SWH_HEADERS });
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

// The branch head SWH archived, out of the snapshot's branches: main, or whatever HEAD
// aliases to.
function archivedHead(snapshot) {
  const branches = snapshot?.branches ?? {};
  const main = branches["refs/heads/main"];
  if (main?.target_type === "revision") return main.target;
  const head = branches.HEAD;
  if (head?.target_type === "alias") {
    const t = branches[head.target];
    if (t?.target_type === "revision") return t.target;
  }
  if (head?.target_type === "revision") return head.target;
  return null;
}

export async function verifySwh(repo, { enabled, maxAgeDays }) {
  if (!enabled) return null;
  const slug = repo ? githubSlugFromRawBase(repo) : null;
  if (!slug) {
    skipCheck("Software Heritage archive (--repo is not a raw.githubusercontent.com base)", "swh");
    return null;
  }
  const origin = `https://github.com/${slug.owner}/${slug.repo}`;

  // Remote leg one: the visits. An unreachable archive is an outage, not evidence.
  let visits;
  try {
    visits = await swhJson(`${SWH_API}/origin/${origin}/visits/?per_page=20`);
  } catch (e) {
    skipCheck(`Software Heritage archive (archive.softwareheritage.org unreachable: ${e.message})`, "swh");
    return null;
  }
  const { visit, fresh, ageDays } = pickSwhVisit(visits, Date.now(), maxAgeDays);
  check(visit !== null, `Software Heritage has archived ${slug.owner}/${slug.repo} (a completed visit exists)`, "swh");
  if (!visit) return null;
  check(fresh, `Software Heritage archived it ${ageDays.toFixed(1)} day(s) ago (allowed ${maxAgeDays})`, "swh");

  // Remote leg two: the archived head is a commit of this repository. A snapshot of
  // some other history would pass the age check and prove nothing.
  let snapshot;
  try {
    snapshot = await swhJson(`${SWH_API}/snapshot/${visit.snapshot}/`);
  } catch (e) {
    skipCheck(`Software Heritage snapshot ${visit.snapshot.slice(0, 12)}... (fetch failed: ${e.message})`, "swh");
    return visit.snapshot;
  }
  const head = archivedHead(snapshot);
  check(head !== null, "the archived snapshot names a main branch head", "swh");
  if (!head) return null;
  const headers = { accept: "application/vnd.github+json", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
  const commitRes = await fetch(`https://api.github.com/repos/${slug.owner}/${slug.repo}/commits/${head}`, { headers });
  if (commitRes.status === 403 || commitRes.status === 429) {
    skipCheck(`the archived head ${head.slice(0, 12)}... against the repository (GitHub API rate-limited; set GITHUB_TOKEN to lift the quota)`, "swh");
    return visit.snapshot;
  }
  // 404 is the one answer that means the archived history is not this repository's;
  // 422 is GitHub's word for a malformed sha, which the archive would never produce.
  check(commitRes.ok, `the archived head ${head.slice(0, 12)}... is a commit of the repository`, "swh");
  if (!commitRes.ok) return null;
  detail(`swh:1:snp:${visit.snapshot} archived ${visit.date}`);
  return visit.snapshot;
}
