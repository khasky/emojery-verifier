// SPDX-License-Identifier: Apache-2.0
// Keeping a mirror repository (docs/PROTOCOL.md §9-§10): one run of the check, then the
// files the shared history needs - every new anchor (whatever the verdict), the providers'
// live keys, index.json after a PASS, and one verdict line. The workflow in the mirror
// repository runs this and commits the directory; this module only writes files.
//
// What it never does: rewrite a file it already holds. An anchor that differs from the
// mirror's copy at the same size goes next to it as <size>.conflict-<sha256>.json, and
// latest.json stays where it was.

import { mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fromBase64Url, sha256, toHex, utf8 } from "@emojery/shared/core";
import { generations } from "./log.js";
import { text } from "./source.js";

/** @param {string} dir @param {string} path */
async function readLocal(dir, path) {
  try {
    return new Uint8Array(await readFile(join(dir, path)));
  } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code === "ENOENT") return null;
    throw e;
  }
}

/** @param {string} dir @param {string} path @param {Uint8Array} bytes */
async function writeLocal(dir, path, bytes) {
  await mkdir(dirname(join(dir, path)), { recursive: true });
  await writeFile(join(dir, path), bytes);
}

/** @param {Uint8Array} a @param {Uint8Array} b */
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * A host over a local checkout of the mirror, in the shape source.js hosts answer.
 * @param {string} dir
 */
export function localHost(dir) {
  return {
    base: dir,
    /** @param {string} path */
    get: async (path) => {
      const bytes = await readLocal(dir, path);
      return bytes ? { ok: /** @type {const} */ (true), bytes, headers: new Headers() } : { ok: /** @type {const} */ (false), missing: true, status: 404 };
    },
  };
}

/**
 * The canonical JSON of an RSA key, as PROTOCOL.md §10 names it.
 * @param {{ e: string, n: string }} k
 */
export function canonicalJwk(k) {
  return `{"e":"${k.e}","kty":"RSA","n":"${k.n}"}`;
}

/**
 * Writes the providers' live RSA keys the mirror does not hold yet. Returns the sha256 of
 * each file it added, for the verdict line's jwksAdded.
 * @param {string} dir @param {readonly import("./pins.js").Provider[]} providers
 * @param {(url: string) => Promise<any>} getJson @param {(s: string) => void} note
 */
export async function snapshotJwks(dir, providers, getJson, note) {
  /** @type {string[]} */
  const added = [];
  for (const p of providers) {
    let doc;
    try {
      doc = await getJson(p.jwksUri);
    } catch (e) {
      note(`jwks of ${p.id}: ${/** @type {Error} */ (e).message}`);
      continue;
    }
    for (const k of doc?.keys ?? []) {
      if (k?.kty !== "RSA" || typeof k.n !== "string" || typeof k.e !== "string") continue;
      const name = toHex(await sha256(fromBase64Url(k.n)));
      const path = `jwks/${p.id}/${name}.json`;
      if (await readLocal(dir, path)) continue;
      const bytes = utf8(canonicalJwk(k));
      await writeLocal(dir, path, bytes);
      added.push(toHex(await sha256(bytes)));
    }
  }
  return added;
}

/**
 * Copies the anchors of one generation from the bucket, newest first along `prev`, until
 * one the mirror already holds. Returns how many it wrote and whether any conflicted.
 * @param {string} dir @param {{ get: (p: string) => Promise<import("./source.js").ReadResult> }} bucket @param {string} prefix
 */
export async function mirrorAnchors(dir, bucket, prefix) {
  const latest = await bucket.get(`${prefix}/anchors/latest.json`);
  if (!latest.ok) return { written: 0, conflicts: 0 };
  let written = 0;
  let conflicts = 0;
  /** @type {Uint8Array | null} */
  let file = latest.bytes;
  let first = true;
  while (file) {
    const anchor = JSON.parse(new TextDecoder().decode(file));
    const size = Number(anchor.note.split("\n")[1]);
    const path = `${prefix}/anchors/${size}.json`;
    const held = await readLocal(dir, path);
    if (held && same(held, file)) break;
    if (held) {
      await writeLocal(dir, `${prefix}/anchors/${size}.conflict-${toHex(await sha256(file))}.json`, file);
      conflicts++;
      break;
    }
    await writeLocal(dir, path, file);
    written++;
    if (first) first = false;
    if (anchor.prev === undefined) break;
    const prev = await bucket.get(`${prefix}/anchors/${anchor.prev}.json`);
    file = prev.ok ? prev.bytes : null;
  }
  if (conflicts === 0 && written > 0) await writeLocal(dir, `${prefix}/anchors/latest.json`, latest.bytes);
  return { written, conflicts };
}

/**
 * After a check: the anchors of every generation, index.json on PASS, the verdict line.
 * @param {{ dir: string, bucket: any, logName: string, logKey: Uint8Array, report: import("./report.js").Report, state: { origin: string, size: number } | undefined, jwksAdded: string[], now: Date }} o
 */
export async function recordRun(o) {
  const { dir, bucket, report, state, jwksAdded, now } = o;
  const idx = await bucket.get("index.json");
  // A bad index.json has already failed the check; its anchors are still worth keeping.
  const gens = (await generations(idx.ok ? text(idx) : null, o.logName, o.logKey).catch(() => [{ generation: 0 }])).map((g) => g.generation);
  let anchors = 0;
  for (const g of gens) {
    const r = await mirrorAnchors(dir, bucket, `g${g}`);
    anchors += r.written;
    if (r.conflicts) report.fail(`g${g}: the bucket's anchor differs from the mirror's at the same size; kept beside it as a conflict file`);
  }
  if (report.verdict === "PASS" && idx.ok) {
    const held = await readLocal(dir, "index.json");
    if (!held || !same(held, idx.bytes)) await writeLocal(dir, "index.json", idx.bytes);
  }
  const line = {
    at: now.toISOString(),
    verdict: report.verdict,
    origin: state?.origin ?? null,
    size: state?.size ?? null,
    notes: [...report.failures, ...report.waits, ...report.warnings],
    jwksAdded,
  };
  const month = now.toISOString().slice(0, 7);
  await mkdir(join(dir, "verdicts"), { recursive: true });
  await appendFile(join(dir, "verdicts", `${month}.ndjson`), `${JSON.stringify(line)}\n`);
  return { anchors, message: `sync ${report.verdict} ${state?.origin ?? "-"} ${state?.size ?? "-"}` };
}

