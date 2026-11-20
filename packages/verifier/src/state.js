// SPDX-License-Identifier: Apache-2.0
// The small state file a run keeps between runs: the anchored checkpoint it last pinned,
// and when it first saw the current unanchored tail. No pairs, no counts: --full folds
// from scratch every time. The format is local and not frozen.

import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const DEFAULT_STATE = join(homedir(), ".emojery-verifier", "state.json");

/**
 * @typedef {object} LogState
 * @property {string} origin
 * @property {number} size
 * @property {string} root base64
 * @property {number} anchoredAt
 * @property {{ size: number, firstSeen: number } | null} [tail]
 *
 * @typedef {{ version: 1, logs: Record<string, LogState> }} StateFile
 */

/** @param {string} path @returns {Promise<StateFile>} */
export async function loadState(path) {
  let raw;
  try {
    raw = await readFile(path, "utf8");
  } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code === "ENOENT") return { version: 1, logs: {} };
    throw e;
  }
  const s = JSON.parse(raw);
  if (s?.version !== 1 || typeof s.logs !== "object" || s.logs === null) throw new Error(`${path} is not a state file of this verifier`);
  return s;
}

/** Writes atomically: a crash leaves the old file or the new one, never half. @param {string} path @param {StateFile} state */
export async function saveState(path, state) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(state, null, 1)}\n`);
  await rename(tmp, path);
}
