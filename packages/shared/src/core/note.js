// SPDX-License-Identifier: Apache-2.0
// C2SP signed notes (c2sp.org/signed-note) with Ed25519 keys, the checkpoint body
// (c2sp.org/tlog-checkpoint) and the rewind record of docs/PROTOCOL.md §7 and §9.

import { concat, equalBytes, fromBase64, toBase64, utf8 } from "./bytes.js";
import { sha256 } from "./messages.js";

export class NoteError extends Error {
  name = "NoteError";
}

const SIG_PREFIX = "— ";
const KEY_NAME = /^[^\s+]+$/;
const ED25519 = 0x01;

/**
 * The 4-byte key id of an Ed25519 note key.
 * @param {string} name @param {Uint8Array} publicKey 32 bytes
 */
export async function noteKeyId(name, publicKey) {
  if (!KEY_NAME.test(name)) throw new NoteError("bad key name");
  if (publicKey.length !== 32) throw new NoteError("Ed25519 public key must be 32 bytes");
  return (await sha256(concat(utf8(name), Uint8Array.of(0x0a, ED25519), publicKey))).subarray(0, 4);
}

/**
 * Splits a signed note into its text and signature lines. Signature lines under any name
 * are returned; a caller verifies the ones it knows and ignores the rest.
 * @param {string} note
 */
export function parseNote(note) {
  if (!note.isWellFormed()) throw new NoteError("note is not well-formed");
  const split = note.lastIndexOf("\n\n");
  if (split < 0) throw new NoteError("note has no signature block");
  const text = note.slice(0, split + 1);
  const block = note.slice(split + 2);
  if (text.length === 0 || text.includes("\n\n") || /[\x00-\x09\x0b-\x1f]/.test(text)) throw new NoteError("bad note text");
  if (!block.endsWith("\n")) throw new NoteError("signature block must end with a newline");
  const signatures = [];
  for (const line of block.slice(0, -1).split("\n")) {
    if (!line.startsWith(SIG_PREFIX)) throw new NoteError("malformed signature line");
    const rest = line.slice(SIG_PREFIX.length);
    const space = rest.lastIndexOf(" ");
    if (space <= 0) throw new NoteError("malformed signature line");
    const name = rest.slice(0, space);
    if (!KEY_NAME.test(name)) throw new NoteError("bad key name in signature line");
    const raw = fromBase64(rest.slice(space + 1));
    if (raw.length < 5) throw new NoteError("signature too short");
    signatures.push({ name, keyId: raw.subarray(0, 4), signature: raw.subarray(4) });
  }
  if (signatures.length === 0) throw new NoteError("note has no signatures");
  return { text, signatures };
}

/** @param {Uint8Array} raw */
async function importEd25519(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

/**
 * Verifies that `note` carries a valid Ed25519 signature by `publicKey` under `name`.
 * Returns the note text. Signatures under other names, or under this name with another
 * key id, are ignored; a second line for the same key is a failure.
 * @param {string} note @param {string} name @param {Uint8Array} publicKey
 */
export async function verifyNote(note, name, publicKey) {
  const { text, signatures } = parseNote(note);
  const id = await noteKeyId(name, publicKey);
  const mine = signatures.filter((s) => s.name === name && equalBytes(s.keyId, id));
  if (mine.length === 0) throw new NoteError(`no signature by ${name}`);
  if (mine.length > 1) throw new NoteError(`more than one signature by ${name}`);
  if (mine[0].signature.length !== 64) throw new NoteError("Ed25519 signature must be 64 bytes");
  const key = await importEd25519(publicKey);
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, key, mine[0].signature, utf8(text));
  if (!ok) throw new NoteError(`signature by ${name} does not verify`);
  return text;
}

/**
 * Signs note text with an Ed25519 CryptoKey; the publisher's side and the tests'.
 * @param {string} text ending in "\n" @param {string} name @param {CryptoKey} privateKey @param {Uint8Array} publicKey
 */
export async function signNote(text, name, privateKey, publicKey) {
  if (!text.endsWith("\n") || text.includes("\n\n")) throw new NoteError("note text must end in one newline and hold no blank line");
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, utf8(text)));
  return `${text}\n${SIG_PREFIX}${name} ${toBase64(concat(await noteKeyId(name, publicKey), sig))}\n`;
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

/** @param {string} s @param {string} what */
function decimal(s, what) {
  if (!DECIMAL.test(s)) throw new NoteError(`${what} is not a decimal`);
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new NoteError(`${what} is too large`);
  return n;
}

/** @param {string} s @param {string} what */
function hash32(s, what) {
  const b = fromBase64(s);
  if (b.length !== 32) throw new NoteError(`${what} is not 32 bytes`);
  return b;
}

/**
 * The checkpoint body: origin, size, root, then extension lines a verifier ignores.
 * @param {string} text
 */
export function parseCheckpoint(text) {
  const lines = text.slice(0, -1).split("\n");
  if (lines.length < 3) throw new NoteError("checkpoint needs origin, size and root");
  const [origin, size, root, ...extensions] = lines;
  if (origin.length === 0) throw new NoteError("empty origin");
  return { origin, size: decimal(size, "size"), root: hash32(root, "root"), extensions };
}

/** @param {{ origin: string, size: number, root: Uint8Array }} c */
export function checkpointText(c) {
  return `${c.origin}\n${c.size}\n${toBase64(c.root)}\n`;
}

export const REWIND_TAG = "emojery-rewind-v1";

/**
 * The rewind record body of §9.
 * @param {string} text
 */
export function parseRewind(text) {
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== 9 || lines[0] !== REWIND_TAG) throw new NoteError("not a rewind record");
  const [, origin, forkedFrom, at, n, rootN, m, rootM, reason] = lines;
  const r = {
    origin,
    forkedFrom,
    at: decimal(at, "at"),
    n: decimal(n, "N"),
    rootN: hash32(rootN, "rootN"),
    m: decimal(m, "M"),
    rootM: hash32(rootM, "rootM"),
    reason,
  };
  if (r.m < r.n) throw new NoteError("M is below N");
  if (reason.length === 0) throw new NoteError("empty reason");
  return r;
}

/** @param {{ origin: string, forkedFrom: string, at: number, n: number, rootN: Uint8Array, m: number, rootM: Uint8Array, reason: string }} r */
export function rewindText(r) {
  if (r.reason.includes("\n") || r.reason.length === 0) throw new NoteError("reason must be one non-empty line");
  return [REWIND_TAG, r.origin, r.forkedFrom, r.at, r.n, toBase64(r.rootN), r.m, toBase64(r.rootM), r.reason].join("\n") + "\n";
}


const ORIGIN = /^([^\s/]+)\/g(0|[1-9][0-9]*)$/;

/**
 * `<log_name>/g<k>` → its parts.
 * @param {string} origin
 */
export function parseOrigin(origin) {
  const m = ORIGIN.exec(origin);
  if (!m) throw new NoteError(`not a log origin: ${origin}`);
  return { logName: m[1], generation: Number(m[2]) };
}
