// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fromBase64, toHex } from "../src/core/bytes.js";
import { checkpointText, noteKeyId, NoteError, parseCheckpoint, parseNote, parseOrigin, parseRewind, rewindText, signNote, verifyNote } from "../src/core/note.js";

const sumdb = JSON.parse(readFileSync(new URL("../vectors/third-party/sumdb-note/vectors.json", import.meta.url), "utf8"));

async function keyPair() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return { privateKey: kp.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) };
}

test("the sumdb note vector: key id and signature", async () => {
  const [name, hash, key] = sumdb.verifierKey.split("+");
  const raw = fromBase64(key);
  assert.equal(raw[0], 1);
  const pub = raw.subarray(1);
  assert.equal(toHex(await noteKeyId(name, pub)), hash);
  const text = await verifyNote(sumdb.note, name, pub);
  assert.equal(text, "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n");
  const tampered = sumdb.note.replace("cryptography", "Cryptography");
  await assert.rejects(verifyNote(tampered, name, pub), NoteError);
  await assert.rejects(verifyNote(sumdb.note, "PeterNeumann2", pub), NoteError);
});

test("unknown signature lines are ignored, a duplicate own line is not", async () => {
  const { privateKey, publicKey } = await keyPair();
  const other = await keyPair();
  const signed = await signNote("log.emojery.app/g0\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", "log.emojery.app", privateKey, publicKey);
  const cosigned = signed + (await signNote("log.emojery.app/g0\n1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", "witness.example", other.privateKey, other.publicKey)).split("\n\n")[1];
  assert.equal(parseNote(cosigned).signatures.length, 2);
  await verifyNote(cosigned, "log.emojery.app", publicKey);
  const ownLine = signed.split("\n\n")[1];
  await assert.rejects(verifyNote(signed + ownLine, "log.emojery.app", publicKey), /more than one/);
});

test("malformed notes", () => {
  for (const bad of ["no block\n", "text\n\n", "text\n\n— name\n", "text\n\n- name AAAAAAA=\n", "a\n\nb\n\n— n AAAAAAA=\n", "t\x01\n\n— n AAAAAAA=\n"]) {
    assert.throws(() => parseNote(bad), NoteError, JSON.stringify(bad));
  }
});

test("checkpoint body", () => {
  const root = new Uint8Array(32).fill(1);
  const text = checkpointText({ origin: "log.emojery.app/g0", size: 1048576, root });
  assert.equal(text, "log.emojery.app/g0\n1048576\nAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n");
  assert.deepEqual(parseCheckpoint(text), { origin: "log.emojery.app/g0", size: 1048576, root, extensions: [] });
  assert.deepEqual(parseCheckpoint(`${text}ext one\n`).extensions, ["ext one"]);
  for (const bad of ["o\n01\nAQ==\n", "o\n1\nAQ==\n", "o\n-1\n" + text.split("\n")[2] + "\n", "o\n1\n"]) assert.throws(() => parseCheckpoint(bad), NoteError, bad);
});

test("rewind record body", () => {
  const r = { origin: "log.emojery.app/g1", forkedFrom: "log.emojery.app/g0", at: 1790000000000, n: 1048576, rootN: new Uint8Array(32).fill(2), m: 1050108, rootM: new Uint8Array(32).fill(3), reason: "database incident" };
  const text = rewindText(r);
  assert.equal(text.split("\n")[0], "emojery-rewind-v1");
  assert.deepEqual(parseRewind(text), r);
  assert.throws(() => parseRewind(rewindText({ ...r, m: 1 })), NoteError);
  assert.throws(() => rewindText({ ...r, reason: "two\nlines" }), NoteError);
  assert.throws(() => parseRewind(text.replace("emojery-rewind-v1", "emojery-rewind-v2")), NoteError);
});

test("origins", () => {
  assert.deepEqual(parseOrigin("log.emojery.app/g0"), { logName: "log.emojery.app", generation: 0 });
  assert.deepEqual(parseOrigin("log-staging.emojery.app/g12"), { logName: "log-staging.emojery.app", generation: 12 });
  for (const bad of ["log.emojery.app", "log.emojery.app/g01", "log.emojery.app/g", "a b/g0", "x/y/g0"]) assert.throws(() => parseOrigin(bad), NoteError, bad);
});
