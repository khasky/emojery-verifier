// SPDX-License-Identifier: GPL-3.0-or-later
// Self-test for the identity track: the op 5/6/7 leaf bytes and the signed-vote tail
// (pinned cross-repo vectors), invariants G/H/I, the Ed25519 and blind RSA-PSS
// signature checks on freshly generated keys, the noir-jwt public-input layout, and
// the ENROLL proof driver's skip/fail paths against stubbed fetchers.
//   node src/identity.selftest.mjs
// No network; @aztec/bb.js is never loaded here (its own verify path needs a real
// proof, which only the prover container can mint).

import * as ed from "@noble/ed25519";
import {
  AUD_MAX,
  DEFAULT_ISSUERS,
  enrollPublicInputs,
  fieldHex,
  findJwk,
  ISS_MAX,
  jwkModulus,
  parseIssuersFlag,
  providerForIssuer,
  PUBLIC_INPUT_COUNT,
  redcParam,
  splitLimbs,
  verifyEnrollProofs,
} from "./identity.mjs";
import {
  bytesToHex,
  checkIdentityInvariants,
  checkStructuralInvariants,
  concatBytes,
  EPOCH_KEYS_PER_ACCOUNT,
  epochKeyMessage,
  hexToBytes,
  leafHash,
  leafHashFromEntry,
  lp,
  serializeLeaf,
  sha256,
  utf8,
  verifyIdentitySignatures,
  voteSignatureMessage,
} from "./transparency.mjs";

let failed = false;
function check(ok, msg) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`);
  if (!ok) failed = true;
}

// --- KAT: the cross-repo identity vectors ------------------------------------------
// Inputs shared with the backend's log-leaf tests; every hash below is asserted there
// too, so the two serializers cannot drift apart unnoticed.
const SALT = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const ISS = "https://accounts.google.com";
const SUB = "1234567890";
const AUD = "emojery-client";
const PUBKEY = new Uint8Array(32).fill(0x11);
const SIG = new Uint8Array(64).fill(0x22);
const KEY_SIG = new Uint8Array(256).fill(0x33);
const PROOF = hexToBytes("aabbccdd");
const NONCE = "0123456789abcdef";
const EPOCH = 1234n;
const TS = 1700000040000;

const nullifier = bytesToHex(await sha256(concatBytes(utf8("emojery-nullifier-v1"), lp(ISS), lp(SUB), lp(AUD), SALT)));
check(nullifier === "44815fb9364d5fcfc695b7ca305f3df8d1cd4b15a0a12c76b88e19b6e4f7e1d2", "KAT nullifier");
const saltCommitment = await sha256(SALT);
check(bytesToHex(saltCommitment) === "ae216c2ef5247a3782c135efa279a3e4cdc61094270f5d2be58c6204b7a612c9", "KAT salt_commitment");
const userRef = bytesToHex(await sha256(PUBKEY));
check(userRef === "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc", "KAT user_ref = SHA256(pubkey)");

const votes = { seq: 5n, ts: TS, op: 1, site: "github", targetId: "gh:o/r", reaction: "👍", prevReaction: null, userRef, clientPubkey: PUBKEY, clientSig: SIG, clientNonce: NONCE };
check(bytesToHex(await leafHash(votes)) === "65bd0426b4e0344ef456e1817b4eb0841fe1eaf25f2176a67033631f7a0edbe4", "KAT signed vote leaf_hash");
const nulls = { site: null, targetId: null, reaction: null, prevReaction: null, userRef: null };
const enroll = { seq: 1n, ts: TS, op: 5, ...nulls, nullifier, iss: ISS, aud: AUD, kid: "kid-1", proof: PROOF, saltCommitment };
check(bytesToHex(await leafHash(enroll)) === "9b3e82734edfc3e806fbeb1f300b92bbe564b59a7fbc8574b567d4a4245ede86", "KAT ENROLL leaf_hash");
const issue = { seq: 2n, ts: TS, op: 6, ...nulls, nullifier, epoch: EPOCH };
check(bytesToHex(await leafHash(issue)) === "fc70129a7d4f9ee4ea1f943a8a71beaf8ecbac1174dc3c692f01c7af7a81638a", "KAT ISSUE leaf_hash");
const key = { seq: 4n, ts: TS, op: 7, ...nulls, epoch: EPOCH, clientPubkey: PUBKEY, keySig: KEY_SIG };
check(bytesToHex(await leafHash(key)) === "3567a9a146e73434e5bb898c8b3dbb9236292c8692a78bcc88de196aff355a7d", "KAT KEY leaf_hash");
check(
  bytesToHex(voteSignatureMessage("github", "gh:o/r", "👍", NONCE)) === "656d6f6a6572792d766f74652d7631000000066769746875620000000667683a6f2f7200000004f09f918d0000001030313233343536373839616263646566",
  "KAT voteSignatureMessage bytes",
);
check(bytesToHex(epochKeyMessage(EPOCH, PUBKEY)) === `656d6f6a6572792d65706f63682d6b65792d763100000000000004d2${"11".repeat(32)}`, "KAT epochKeyMessage bytes");

// A vote without a client key keeps the legacy 8-field bytes, byte-for-byte.
const legacy = { seq: 5n, ts: TS, op: 1, site: "github", targetId: "gh:o/r", reaction: "👍", prevReaction: null, userRef };
check(serializeLeaf(legacy).length + 4 + 32 + 4 + 64 + 4 + NONCE.length === serializeLeaf(votes).length, "signed-vote tail is lpb(pubkey)||lpb(sig)||lp(nonce) after the legacy bytes");
check(bytesToHex(serializeLeaf({ ...legacy, clientPubkey: null })) === bytesToHex(serializeLeaf(legacy)), "an explicit null pubkey is the legacy leaf");

// --- leafHashFromEntry: rows in the /log/entries wire shape ------------------------
const rowVote = { seq: "5", ts: TS, op: 1, site: "github", target_id: "gh:o/r", reaction: "👍", prev_reaction: null, user_ref: userRef, client_pubkey: bytesToHex(PUBKEY), client_sig: bytesToHex(SIG), client_nonce: NONCE };
check(bytesToHex(await leafHashFromEntry(rowVote)) === bytesToHex(await leafHash(votes)), "row -> signed vote leaf_hash");
const rowOld = { seq: "5", ts: TS, op: 1, site: "github", target_id: "gh:o/r", reaction: "👍", prev_reaction: null, user_ref: userRef };
check(bytesToHex(await leafHashFromEntry(rowOld)) === bytesToHex(await leafHash(legacy)), "row without the identity fields (old shard line) -> legacy leaf_hash");
const rowEnroll = { seq: "1", ts: TS, op: 5, site: null, target_id: null, reaction: null, prev_reaction: null, user_ref: "0".repeat(64), nullifier, iss: ISS, aud: AUD, kid: "kid-1", proof_b64: Buffer.from(PROOF).toString("base64"), salt_commitment: bytesToHex(saltCommitment) };
check(bytesToHex(await leafHashFromEntry(rowEnroll)) === bytesToHex(await leafHash(enroll)), "row -> ENROLL leaf_hash (zero-sentinel user_ref is not hashed)");
const rowIssue = { seq: "2", ts: TS, op: 6, site: null, target_id: null, reaction: null, prev_reaction: null, user_ref: "0".repeat(64), nullifier, epoch: "1234" };
check(bytesToHex(await leafHashFromEntry(rowIssue)) === bytesToHex(await leafHash(issue)), "row -> ISSUE leaf_hash (epoch as a string)");
const rowKey = { seq: "4", ts: TS, op: 7, site: null, target_id: null, reaction: null, prev_reaction: null, user_ref: "0".repeat(64), epoch: "1234", client_pubkey: bytesToHex(PUBKEY), key_sig: bytesToHex(KEY_SIG) };
check(bytesToHex(await leafHashFromEntry(rowKey)) === bytesToHex(await leafHash(key)), "row -> KEY leaf_hash");

// --- invariant A: identity leaf shapes ---------------------------------------------
check(checkStructuralInvariants([rowEnroll, rowIssue, rowKey, rowVote]).length === 0, "invariant A: well-formed identity leaves and a signed vote pass");
check(checkStructuralInvariants([{ ...rowEnroll, site: "github" }]).length === 1, "invariant A: an identity leaf carrying a vote field is flagged");
check(checkStructuralInvariants([{ ...rowEnroll, proof_b64: null }]).length === 1, "invariant A: ENROLL without a proof is flagged");
const { proof_b64: proofOnly, ...rowEnrollSpec } = { ...rowEnroll, proof: rowEnroll.proof_b64 };
check(bytesToHex(await leafHashFromEntry(rowEnrollSpec)) === bytesToHex(await leafHash(enroll)) && proofOnly !== undefined, "row with the spec key `proof` (not proof_b64) -> ENROLL leaf_hash");
check(checkStructuralInvariants([{ ...rowKey, key_sig: "33".repeat(255) }]).length === 1, "invariant A: KEY with a short key_sig is flagged");
check(checkStructuralInvariants([{ ...rowIssue, epoch: null }]).length === 1, "invariant A: ISSUE without an epoch is flagged");
check(checkStructuralInvariants([{ ...rowVote, client_sig: null }]).length === 1, "invariant A: a vote with a pubkey but no signature is flagged");
check(checkStructuralInvariants([{ ...rowVote, op: 8 }]).length === 1, "invariant A: op=8 stays unexpected");

// --- invariants G/H/I (structural) --------------------------------------------------
const PK2 = "44".repeat(32);
const enrollRow = (seq, nul) => ({ ...rowEnroll, seq: String(seq), nullifier: nul });
const issueRow = (seq, nul, epoch = "1234") => ({ ...rowIssue, seq: String(seq), nullifier: nul, epoch });
const keyRow = (seq, pk, epoch = "1234") => ({ ...rowKey, seq: String(seq), client_pubkey: pk, epoch });
const voteRow = (seq, pk, ref, nonce) => ({ ...rowVote, seq: String(seq), client_pubkey: pk, user_ref: ref, client_nonce: nonce });
const good = [enrollRow(1, nullifier), issueRow(2, nullifier), keyRow(3, bytesToHex(PUBKEY)), voteRow(4, bytesToHex(PUBKEY), userRef, "n1"), voteRow(5, bytesToHex(PUBKEY), userRef, "n2"), rowOld];
const goodResult = await checkIdentityInvariants(good);
check(goodResult.violations.length === 0, `identity invariants: a consistent track passes (${goodResult.violations.join("; ")})`);
check(goodResult.signedVotes === 2 && goodResult.unsignedVotes === 1 && goodResult.enrolls === 1 && goodResult.issues === 1 && goodResult.keys === 1, "identity invariants: counts");
const flagged = async (rows, what) => {
  const r = await checkIdentityInvariants(rows);
  check(r.violations.length === 1 && r.violations[0].includes(what), `identity invariants: ${what} flagged (${r.violations[0] ?? "nothing"})`);
};
await flagged([enrollRow(1, nullifier), enrollRow(2, nullifier)], "second ENROLL");
await flagged([issueRow(1, nullifier)], "no prior ENROLL");
await flagged([enrollRow(1, nullifier), issueRow(2, nullifier), issueRow(3, nullifier), issueRow(4, nullifier), issueRow(5, nullifier)], `limit ${EPOCH_KEYS_PER_ACCOUNT}`);
await flagged([enrollRow(1, nullifier), issueRow(2, nullifier), keyRow(3, bytesToHex(PUBKEY)), keyRow(4, PK2)], "exceeds the 1 ISSUE");
await flagged([enrollRow(1, nullifier), issueRow(2, nullifier), issueRow(3, nullifier), keyRow(4, bytesToHex(PUBKEY)), keyRow(5, bytesToHex(PUBKEY))], "already registered");
await flagged([voteRow(1, bytesToHex(PUBKEY), userRef, "n1")], "no prior KEY");
await flagged([enrollRow(1, nullifier), issueRow(2, nullifier), keyRow(3, bytesToHex(PUBKEY)), voteRow(4, bytesToHex(PUBKEY), "c".repeat(64), "n1")], "not SHA256");
await flagged([enrollRow(1, nullifier), issueRow(2, nullifier), keyRow(3, bytesToHex(PUBKEY)), voteRow(4, bytesToHex(PUBKEY), userRef, "n1"), voteRow(5, bytesToHex(PUBKEY), userRef, "n1")], "nonce reused");
const perEpoch = await checkIdentityInvariants([enrollRow(1, nullifier), issueRow(2, nullifier, "1"), keyRow(3, bytesToHex(PUBKEY), "2")]);
check(perEpoch.violations.length === 1, "invariant H counts KEY against ISSUE per epoch, not globally");

// --- G/H cryptographic: real keys ----------------------------------------------------
ed.etc.sha512Async = (...m) => crypto.subtle.digest("SHA-512", ed.etc.concatBytes(...m)).then((b) => new Uint8Array(b));
const edPriv = ed.utils.randomPrivateKey();
const edPub = await ed.getPublicKeyAsync(edPriv);
const edRef = bytesToHex(await sha256(edPub));
const signedVote = async (seq, reaction, prev, nonce) => {
  const sig = await ed.signAsync(voteSignatureMessage("github", "gh:o/r", reaction, nonce), edPriv);
  return { ...rowVote, seq: String(seq), op: reaction === null ? 3 : prev === null ? 1 : 2, reaction, prev_reaction: prev, user_ref: edRef, client_pubkey: bytesToHex(edPub), client_sig: bytesToHex(sig), client_nonce: nonce };
};
const rsa = await crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-384" }, true, ["sign", "verify"]);
const spkiB64 = Buffer.from(await crypto.subtle.exportKey("spki", rsa.publicKey)).toString("base64");
const keySig = new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 48 }, rsa.privateKey, epochKeyMessage(EPOCH, edPub)));
const realKey = { ...rowKey, client_pubkey: bytesToHex(edPub), key_sig: bytesToHex(keySig) };
const track = [rowEnroll, rowIssue, realKey, await signedVote(5, "👍", null, "n1"), await signedVote(6, null, "👍", "n2")];
const sigs = await verifyIdentitySignatures(track, { blindPubkeySpkiB64: spkiB64 });
check(sigs.voteViolations.length === 0 && sigs.votesChecked === 2, `G: add and remove signatures verify (${sigs.voteViolations.join("; ")})`);
check(sigs.keyViolations.length === 0 && sigs.keysChecked === 1, `H: blind RSA-PSS key_sig verifies (${sigs.keyViolations.join("; ")})`);
const tampered = { ...track[3], reaction: "👎" };
const badVote = await verifyIdentitySignatures([tampered], { blindPubkeySpkiB64: spkiB64 });
check(badVote.voteViolations.length === 1, "G: a vote whose reaction was edited no longer verifies");
const badKey = await verifyIdentitySignatures([{ ...realKey, epoch: "1235" }], { blindPubkeySpkiB64: spkiB64 });
check(badKey.keyViolations.length === 1, "H: a KEY leaf whose epoch was edited no longer verifies");
const wrongSalt = new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, rsa.privateKey, epochKeyMessage(EPOCH, edPub)));
const badSalt = await verifyIdentitySignatures([{ ...realKey, key_sig: bytesToHex(wrongSalt) }], { blindPubkeySpkiB64: spkiB64 });
check(badSalt.keyViolations.length === 1, "H: a PSS signature with the wrong salt length is rejected (salt is pinned at 48)");
const noPin = await verifyIdentitySignatures(track, { blindPubkeySpkiB64: "" });
check(noPin.keysChecked === 0 && noPin.keysSkipped === 1 && noPin.votesChecked === 2, "H: without a pinned blind key the KEY leaves are counted as skipped, votes still checked");

// --- J: the noir-jwt public-input layout -------------------------------------------
const modulus = (1n << 2047n) | 0x1234567890abcdefn | (0xabcn << 1000n);
const limbs = splitLimbs(modulus);
check(limbs.length === 18 && limbs.every((l) => l < 1n << 120n), "limbs: 18 limbs of at most 120 bits");
check(limbs.reduce((acc, l, i) => acc | (l << (120n * BigInt(i))), 0n) === modulus, "limbs: little-endian 120-bit split reassembles the modulus");
check(redcParam(modulus) === (1n << 4100n) / modulus, "redc = floor(2^(2*2048+4) / n), as noir-jwt's generateInputs computes it");
check(fieldHex(255n) === `0x${"0".repeat(62)}ff`, "fieldHex: 32-byte big-endian field");
const inputs = enrollPublicInputs({ modulus, iss: ISS, aud: AUD, nullifierHex: nullifier, saltCommitmentHex: bytesToHex(saltCommitment) });
check(inputs.length === PUBLIC_INPUT_COUNT && PUBLIC_INPUT_COUNT === 326, "public inputs: 18+18+97+129+32+32 = 326 fields");
check(inputs[0] === fieldHex(limbs[0]) && inputs[18] === fieldHex(redcParam(modulus) & ((1n << 120n) - 1n)), "public inputs: modulus limbs then redc limbs");
const issStart = 36;
check(inputs[issStart] === fieldHex(0x68) && inputs[issStart + ISS.length - 1] === fieldHex(0x6d) && inputs[issStart + ISS.length] === fieldHex(0) && inputs[issStart + ISS_MAX] === fieldHex(ISS.length), "public inputs: iss bytes zero-padded to 96, then its length");
const audStart = issStart + ISS_MAX + 1;
check(inputs[audStart] === fieldHex(0x65) && inputs[audStart + AUD_MAX] === fieldHex(AUD.length), "public inputs: aud bytes padded to 128, then its length");
const nulStart = audStart + AUD_MAX + 1;
check(inputs[nulStart] === fieldHex(0x44) && inputs[nulStart + 31] === fieldHex(0xd2) && inputs[nulStart + 32] === fieldHex(0xae) && inputs[nulStart + 63] === fieldHex(0xc9), "public inputs: nullifier then salt_commitment, one byte per field");
let threw = false;
try {
  enrollPublicInputs({ modulus, iss: "x".repeat(97), aud: AUD, nullifierHex: nullifier, saltCommitmentHex: bytesToHex(saltCommitment) });
} catch {
  threw = true;
}
check(threw, "public inputs: an iss longer than the circuit's 96 bytes is refused");

// --- J: issuer and key resolution ----------------------------------------------------
check(providerForIssuer(DEFAULT_ISSUERS, ISS) === "google", "issuers: google resolves");
check(providerForIssuer(DEFAULT_ISSUERS, "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0") === "microsoft", "issuers: a Microsoft tenant iss matches the pattern");
check(providerForIssuer(DEFAULT_ISSUERS, "https://accounts.google.com.evil.example") === null, "issuers: a look-alike iss does not resolve");
check(parseIssuersFlag("test=https://api-staging.example/test-oidc, google=https://accounts.google.com").length === 2, "--issuers parses provider=iss pairs");
const nB64 = Buffer.from(hexToBytes(modulus.toString(16))).toString("base64url");
check(jwkModulus({ kty: "RSA", n: nB64, e: "AQAB", kid: "k" }) === modulus, "jwkModulus: base64url n round-trips");
check(findJwk({ keys: [{ kid: "a", n: "x" }, { kid: "k", kty: "RSA", n: nB64 }] }, "k")?.n === nB64 && findJwk({ kty: "RSA", n: nB64, kid: "k" }, "k") !== null && findJwk({ kty: "RSA", n: nB64, kid: "k" }, "other") === null, "findJwk: a JWKS document or a lone JWK, matched by kid");
threw = false;
try {
  jwkModulus({ kty: "RSA", n: Buffer.from(hexToBytes((1n << 1023n).toString(16))).toString("base64url") });
} catch {
  threw = true;
}
check(threw, "jwkModulus: a 1024-bit key is refused (the circuit takes 2048)");

// --- J: the driver's skip and fail paths, no bb.js ---------------------------------
const REPO = "https://raw.example.test/main";
const base = { repo: REPO, getJson: async () => ({}), getBytes: async () => new Uint8Array(0), vkSha256: "ab".repeat(32), saltCommitment: bytesToHex(saltCommitment), issuers: DEFAULT_ISSUERS, audiences: [AUD], liveJwks: false };
check((await verifyEnrollProofs([rowVote], base)).status === "skip", "J: no ENROLL leaves -> skip");
check((await verifyEnrollProofs([rowEnroll], { ...base, vkSha256: "" })).reason.includes("PINNED_ENROLL_VK_SHA256"), "J: missing VK pin -> skip naming the pin");
check((await verifyEnrollProofs([rowEnroll], { ...base, saltCommitment: "" })).status === "skip", "J: missing salt-commitment pin -> skip");
check((await verifyEnrollProofs([rowEnroll], { ...base, audiences: [] })).status === "skip", "J: missing audiences -> skip");
check((await verifyEnrollProofs([rowEnroll], { ...base, repo: undefined })).status === "skip", "J: no --repo -> skip");
const vkBytes = utf8("not a real vk");
const vkHash = bytesToHex(await sha256(vkBytes));
const withVk = { ...base, getBytes: async (url) => (url.endsWith("/keys/enroll-v1.vk") ? vkBytes : new Uint8Array(0)) };
const badHash = await verifyEnrollProofs([rowEnroll], withVk);
check(badHash.status === "fail" && badHash.reason.includes("sha256"), "J: a VK whose sha256 differs from the pin fails before any proof is read");
const missingVk = await verifyEnrollProofs([rowEnroll], {
  ...base,
  getBytes: async () => {
    throw new Error("GET -> 404");
  },
});
check(missingVk.status === "fail", "J: an unreadable VK is a fail, not a skip (the pin says it must exist)");
// With the VK accepted, the driver loads bb.js. Stub the import path out by pointing at
// an unadmitted issuer first: those leaves fail before the prover is touched, and the
// run must still report per-leaf reasons.
const unadmitted = { ...rowEnroll, iss: "https://evil.example" };
const drv = await verifyEnrollProofs([unadmitted, { ...rowEnroll, aud: "other-client" }, { ...rowEnroll, salt_commitment: "ff".repeat(32) }], { ...withVk, vkSha256: vkHash });
check(drv.status === "fail" && drv.failed === 3 && drv.notes.some((n) => n.includes("not an admitted issuer")) && drv.notes.some((n) => n.includes("pinned client id")) && drv.notes.some((n) => n.includes("salt_commitment")), "J: issuer, audience and salt-commitment mismatches are each named per leaf");
const jwkFetches = [];
const liveMismatch = await verifyEnrollProofs([rowEnroll], {
  ...withVk,
  vkSha256: vkHash,
  liveJwks: true,
  getJson: async (url) => {
    jwkFetches.push(url);
    if (url.endsWith("/jwks/google/kid-1.json")) return { kty: "RSA", kid: "kid-1", n: nB64, e: "AQAB" };
    if (url.endsWith("/.well-known/openid-configuration")) return { jwks_uri: "https://live.example/jwks" };
    if (url === "https://live.example/jwks") return { keys: [{ kty: "RSA", kid: "kid-1", n: Buffer.from(hexToBytes(((1n << 2047n) | 7n).toString(16))).toString("base64url"), e: "AQAB" }] };
    return {};
  },
});
check(liveMismatch.status === "fail" && liveMismatch.notes.some((n) => n.includes("differs from the provider's live JWKS")), "J: an archived provider key that disagrees with the live JWKS fails");
check(jwkFetches.some((u) => u === `${REPO}/jwks/google/kid-1.json`) && jwkFetches.some((u) => u === `${ISS}/.well-known/openid-configuration`), "J: reads jwks/<provider>/<kid>.json from the repo and discovers the live JWKS from iss");

console.log(failed ? "\nRESULT: FAIL" : "\nRESULT: PASS");
process.exit(failed ? 1 : 0);
