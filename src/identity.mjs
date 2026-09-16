// SPDX-License-Identifier: GPL-3.0-or-later
// Invariant J: every ENROLL (op=5) leaf carries an UltraHonk proof that an RS256
// id_token, signed by the OpenID provider's published key, named the leaf's iss and
// aud and a private sub, and that the leaf's nullifier is
//   SHA256("emojery-nullifier-v1" || lp(iss) || lp(sub) || lp(aud) || salt)
// for the salt whose SHA256 is the pinned salt_commitment. The proof is checked
// against the pinned verification key with public inputs this file rebuilds from the
// leaf, the archived provider key and the pins — nothing in the proof is trusted.
//
// The prover is @aztec/bb.js, imported lazily: the rest of the audit stays on
// @noble/ed25519 alone, and --no-proofs skips this file entirely.

import { base64ToBytes, bytesToHex, hexToBytes, OP_ENROLL, proofBase64, sha256, utf8 } from "./transparency.mjs";

// The circuit's RSA parameters as noir-jwt (v0.5.1) lays them out: an RSA-2048 value is
// 18 little-endian limbs of 120 bits, and the Barrett reduction parameter is
// floor(2^(2*2048+4) / n). Every limb is one public-input field.
export const RSA_BITS = 2048;
export const LIMB_BITS = 120;
export const LIMB_COUNT = 18;
// BoundedVec capacities of the circuit's public iss/aud (prover/circuit/src/main.nr).
export const ISS_MAX = 96;
export const AUD_MAX = 128;
// modulus[18] || redc[18] || iss[96] || iss_len || aud[128] || aud_len || nullifier[32] || salt_commitment[32]
export const PUBLIC_INPUT_COUNT = LIMB_COUNT * 2 + ISS_MAX + 1 + AUD_MAX + 1 + 32 + 32;

export const VK_PATH = "keys/enroll-v1.vk";
export const VK_META_PATH = "keys/enroll-v1.json";

// The OpenID issuers the log admits. Microsoft's iss carries the tenant id, so it is a
// pattern; the rest are exact. --issuers replaces the list (provider=iss, comma-separated;
// an iss starting with ^ is a regular expression).
export const DEFAULT_ISSUERS = [
  { provider: "google", iss: "https://accounts.google.com" },
  { provider: "apple", iss: "https://appleid.apple.com" },
  { provider: "microsoft", iss: "^https://login\\.microsoftonline\\.com/[0-9a-f-]{36}/v2\\.0$" },
  { provider: "facebook", iss: "https://www.facebook.com" },
  { provider: "linkedin", iss: "https://www.linkedin.com/oauth" },
  { provider: "discord", iss: "https://discord.com" },
  { provider: "twitch", iss: "https://id.twitch.tv/oauth2" },
  { provider: "slack", iss: "https://slack.com" },
];

export function parseIssuersFlag(text) {
  return String(text)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const i = pair.indexOf("=");
      if (i < 1) throw new Error(`--issuers: expected provider=iss, got ${pair}`);
      return { provider: pair.slice(0, i), iss: pair.slice(i + 1) };
    });
}

export function parseListFlag(text) {
  return String(text)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function providerForIssuer(issuers, iss) {
  for (const { provider, iss: want } of issuers) {
    if (want.startsWith("^") ? new RegExp(want).test(iss) : want === iss) return provider;
  }
  return null;
}

export function splitLimbs(n, bits = LIMB_BITS, count = LIMB_COUNT) {
  const mask = (1n << BigInt(bits)) - 1n;
  const limbs = [];
  for (let i = 0; i < count; i++) limbs.push((n >> (BigInt(i) * BigInt(bits))) & mask);
  return limbs;
}

export function redcParam(n) {
  return (1n << (2n * BigInt(RSA_BITS) + 4n)) / n;
}

// One public input as bb.js takes it: a 0x-prefixed 32-byte big-endian field.
export function fieldHex(x) {
  return `0x${BigInt(x).toString(16).padStart(64, "0")}`;
}

// The modulus of an RSA JWK (base64url n). Rejects anything but a 2048-bit RSA key:
// the circuit is sized for exactly that, and a shorter key would be padded into
// limbs that verify nothing.
export function jwkModulus(jwk) {
  if (!jwk || jwk.kty !== "RSA" || typeof jwk.n !== "string") throw new Error("JWK is not an RSA key");
  const n = BigInt(`0x${Buffer.from(jwk.n, "base64url").toString("hex")}`);
  const bits = n.toString(2).length;
  if (bits !== RSA_BITS) throw new Error(`JWK modulus is ${bits} bits, the circuit takes ${RSA_BITS}`);
  return n;
}

// A published key file is either the JWK itself or a JWKS document holding it.
export function findJwk(doc, kid) {
  if (doc && Array.isArray(doc.keys)) return doc.keys.find((k) => k?.kid === kid) ?? null;
  if (doc && typeof doc.n === "string") return doc.kid === undefined || doc.kid === kid ? doc : null;
  return null;
}

// A BoundedVec<u8, MAX> as public inputs: MAX byte fields (zero-padded) then the length.
function boundedVecFields(text, max) {
  const bytes = utf8(text);
  if (bytes.length > max) throw new Error(`value of ${bytes.length} bytes exceeds the circuit's ${max}`);
  const out = [];
  for (let i = 0; i < max; i++) out.push(fieldHex(i < bytes.length ? bytes[i] : 0));
  out.push(fieldHex(bytes.length));
  return out;
}

export function enrollPublicInputs({ modulus, iss, aud, nullifierHex, saltCommitmentHex }) {
  const out = [];
  for (const limb of splitLimbs(modulus)) out.push(fieldHex(limb));
  for (const limb of splitLimbs(redcParam(modulus))) out.push(fieldHex(limb));
  out.push(...boundedVecFields(iss, ISS_MAX));
  out.push(...boundedVecFields(aud, AUD_MAX));
  for (const b of hexToBytes(nullifierHex)) out.push(fieldHex(b));
  for (const b of hexToBytes(saltCommitmentHex)) out.push(fieldHex(b));
  if (out.length !== PUBLIC_INPUT_COUNT) throw new Error(`public input count ${out.length} != ${PUBLIC_INPUT_COUNT}`);
  return out;
}

// The provider's live JWKS, resolved through OpenID discovery. Memoized per issuer;
// null when the provider cannot be reached (that is an outage, not tamper evidence).
async function liveJwksFor(iss, getJson, cache) {
  if (cache.has(iss)) return cache.get(iss);
  let jwks = null;
  try {
    const conf = await getJson(`${iss.replace(/\/$/, "")}/.well-known/openid-configuration`);
    if (typeof conf?.jwks_uri === "string") jwks = await getJson(conf.jwks_uri);
  } catch {
    jwks = null;
  }
  cache.set(iss, jwks);
  return jwks;
}

// Verify every ENROLL proof in `entries`. Pure over its inputs apart from the two
// fetchers: getJson(url) and getBytes(url) read the log repo (and, for the live JWKS
// cross-check, the provider). Returns
//   { status: "skip" | "pass" | "fail", reason, checked, failed, notes[] }
// where a skip names the pin or artifact that is missing.
export async function verifyEnrollProofs(entries, { repo, getJson, getBytes, vkSha256, saltCommitment, issuers, audiences, bbVersion, liveJwks = true, onProgress }) {
  const enrolls = entries.filter((e) => e.op === OP_ENROLL);
  const notes = [];
  const result = (status, reason, extra = {}) => ({ status, reason, checked: 0, failed: 0, notes, ...extra });
  if (enrolls.length === 0) return result("skip", "no ENROLL leaves in the log yet");
  if (!repo) return result("skip", "needs --repo (the verification key and the archived provider keys live in the log repo)");
  if (!vkSha256) return result("skip", "no pinned verification-key hash (PINNED_ENROLL_VK_SHA256 / --enroll-vk-hash)");
  if (!saltCommitment) return result("skip", "no pinned salt commitment (PINNED_SALT_COMMITMENT / --salt-commitment)");
  if (!audiences?.length) return result("skip", "no pinned audiences (PINNED_AUDIENCES / --audiences)");

  let vk;
  try {
    vk = await getBytes(`${repo}/${VK_PATH}`);
  } catch (e) {
    return result("fail", `${VK_PATH} could not be read (${e.message})`);
  }
  const vkHash = bytesToHex(await sha256(vk));
  if (vkHash !== vkSha256.toLowerCase()) return result("fail", `${VK_PATH} sha256 ${vkHash} != pinned ${vkSha256}`);
  try {
    const meta = await getJson(`${repo}/${VK_META_PATH}`);
    if (meta?.bb_version && bbVersion && String(meta.bb_version) !== String(bbVersion)) {
      notes.push(`${VK_META_PATH} says bb ${meta.bb_version}, this verifier runs @aztec/bb.js ${bbVersion} — a proof that fails below may be a version drift, not a forgery`);
    }
  } catch {
    notes.push(`${VK_META_PATH} not published; bb version not cross-checked`);
  }

  let bb;
  try {
    bb = await import("@aztec/bb.js");
  } catch (e) {
    return result("fail", `@aztec/bb.js could not be loaded (${e.message}); run pnpm install, or pass --no-proofs`);
  }
  const api = await bb.Barretenberg.new();
  const backend = new bb.UltraHonkVerifierBackend(api);
  const archived = new Map(); // provider/kid -> modulus | null
  const live = new Map();
  let failed = 0;
  let checked = 0;
  const fail = (e, why) => {
    failed++;
    notes.push(`seq=${e.seq}: ${why}`);
  };
  try {
    for (const [i, e] of enrolls.entries()) {
      checked++;
      const provider = providerForIssuer(issuers, e.iss);
      if (!provider) {
        fail(e, `iss ${e.iss} is not an admitted issuer`);
        continue;
      }
      if (!audiences.includes(e.aud)) {
        fail(e, `aud ${e.aud} is not a pinned client id`);
        continue;
      }
      if (String(e.salt_commitment).toLowerCase() !== saltCommitment.toLowerCase()) {
        fail(e, "salt_commitment differs from the pinned one");
        continue;
      }
      const keyPath = `jwks/${provider}/${e.kid}.json`;
      let modulus = archived.get(keyPath);
      if (modulus === undefined) {
        try {
          const jwk = findJwk(await getJson(`${repo}/${keyPath}`), e.kid);
          if (!jwk) throw new Error("no JWK with that kid in the file");
          modulus = jwkModulus(jwk);
          if (liveJwks) {
            const jwks = await liveJwksFor(e.iss, getJson, live);
            if (!jwks) notes.push(`${provider}: live JWKS unreachable; the archived key for kid ${e.kid} was not cross-checked`);
            else {
              const liveJwk = findJwk(jwks, e.kid);
              if (!liveJwk) notes.push(`${provider}: kid ${e.kid} is no longer in the live JWKS (rotated); the archived key stands`);
              else if (jwkModulus(liveJwk) !== modulus) throw new Error(`archived modulus for kid ${e.kid} differs from the provider's live JWKS`);
            }
          }
        } catch (err) {
          modulus = null;
          notes.push(`${keyPath}: ${err.message}`);
        }
        archived.set(keyPath, modulus);
      }
      if (modulus === null) {
        fail(e, `provider key ${keyPath} unusable`);
        continue;
      }
      let ok = false;
      try {
        const publicInputs = enrollPublicInputs({ modulus, iss: e.iss, aud: e.aud, nullifierHex: e.nullifier, saltCommitmentHex: e.salt_commitment });
        ok = await backend.verifyProof({ proof: base64ToBytes(proofBase64(e)), publicInputs, verificationKey: vk });
      } catch (err) {
        fail(e, `proof verification threw: ${err.message}`);
        continue;
      }
      if (!ok) fail(e, `ENROLL proof does not verify (nullifier ${String(e.nullifier).slice(0, 12)}...)`);
      if (onProgress) onProgress(i + 1, enrolls.length);
    }
  } finally {
    await api.destroy();
  }
  return result(failed ? "fail" : "pass", `${checked} ENROLL proof(s), ${failed} bad`, { checked, failed });
}
