// SPDX-License-Identifier: Apache-2.0
// ENROLL checks that need more than the leaf (docs/PROTOCOL.md §4.3, §10, §11): the
// zero-knowledge proof against the pinned verification key, with public inputs rebuilt
// here from the leaf, the provider key and the pinned salt commitment - nothing inside
// the proof is trusted - and the provider key itself.

import { readFile } from "node:fs/promises";
import { equalBytes, fromBase64Url, sha256, toBase64Url, toHex, utf8 } from "@emojery/shared/core";

const KEYS = new URL("../keys/", import.meta.url);
// The structured reference string a proof check needs: the first G1 point (uncompressed,
// 64 bytes) and the G2 point (128 bytes) of Aztec's BN254 ceremony, as its CDN serves them.
export const CRS_G1_SHA256 = "d6ba9329f8932c12192b37849f772104d20048f76434a3290512d9d814e4116f";
export const CRS_G2_SHA256 = "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f";

export const RSA_BITS = 2048;
const LIMB_BITS = 120n;
const LIMB_COUNT = 18;
const ISS_MAX = 96;
const AUD_MAX = 128;
export const PUBLIC_INPUT_COUNT = LIMB_COUNT * 2 + ISS_MAX + 1 + AUD_MAX + 1 + 32 + 32 + 32;

/** @param {Uint8Array} b */
function bigFromBytes(b) {
  return b.length === 0 ? 0n : BigInt(`0x${toHex(b)}`);
}

/** @param {bigint} x */
function fieldHex(x) {
  return `0x${x.toString(16).padStart(64, "0")}`;
}

/** @param {bigint} n */
function limbs(n) {
  const mask = (1n << LIMB_BITS) - 1n;
  return Array.from({ length: LIMB_COUNT }, (_, i) => (n >> (BigInt(i) * LIMB_BITS)) & mask);
}

/** @param {string} s @param {number} max */
function boundedVec(s, max) {
  const b = utf8(s);
  if (b.length > max) throw new Error(`${b.length} bytes exceed the circuit's ${max}`);
  return [...Array.from({ length: max }, (_, i) => fieldHex(BigInt(i < b.length ? b[i] : 0))), fieldHex(BigInt(b.length))];
}

/**
 * The 358 public inputs of an ENROLL proof.
 * @param {{ modulus: Uint8Array, iss: string, aud: string, nullifier: Uint8Array, saltCommitment: Uint8Array, accountPubkey: Uint8Array }} p
 */
export function enrollPublicInputs(p) {
  const n = bigFromBytes(p.modulus);
  if (n.toString(2).length !== RSA_BITS) throw new Error(`modulus is not ${RSA_BITS} bits`);
  const redc = (1n << (2n * BigInt(RSA_BITS) + 6n)) / n;
  const out = [...limbs(n).map(fieldHex), ...limbs(redc).map(fieldHex), ...boundedVec(p.iss, ISS_MAX), ...boundedVec(p.aud, AUD_MAX)];
  for (const b of [p.nullifier, p.saltCommitment, p.accountPubkey]) {
    if (b.length !== 32) throw new Error("public 32-byte value is not 32 bytes");
    for (const x of b) out.push(fieldHex(BigInt(x)));
  }
  if (out.length !== PUBLIC_INPUT_COUNT) throw new Error(`public input count ${out.length}`);
  return out;
}

/**
 * The canonical JSON of an RSA provider key (§10) and the modulus bytes it carries.
 * Refuses anything but a 2048-bit RSA key with e = 65537.
 * @param {{ kty?: unknown, n?: unknown, e?: unknown }} jwk
 */
export function canonicalJwk(jwk) {
  if (jwk?.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") throw new Error("not an RSA JWK");
  const raw = fromBase64Url(jwk.n);
  let start = 0;
  while (start < raw.length - 1 && raw[start] === 0) start++;
  const modulus = raw.subarray(start);
  if (bigFromBytes(modulus).toString(2).length !== RSA_BITS) throw new Error(`modulus is not ${RSA_BITS} bits`);
  if (jwk.e !== "AQAB") throw new Error("exponent is not 65537");
  return { modulus, json: `{"e":"AQAB","kty":"RSA","n":"${toBase64Url(modulus)}"}` };
}

/** @param {Uint8Array} modulus */
export function modulusHash(modulus) {
  return sha256(modulus);
}

/**
 * Checks a provider key file against the modulus hash an ENROLL names: the file must be
 * the canonical serialization of a key whose modulus hashes to `want`.
 * @param {string} text @param {Uint8Array} want
 */
export async function checkJwkFile(text, want) {
  const { modulus, json } = canonicalJwk(JSON.parse(text));
  if (text !== json) throw new Error("provider key file is not in canonical form");
  if (!equalBytes(await modulusHash(modulus), want)) throw new Error("provider key file holds another modulus");
  return modulus;
}

/**
 * The verification key of an ENROLL version, from this package, checked against its pin.
 * @param {number} version @param {string} vkSha256
 */
export async function verificationKey(version, vkSha256) {
  const vk = new Uint8Array(await readFile(new URL(`enroll-v${version}.vk`, KEYS)));
  if (toHex(await sha256(vk)) !== vkSha256) throw new Error(`the packaged verification key of ENROLL v${version} does not match its pin`);
  return vk;
}

/**
 * The two points of the structured reference string an UltraHonk check needs, from this
 * package and checked against their pins: no download, nothing written to disk.
 */
export async function crsPoints() {
  const g1 = new Uint8Array(await readFile(new URL("bn254_g1.dat", KEYS)));
  const g2 = new Uint8Array(await readFile(new URL("bn254_g2.dat", KEYS)));
  if (toHex(await sha256(g1)) !== CRS_G1_SHA256 || toHex(await sha256(g2)) !== CRS_G2_SHA256) throw new Error("the packaged CRS points do not match their pins");
  return { g1, g2 };
}

/**
 * A proof checker over @aztec/bb.js with verifier target evm, on the WASM backend on
 * every platform and with the reference string set from the packaged points. Loaded
 * lazily, so a run that checks no proofs never loads the WASM.
 * @param {Uint8Array} vk
 */
export async function proofChecker(vk) {
  const { g1, g2 } = await crsPoints();
  const bb = await import("@aztec/bb.js");
  const api = await bb.Barretenberg.new({ backend: bb.BackendType.Wasm, threads: 1, skipSrsInit: true });
  await api.srsInitSrs({ pointsBuf: g1, numPoints: 1, g2Point: g2 });
  const backend = new bb.UltraHonkVerifierBackend(api);
  return {
    /** @param {Uint8Array} proof @param {string[]} publicInputs */
    verify: (proof, publicInputs) => backend.verifyProof({ proof, publicInputs, verificationKey: vk }, { verifierTarget: "evm" }),
    close: () => api.destroy(),
  };
}
