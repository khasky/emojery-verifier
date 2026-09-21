// SPDX-License-Identifier: GPL-3.0-or-later
// Byte helpers on WebCrypto and nothing else. transparency.mjs re-exports them for its
// own callers; ots-core.mjs imports them from here so the OTS codec loads with no
// package installed, which is how the operator's upgrade job runs it.

const TE = new TextEncoder();

export function utf8(s) {
  return TE.encode(s);
}
export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
export function hexToBytes(s) {
  if (typeof s !== "string") throw new Error("hexToBytes: expected a hex string");
  const c = s.startsWith("\\x") ? s.slice(2) : s;
  // Fail loud on malformed hex rather than silently substituting 0x00: parseInt("zz",16)
  // is NaN -> 0 in the loop below, and an odd length drops the last nibble, so a bad root
  // or leaf would recompute to a WRONG value that mismatches a real one only by luck. The
  // publisher's encoder rejects the same inputs; this keeps the two byte-for-byte.
  if (c.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(c)) {
    throw new Error(`hexToBytes: invalid hex (${c.length} chars): ${c.slice(0, 24)}${c.length > 24 ? "..." : ""}`);
  }
  const out = new Uint8Array(c.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(c.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function bytesToHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}
export async function sha256(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}
