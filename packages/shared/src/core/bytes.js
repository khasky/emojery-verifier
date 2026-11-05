// SPDX-License-Identifier: Apache-2.0
// The encodings of docs/PROTOCOL.md §1. Every integer is big-endian; every length
// prefix counts bytes. There is deliberately no `lp`: a field is written with exactly
// the function the protocol's field table names, so an lp16 field cannot silently
// become an lp32 one.

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export class EncodingError extends Error {
  name = "EncodingError";
}

/** @param {string} s */
export function utf8(s) {
  if (!s.isWellFormed()) throw new EncodingError("string is not well-formed UTF-16");
  return encoder.encode(s);
}

/** @param {Uint8Array} b */
export function decodeUtf8(b) {
  try {
    return strictDecoder.decode(b);
  } catch {
    throw new EncodingError("bytes are not well-formed UTF-8");
  }
}

/** @param {...Uint8Array} parts */
export function concat(...parts) {
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

/** @param {number} n */
export function u8(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new EncodingError(`u8 out of range: ${n}`);
  return Uint8Array.of(n);
}

/** @param {number} n */
export function u16(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new EncodingError(`u16 out of range: ${n}`);
  return Uint8Array.of(n >>> 8, n & 0xff);
}

/** @param {number} n */
export function u32(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new EncodingError(`u32 out of range: ${n}`);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

/** @param {bigint | number} n */
export function u64(n) {
  const v = BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new EncodingError(`u64 out of range: ${n}`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v);
  return out;
}

/** @param {Uint8Array} b */
export function lpb16(b) {
  if (b.length > 0xffff) throw new EncodingError(`field too long for lpb16: ${b.length} bytes`);
  return concat(u16(b.length), b);
}

/** @param {string} s */
export function lp16(s) {
  return lpb16(utf8(s));
}

/** @param {string} s */
export function lp32(s) {
  const b = utf8(s);
  return concat(u32(b.length), b);
}

/**
 * Reads fields off a byte string in order. Every read checks that the bytes are there;
 * `end()` checks that nothing is left over, so a decoder built on it rejects both a
 * truncated record and one with trailing bytes.
 */
export class Reader {
  /** @param {Uint8Array} bytes */
  constructor(bytes) {
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }

  /** @param {number} n */
  take(n) {
    if (this.pos + n > this.bytes.length) throw new EncodingError(`truncated: need ${n} bytes at offset ${this.pos}`);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  u8() {
    return this.take(1)[0];
  }

  u16() {
    this.take(2);
    return this.view.getUint16(this.pos - 2);
  }

  u32() {
    this.take(4);
    return this.view.getUint32(this.pos - 4);
  }

  u64() {
    this.take(8);
    return this.view.getBigUint64(this.pos - 8);
  }

  lpb16() {
    return this.take(this.u16());
  }

  lp16() {
    return decodeUtf8(this.lpb16());
  }

  end() {
    if (this.pos !== this.bytes.length) throw new EncodingError(`${this.bytes.length - this.pos} trailing bytes`);
  }
}

/** @param {Uint8Array} b */
export function toHex(b) {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/** @param {string} hex */
export function fromHex(hex) {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) throw new EncodingError("not lowercase hex of even length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** RFC 4648 §4, with padding. @param {Uint8Array} b */
export function toBase64(b) {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}

/**
 * Strict RFC 4648 §4 decode: padding required, no whitespace, canonical trailing bits.
 * @param {string} s
 */
export function fromBase64(s) {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) throw new EncodingError("not canonical base64");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (toBase64(out) !== s) throw new EncodingError("not canonical base64");
  return out;
}

/** RFC 4648 §5, no padding. @param {Uint8Array} b */
export function toBase64Url(b) {
  return toBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Strict RFC 4648 §5 decode without padding; anything outside the alphabet, padding or
 * non-canonical trailing bits is refused.
 * @param {string} s
 */
export function fromBase64Url(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new EncodingError("not canonical base64url");
  const std = s.replace(/-/g, "+").replace(/_/g, "/");
  const out = fromBase64(std + "=".repeat((4 - (std.length % 4)) % 4));
  if (toBase64Url(out) !== s) throw new EncodingError("not canonical base64url");
  return out;
}

/**
 * Bytewise comparison, the only order the protocol uses for strings (top-10 ties).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
export function compareBytes(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
export function equalBytes(a, b) {
  return a.length === b.length && compareBytes(a, b) === 0;
}
