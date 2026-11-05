// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import { test } from "node:test";
import { compareBytes, concat, EncodingError, fromHex, lp16, lp32, lpb16, Reader, toHex, u8, u16, u32, u64, utf8 } from "../src/core/bytes.js";

test("integers are big-endian and range-checked", () => {
  assert.equal(toHex(u8(0x02)), "02");
  assert.equal(toHex(u16(0x0102)), "0102");
  assert.equal(toHex(u32(1)), "00000001");
  assert.equal(toHex(u32(0xffffffff)), "ffffffff");
  assert.equal(toHex(u64(1)), "0000000000000001");
  assert.equal(toHex(u64(0xffffffffffffffffn)), "ffffffffffffffff");
  for (const bad of [() => u8(256), () => u16(-1), () => u32(2 ** 32), () => u32(1.5), () => u64(-1n), () => u64(2n ** 64n)]) {
    assert.throws(bad, EncodingError);
  }
});

test("lp16 and lp32 differ only in the width of the length", () => {
  assert.equal(toHex(lp16("github")), "0006676974687562");
  assert.equal(toHex(lp32("github")), "00000006676974687562");
  assert.equal(toHex(lp16("")), "0000");
  assert.equal(toHex(lp16("👍")), "0004f09f918d");
  assert.equal(toHex(lpb16(fromHex("00ff"))), "000200ff");
});

test("a lone surrogate is refused, not replaced", () => {
  assert.throws(() => utf8("\uD83D"), EncodingError);
  assert.throws(() => lp16("a\uDC00"), EncodingError);
});

test("an over-long field is refused", () => {
  assert.throws(() => lpb16(new Uint8Array(0x10000)), EncodingError);
  assert.equal(lpb16(new Uint8Array(0xffff)).length, 0x10001);
});

test("the reader rejects truncation, trailing bytes and ill-formed UTF-8", () => {
  const r = new Reader(concat(u8(2), u16(3), lp16("abc"), u32(7), u64(9n)));
  assert.equal(r.u8(), 2);
  assert.equal(r.u16(), 3);
  assert.equal(r.lp16(), "abc");
  assert.equal(r.u32(), 7);
  assert.equal(r.u64(), 9n);
  r.end();

  assert.throws(() => new Reader(fromHex("0005616263")).lp16(), EncodingError);
  assert.throws(() => new Reader(fromHex("00")).u16(), EncodingError);
  assert.throws(() => {
    const t = new Reader(fromHex("000161ff"));
    t.lp16();
    t.end();
  }, EncodingError);
  assert.throws(() => new Reader(fromHex("0001ff")).lp16(), EncodingError);
  assert.throws(() => new Reader(fromHex("0003eda080")).lp16(), EncodingError);
});

test("bytes compare bytewise, not by UTF-16 code unit", () => {
  // ☝️ (U+261D U+FE0F) and ☝🏻 (U+261D U+1F3FB): UTF-16 order puts the skin tone first, UTF-8 order puts it last.
  const plain = utf8("☝️");
  const toned = utf8("☝\u{1F3FB}");
  assert.ok("☝\u{1F3FB}" < "☝️");
  assert.ok(compareBytes(plain, toned) < 0);
  assert.equal(compareBytes(utf8("a"), utf8("ab")) < 0, true);
});

test("hex round-trips and refuses uppercase", () => {
  assert.equal(toHex(fromHex("00a1ff")), "00a1ff");
  assert.throws(() => fromHex("00A1"), EncodingError);
  assert.throws(() => fromHex("abc"), EncodingError);
});
