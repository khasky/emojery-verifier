// SPDX-License-Identifier: Apache-2.0
// The reactions a vote may set: each string exactly as it is signed, fully qualified
// RGI emoji with U+FE0F where it belongs. Nothing normalises a reaction; `❤` is not
// `❤️`. The list only grows - a removed string would lock every pair holding it.

import palette from "./reactions.palette.json" with { type: "json" };

/** @type {readonly string[]} */
export const PALETTE = Object.freeze([...palette.reactions]);
export const PALETTE_VERSION = palette.version;
export const PALETTE_SHA256 = palette.sha256;

const members = new Set(PALETTE);

/** @param {string} reaction */
export function isPaletteReaction(reaction) {
  return members.has(reaction);
}
