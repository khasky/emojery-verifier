// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone port of the transparency-log byte spec — this file IS the spec for
// the verifier: the canonical, fixed wire formats are defined here, not in a
// separate doc. Any deviation from them would make verification fail.

import * as ed from "@noble/ed25519";

// noble needs a SHA-512; Node's WebCrypto provides it everywhere.
ed.etc.sha512Async = (...m) =>
  crypto.subtle.digest("SHA-512", ed.etc.concatBytes(...m)).then((b) => new Uint8Array(b));

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const LP_NULL = 0xffffffff;
export const OP_REVOKE = 4;
// Identity track (op 5..7). Never folded into counters; checked by the identity
// invariants below and by identity.mjs.
export const OP_ENROLL = 5; // one per (account, account key): the ZK-proven OpenID registration, keyed by nullifier
export const OP_ISSUE = 6; // one blind-signed epoch-key grant, authorised by the enrolled account key
export const OP_KEY = 7; // one registered epoch pubkey with its unblinded RSA-PSS signature
// How many ISSUE leaves one enrolled account may hold per epoch (a second device,
// a reinstall). The default of --keys-per-account; every ISSUE is signed by the
// account's own key, so the cap bounds devices, not trust.
export const EPOCH_KEYS_PER_ACCOUNT = 10;

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
export function u8(n) {
  return Uint8Array.of(n & 0xff);
}
export function u32be(n) {
  const o = new Uint8Array(4);
  new DataView(o.buffer).setUint32(0, n >>> 0, false);
  return o;
}
export function u64be(n) {
  const o = new Uint8Array(8);
  new DataView(o.buffer).setBigUint64(0, BigInt(n), false);
  return o;
}
export function lp(s) {
  if (s === null || s === undefined) return u32be(LP_NULL);
  const b = utf8(s);
  return concatBytes(u32be(b.length), b);
}
export function lpb(b) {
  if (b === null || b === undefined) return u32be(LP_NULL);
  return concatBytes(u32be(b.length), b);
}
export function hexToBytes(s) {
  if (typeof s !== "string") throw new Error("hexToBytes: expected a hex string");
  const c = s.startsWith("\\x") ? s.slice(2) : s;
  // Fail loud on malformed hex rather than silently substituting 0x00: parseInt("zz",16)
  // is NaN -> 0 in the loop below, and an odd length drops the last nibble, so a bad root
  // or leaf would recompute to a WRONG value that mismatches a real one only by luck. The
  // publisher's encoder rejects the same inputs; this keeps the two byte-for-byte.
  if (c.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(c)) {
    throw new Error(`hexToBytes: invalid hex (${c.length} chars): ${c.slice(0, 24)}${c.length > 24 ? "…" : ""}`);
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
export function base64ToBytes(s) {
  return new Uint8Array(Buffer.from(s, "base64"));
}

export async function sha256(b) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", b));
}

// canonical = u64(seq) || u64(ts) || u8(op)
//           || lp(site) || lp(target_id) || lp(reaction) || lp(prev_reaction) || lp(user_ref)
// op 1..3 with a client key appends || lpb(pubkey) || lpb(sig) || lp(nonce) — a legacy
//   (1.0.0, unsigned) vote keeps the bare 8-field bytes;
// op=4 appends || u64(revoke_seq) || lp(reason_code) || lpb(evidence_hash);
// op=5 appends || lp(nullifier) || lp(iss) || lp(aud) || lp(kid) || lpb(proof_hash32) || lpb(salt_commitment) || lpb(account_pubkey);
// op=6 appends || lp(nullifier) || u64(epoch) || lpb(account_pubkey) || lpb(blinded_hash) || lpb(account_sig);
// op=7 appends || u64(epoch) || lpb(pubkey) || lpb(key_sig).
// For op 4..7 the five base strings are NULL.
export function serializeLeaf(f) {
  const base = concatBytes(
    u64be(f.seq),
    u64be(f.ts),
    u8(f.op),
    lp(f.site),
    lp(f.targetId),
    lp(f.reaction),
    lp(f.prevReaction),
    lp(f.userRef),
  );
  switch (f.op) {
    case OP_REVOKE:
      return concatBytes(base, u64be(f.revokeSeq ?? 0), lp(f.reasonCode ?? null), lpb(f.evidenceHash ?? null));
    case OP_ENROLL:
      return concatBytes(base, lp(f.nullifier ?? null), lp(f.iss ?? null), lp(f.aud ?? null), lp(f.kid ?? null), lpb(f.proofHash ?? null), lpb(f.saltCommitment ?? null), lpb(f.accountPubkey ?? null));
    case OP_ISSUE:
      return concatBytes(base, lp(f.nullifier ?? null), u64be(f.epoch ?? 0), lpb(f.accountPubkey ?? null), lpb(f.blindedHash ?? null), lpb(f.accountSig ?? null));
    case OP_KEY:
      return concatBytes(base, u64be(f.epoch ?? 0), lpb(f.clientPubkey ?? null), lpb(f.keySig ?? null));
    default:
      if (f.clientPubkey == null) return base;
      return concatBytes(base, lpb(f.clientPubkey), lpb(f.clientSig ?? null), lp(f.clientNonce ?? null));
  }
}

// --- signed messages (cross-repo contract) ---------------------------------
//
// The extension signs these exact bytes; the verifier re-derives them from the
// public leaf. Domain prefixes are raw UTF-8, not length-prefixed.

// Ed25519 message of one vote: "emojery-vote-v1" || lp(site) || lp(target_id) || lp(reaction) || lp(nonce).
export function voteSignatureMessage(site, targetId, reaction, nonce) {
  return concatBytes(utf8("emojery-vote-v1"), lp(site), lp(targetId), lp(reaction), lp(nonce));
}

// RSA-PSS (blind-signed) message binding an epoch pubkey: "emojery-epoch-key-v1" || u64be(epoch) || pubkey32.
export function epochKeyMessage(epoch, pubkey) {
  if (pubkey.length !== 32) throw new Error("epochKeyMessage: pubkey must be 32 bytes");
  return concatBytes(utf8("emojery-epoch-key-v1"), u64be(epoch), pubkey);
}

// Ed25519 (account-key) message authorising one ISSUE: "emojery-issue-v1" || u64be(epoch) || blinded_hash32,
// where blinded_hash = SHA256 of the blinded RSA message the grant was signed over.
export function issueMessage(epoch, blindedHash) {
  if (blindedHash.length !== 32) throw new Error("issueMessage: blinded_hash must be 32 bytes");
  return concatBytes(utf8("emojery-issue-v1"), u64be(epoch), blindedHash);
}
export function leafHash(f) {
  return sha256(concatBytes(u8(LEAF_PREFIX), serializeLeaf(f)));
}
export function nodeHash(l, r) {
  return sha256(concatBytes(u8(NODE_PREFIX), l, r));
}

// --- hash chain -----------------------------------------------------------

// prev_hash of seq=1.
export const GENESIS_PREV = new Uint8Array(32);

// entry_hash = SHA256(0x00 || prev_hash || leaf_hash)
export function entryHash(prevHash, leaf) {
  return sha256(concatBytes(u8(LEAF_PREFIX), prevHash, leaf));
}

// Replay the published chain. The Merkle root already pins WHICH leaves the tree
// holds; the chain pins their ORDER, and every row of /log/entries publishes its
// entry_hash — so a chain nobody replays is a published claim nobody checks. The
// leaf hashes come from the caller's own recomputation, never from the served
// leaf_hash field, so this cannot inherit a lie that check 3 just caught.
//
// A row without an entry_hash cannot chain the rows after it (there is nothing to
// carry forward), so the replay stops there rather than reporting every later leaf.
export async function checkHashChain(entries, leaves) {
  const violations = [];
  let prev = GENESIS_PREV;
  for (const [i, e] of entries.entries()) {
    if (!e.entry_hash) {
      violations.push(`seq=${e.seq}: no entry_hash — a checkpoint-covered leaf is unchained (chain replay stops here)`);
      break;
    }
    const got = bytesToHex(await entryHash(prev, leaves[i]));
    if (got !== e.entry_hash) {
      // Both hashes in full: a truncated pair reads as identical whenever the
      // difference sits in the tail, which is exactly when someone is looking.
      violations.push(`seq=${e.seq}: entry_hash ${e.entry_hash} != recomputed ${got}`);
    }
    prev = hexToBytes(e.entry_hash);
  }
  return violations;
}

async function appendLeafToFringe(fringe, leaf) {
  let carry = leaf;
  let level = 0;
  while (fringe[level]) {
    carry = await nodeHash(fringe[level], carry);
    fringe[level] = null;
    level++;
  }
  fringe[level] = carry;
}

async function rootOfFringe(fringe) {
  let root = null;
  for (let l = 0; l < fringe.length; l++) {
    if (!fringe[l]) continue;
    root = root === null ? fringe[l] : await nodeHash(fringe[l], root);
  }
  return root;
}

// Incremental (binary-counter) Merkle root over leaf hashes — O(N).
export async function merkleRootFromLeaves(leaves) {
  const fringe = [];
  for (const leaf of leaves) await appendLeafToFringe(fringe, leaf);
  return rootOfFringe(fringe);
}

// Roots of every historical prefix in `sizes`, from ONE pass over the leaves
// (O(N + |sizes|·log N)). Feeds the checkpoint-archive replay: every signed
// tree head ever published must equal the root recomputed at its tree_size
// from today's leaves — i.e. all checkpoints lie on one append-only history.
// Returns Map<size, rootBytes>; sizes beyond leaves.length are absent.
export async function merkleRootsAtSizes(leaves, sizes) {
  const want = new Set(sizes.map(Number));
  const roots = new Map();
  const fringe = [];
  for (let i = 0; i < leaves.length; i++) {
    await appendLeafToFringe(fringe, leaves[i]);
    if (want.has(i + 1)) roots.set(i + 1, await rootOfFringe(fringe));
  }
  return roots;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (const [i, byte] of a.entries()) diff |= byte ^ (b[i] ?? 0);
  return diff === 0;
}

function isPow2(n) {
  if (n < 1 || !Number.isInteger(n)) return false;
  while (n % 2 === 0) n /= 2;
  return n === 1;
}

// Does the tree of size `second` contain the tree of size `first` as a prefix?
// Answered from ~log2(second) hashes with no leaf in hand - which is the whole
// point: an auditor who only wants to know that nothing was rewritten never
// downloads the log. The operator publishes the proof beside each checkpoint
// (checks/archive.mjs), so this runs offline too.
// Keep in sync with emojery-workers src/lib/merkle.ts verifyConsistency.
export async function verifyConsistency(first, second, oldRoot, newRoot, proofIn) {
  if (first < 0 || first > second) return false;
  if (first === 0) return true; // every tree extends the empty tree
  if (first === second) return proofIn.length === 0 && bytesEqual(oldRoot, newRoot);
  const proof = isPow2(first) ? [oldRoot, ...proofIn] : proofIn;
  if (proof.length === 0) return false;
  // Two indices walking up the same path, one in each tree, and the two roots
  // rebuilt in step from the shared node the proof starts at.
  let oldIdx = first - 1;
  let newIdx = second - 1;
  while (oldIdx % 2 === 1) {
    oldIdx = Math.floor(oldIdx / 2);
    newIdx = Math.floor(newIdx / 2);
  }
  const seed = proof[0];
  if (!seed) return false;
  let oldHash = seed;
  let newHash = seed;
  for (const sibling of proof.slice(1)) {
    if (newIdx === 0) return false;
    if (oldIdx % 2 === 1 || oldIdx === newIdx) {
      oldHash = await nodeHash(sibling, oldHash);
      newHash = await nodeHash(sibling, newHash);
      if (oldIdx % 2 === 0) {
        do {
          oldIdx = Math.floor(oldIdx / 2);
          newIdx = Math.floor(newIdx / 2);
        } while (oldIdx % 2 === 0 && oldIdx !== 0);
      }
    } else {
      newHash = await nodeHash(newHash, sibling);
    }
    oldIdx = Math.floor(oldIdx / 2);
    newIdx = Math.floor(newIdx / 2);
  }
  return newIdx === 0 && bytesEqual(oldHash, oldRoot) && bytesEqual(newHash, newRoot);
}

export function sthBytes(treeSize, rootHash, ts) {
  return concatBytes(u64be(treeSize), rootHash, u64be(ts));
}
export function verifySth(pubRawB64, sigBytes, sth) {
  return ed.verifyAsync(sigBytes, sthBytes(sth.treeSize, sth.rootHash, sth.ts), base64ToBytes(pubRawB64));
}
// Generic Ed25519 verification over arbitrary bytes.
export function verifySignature(pubRawB64, sigBytes, msgBytes) {
  return ed.verifyAsync(sigBytes, msgBytes, base64ToBytes(pubRawB64));
}

// Per-UTC-day aggregates derivable from the public entries: reactions (op
// 1/2/3), distinct pseudonyms among them, and revocations (op=4).
export function dailyAggregates(entries) {
  const perDay = new Map(); // YYYY-MM-DD -> { votes, refs:Set, revokes }
  const dayOf = (ts) => new Date(Number(ts)).toISOString().slice(0, 10);
  const bucket = (day) => {
    let b = perDay.get(day);
    if (!b) {
      b = { votes: 0, refs: new Set(), revokes: 0 };
      perDay.set(day, b);
    }
    return b;
  };
  for (const e of entries) {
    if (e.op === 1 || e.op === 2 || e.op === 3) {
      const b = bucket(dayOf(e.ts));
      b.votes++;
      if (e.user_ref != null) b.refs.add(e.user_ref);
    } else if (e.op === 4) {
      bucket(dayOf(e.ts)).revokes++;
    }
  }
  return perDay;
}

export function counterKey(site, target, reaction) {
  return `${site}\x00${target}\x00${reaction}`;
}

// log → counters fold (mirrors the served counter math, including op=4 revoke reversal).
export function foldCounters(entries) {
  const counts = new Map();
  const bump = (site, target, reaction, delta) => {
    if (reaction === null || reaction === undefined) return;
    const k = counterKey(site, target, reaction);
    counts.set(k, (counts.get(k) ?? 0) + delta);
  };
  // Index op∈{1,2,3} by seq so a revoke (op=4) can resolve + invert its target.
  const bySeq = new Map();
  const revoked = new Set();
  for (const e of entries) {
    if (e.op === 1) {
      bump(e.site, e.target_id, e.reaction, 1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 2) {
      bump(e.site, e.target_id, e.reaction, 1);
      bump(e.site, e.target_id, e.prev_reaction, -1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 3) {
      bump(e.site, e.target_id, e.prev_reaction, -1);
      bySeq.set(String(e.seq), e);
    } else if (e.op === 4) {
      const rk = e.revoke_seq == null ? null : String(e.revoke_seq);
      if (rk === null || revoked.has(rk)) continue; // missing / double-revoke -> no-op
      const t = bySeq.get(rk);
      if (!t) continue; // unseen / not op∈{1,2,3} -> no-op
      revoked.add(rk);
      if (t.op === 1) bump(t.site, t.target_id, t.reaction, -1);
      else if (t.op === 2) {
        bump(t.site, t.target_id, t.reaction, -1);
        bump(t.site, t.target_id, t.prev_reaction, 1);
      } else if (t.op === 3) bump(t.site, t.target_id, t.prev_reaction, 1);
    }
  }
  for (const [k, v] of counts) if (v < 0) counts.set(k, 0);
  return counts;
}

// Structural consistency an honest log always satisfies, replayed from the
// public entries alone. They check that entries follow the log's own rules — i.e.
// integrity of the record, not authenticity of each author.
//
// Returns an array of human-readable violation strings (empty = all hold).
//
// Five independent checks:
//   A. Per-leaf op/field validity.
//   B. A per-author state machine — no double-add, and a stated previous reaction
//      must match the known current one. A switch/remove may legitimately be the
//      first event seen for an author, so that alone is not a violation.
//   C. Global non-negativity of the per-(site, target, reaction) count at every
//      prefix — an honest log never drives a reaction below zero.
//   D. Every revoke cites an existing EARLIER op∈{1,2,3} leaf (no dangling,
//      forward, or self reference).
//   E. No leaf is revoked twice.
export function checkStructuralInvariants(entries) {
  const violations = [];
  const state = new Map(); // `${user_ref}\x00${site}\x00${target}` -> current reaction | null
  const raw = new Map(); // counterKey(site,target,reaction) -> UNCLAMPED running count
  const seen123 = new Set(); // seqs of prior op∈{1,2,3} (invariant D)
  const revokedSeqs = new Set(); // revoke_seqs already cited (invariant E)
  const bump = (site, target, reaction, delta) => {
    const k = counterKey(site, target, reaction);
    const next = (raw.get(k) ?? 0) + delta;
    raw.set(k, next);
    return next;
  };

  for (const e of entries) {
    const op = e.op;

    // A. per-leaf op/field validity
    if (op === 1) {
      if (e.reaction == null || e.prev_reaction != null)
        violations.push(`seq=${e.seq}: malformed add (reaction set, prev_reaction null)`);
    } else if (op === 2) {
      if (e.reaction == null || e.prev_reaction == null || e.reaction === e.prev_reaction)
        violations.push(`seq=${e.seq}: malformed switch (reaction & prev_reaction set and distinct)`);
    } else if (op === 3) {
      if (e.reaction != null || e.prev_reaction == null)
        violations.push(`seq=${e.seq}: malformed remove (reaction null, prev_reaction set)`);
    } else if (op === 4) {
      // D + E (revoke): must cite an existing EARLIER op∈{1,2,3}; no double-revoke.
      const rk = e.revoke_seq == null ? null : String(e.revoke_seq);
      if (rk === null) violations.push(`seq=${e.seq}: revoke missing revoke_seq`);
      else if (!seen123.has(rk))
        violations.push(
          `seq=${e.seq}: revoke_seq=${rk} has no prior add/switch/remove (dangling/forward/self)`,
        );
      else if (revokedSeqs.has(rk)) violations.push(`seq=${e.seq}: double-revoke of seq=${rk}`);
      else revokedSeqs.add(rk);
      continue; // revoke has no B/C state-machine effect
    } else if (op === OP_ENROLL || op === OP_ISSUE || op === OP_KEY) {
      // Identity leaves carry no vote fields; their own shape is checked here, their
      // cross-leaf rules (G/H/I) by checkIdentityInvariants.
      for (const v of identityLeafShape(e)) violations.push(`seq=${e.seq}: ${v}`);
      continue;
    } else {
      violations.push(`seq=${e.seq}: unexpected op=${op}`);
      continue;
    }
    // A signed vote (1.0.1+) carries its key, signature and nonce; a legacy vote has none
    // of the three. Half a tail is neither.
    if (e.client_pubkey != null || e.client_sig != null || e.client_nonce != null) {
      if (!isHex(e.client_pubkey, 64)) violations.push(`seq=${e.seq}: client_pubkey is not 32 bytes hex`);
      if (!isHex(e.client_sig, 128)) violations.push(`seq=${e.seq}: client_sig is not 64 bytes hex`);
      if (typeof e.client_nonce !== "string" || e.client_nonce.length === 0) violations.push(`seq=${e.seq}: client_nonce missing`);
    }

    // B. per-(user_ref, site, target) state machine
    const sk = `${e.user_ref}\x00${e.site}\x00${e.target_id}`;
    const cur = state.get(sk) ?? null;
    if (op === 1) {
      if (cur != null)
        violations.push(`seq=${e.seq}: double-add (user_ref already active=${cur} on this target)`);
      state.set(sk, e.reaction);
    } else if (op === 2) {
      if (cur != null && cur !== e.prev_reaction)
        violations.push(`seq=${e.seq}: switch prev_reaction=${e.prev_reaction} != known current=${cur}`);
      state.set(sk, e.reaction);
    } else if (op === 3) {
      if (cur != null && cur !== e.prev_reaction)
        violations.push(`seq=${e.seq}: remove prev_reaction=${e.prev_reaction} != known current=${cur}`);
      state.set(sk, null);
    }

    // C. global unclamped non-negativity per (site, target, reaction)
    if (op === 1) {
      bump(e.site, e.target_id, e.reaction, 1);
    } else if (op === 2) {
      bump(e.site, e.target_id, e.reaction, 1);
      if (bump(e.site, e.target_id, e.prev_reaction, -1) < 0)
        violations.push(`seq=${e.seq}: count for ${e.prev_reaction} went negative (switch-away exceeds adds)`);
    } else if (op === 3) {
      if (bump(e.site, e.target_id, e.prev_reaction, -1) < 0)
        violations.push(`seq=${e.seq}: count for ${e.prev_reaction} went negative (remove exceeds adds)`);
    }

    seen123.add(String(e.seq)); // op∈{1,2,3} only (op=4 continues earlier)
  }
  return violations;
}

function isHex(v, chars) {
  return typeof v === "string" && v.length === chars && /^[0-9a-f]+$/i.test(v);
}

// The ENROLL proof column, base64 on the wire. The spec names the key `proof`; `proof_b64`
// is read too so a projection spelling it that way still hashes.
// Where the ENROLL proof's bytes are found: the leaf carries only their digest, and
// the object is stored under it (docs/transparency.md "Enrolment proofs").
export function proofObjectPath(hashHex) {
  return `proofs/${hashHex.slice(0, 2)}/${hashHex}.bin`;
}

function isEpoch(v) {
  return v != null && /^\d{1,19}$/.test(String(v));
}

// Per-leaf shape of an identity leaf (invariant A for op 5..7): the vote fields are
// NULL and the op's own fields are present and well-sized.
function identityLeafShape(e) {
  const v = [];
  if (e.site != null || e.target_id != null || e.reaction != null || e.prev_reaction != null) v.push(`op=${e.op} leaf carries vote fields`);
  if (e.op === OP_ENROLL) {
    if (!isHex(e.nullifier, 64)) v.push("enroll nullifier is not 32 bytes hex");
    if (typeof e.iss !== "string" || !e.iss) v.push("enroll iss missing");
    if (typeof e.aud !== "string" || !e.aud) v.push("enroll aud missing");
    if (typeof e.kid !== "string" || !e.kid) v.push("enroll kid missing");
    if (!isHex(e.proof_hash, 64)) v.push("enroll proof_hash is not 32 bytes hex");
    if (!isHex(e.salt_commitment, 64)) v.push("enroll salt_commitment is not 32 bytes hex");
    if (!isHex(e.account_pubkey, 64)) v.push("enroll account_pubkey is not 32 bytes hex");
  } else if (e.op === OP_ISSUE) {
    if (!isHex(e.nullifier, 64)) v.push("issue nullifier is not 32 bytes hex");
    if (!isEpoch(e.epoch)) v.push("issue epoch missing");
    if (!isHex(e.account_pubkey, 64)) v.push("issue account_pubkey is not 32 bytes hex");
    if (!isHex(e.blinded_hash, 64)) v.push("issue blinded_hash is not 32 bytes hex");
    if (!isHex(e.account_sig, 128)) v.push("issue account_sig is not 64 bytes hex");
  } else if (e.op === OP_KEY) {
    if (!isEpoch(e.epoch)) v.push("key epoch missing");
    if (!isHex(e.client_pubkey, 64)) v.push("key client_pubkey is not 32 bytes hex");
    if (!isHex(e.key_sig, 512)) v.push("key key_sig is not 256 bytes hex");
  }
  return v;
}

// A vote leaf that carries a client key (1.0.1+). A legacy 1.0.0 vote has none and is
// admitted only under --allow-unsigned-votes.
export function isSignedVote(e) {
  return (e.op === 1 || e.op === 2 || e.op === 3) && e.client_pubkey != null;
}

// Identity invariants G (structural half), H (count half) and I, replayed from the
// public entries alone — no key material, no network. The cryptographic halves of G
// and H live in verifyIdentitySignatures, J in identity.mjs.
//
//   G. a signed vote names a pubkey registered by an EARLIER op=7 leaf, its user_ref is
//      SHA256(pubkey), and its nonce is unique per pubkey (a replayed signature is the
//      same bytes twice, so a repeated nonce is the tell).
//   H. per epoch, count(KEY) <= count(ISSUE): the operator can register no more keys
//      than it blind-signed grants for; and no pubkey is registered twice.
//   I. an ISSUE cites an EARLIER ENROLL by its (nullifier, account_pubkey) pair, its
//      blinded_hash is unique (one grant, one leaf), at most keysPerAccount per
//      (nullifier, epoch); an ENROLL (nullifier, account_pubkey) pair is unique (one
//      account may enroll several account keys, one per install).
//
// Returns { violations, signedVotes, unsignedVotes, enrolls, issues, keys }.
export async function checkIdentityInvariants(entries, { keysPerAccount = EPOCH_KEYS_PER_ACCOUNT } = {}) {
  const violations = [];
  const enrolled = new Set(); // `${nullifier}\x00${account_pubkey}` pairs with an earlier ENROLL
  const blindedHashes = new Map(); // blinded_hash hex -> seq of its ISSUE leaf
  const issuesPer = new Map(); // `${nullifier}\x00${epoch}` -> count
  const issuesPerEpoch = new Map(); // epoch -> count(ISSUE)
  const keysPerEpoch = new Map(); // epoch -> count(KEY)
  const registered = new Map(); // pubkey hex -> seq of its KEY leaf
  const noncesPer = new Map(); // pubkey hex -> Set(nonce)
  let signedVotes = 0;
  let unsignedVotes = 0;
  let enrolls = 0;
  let issues = 0;
  let keys = 0;
  for (const e of entries) {
    if (e.op === OP_ENROLL) {
      enrolls++;
      if (typeof e.nullifier !== "string" || !isHex(e.account_pubkey, 64)) continue; // shape: invariant A
      const pair = `${e.nullifier}\x00${e.account_pubkey.toLowerCase()}`;
      if (enrolled.has(pair)) violations.push(`seq=${e.seq}: second ENROLL for nullifier ${e.nullifier.slice(0, 12)}... under account key ${e.account_pubkey.slice(0, 12)}...`);
      enrolled.add(pair);
    } else if (e.op === OP_ISSUE) {
      issues++;
      if (typeof e.nullifier !== "string" || !isEpoch(e.epoch) || !isHex(e.account_pubkey, 64) || !isHex(e.blinded_hash, 64)) continue;
      const epoch = String(e.epoch);
      const pair = `${e.nullifier}\x00${e.account_pubkey.toLowerCase()}`;
      if (!enrolled.has(pair)) violations.push(`seq=${e.seq}: ISSUE for nullifier ${e.nullifier.slice(0, 12)}... under account key ${e.account_pubkey.slice(0, 12)}... with no prior ENROLL of that pair`);
      const bh = e.blinded_hash.toLowerCase();
      if (blindedHashes.has(bh)) violations.push(`seq=${e.seq}: blinded_hash ${bh.slice(0, 12)}... already issued by seq=${blindedHashes.get(bh)}`);
      else blindedHashes.set(bh, String(e.seq));
      const k = `${e.nullifier}\x00${epoch}`;
      const n = (issuesPer.get(k) ?? 0) + 1;
      issuesPer.set(k, n);
      if (keysPerAccount > 0 && n > keysPerAccount) violations.push(`seq=${e.seq}: ISSUE #${n} for one nullifier in epoch ${epoch} (limit ${keysPerAccount})`);
      issuesPerEpoch.set(epoch, (issuesPerEpoch.get(epoch) ?? 0) + 1);
    } else if (e.op === OP_KEY) {
      keys++;
      if (!isHex(e.client_pubkey, 64) || !isEpoch(e.epoch)) continue;
      const epoch = String(e.epoch);
      const pk = e.client_pubkey.toLowerCase();
      if (registered.has(pk)) violations.push(`seq=${e.seq}: pubkey ${pk.slice(0, 12)}... already registered by seq=${registered.get(pk)}`);
      else registered.set(pk, String(e.seq));
      const n = (keysPerEpoch.get(epoch) ?? 0) + 1;
      keysPerEpoch.set(epoch, n);
      if (n > (issuesPerEpoch.get(epoch) ?? 0)) violations.push(`seq=${e.seq}: KEY #${n} in epoch ${epoch} exceeds the ${issuesPerEpoch.get(epoch) ?? 0} ISSUE leaf(s) so far`);
    } else if (e.op === 1 || e.op === 2 || e.op === 3) {
      if (e.client_pubkey == null) {
        unsignedVotes++;
        continue;
      }
      signedVotes++;
      if (!isHex(e.client_pubkey, 64)) continue;
      const pk = e.client_pubkey.toLowerCase();
      if (!registered.has(pk)) violations.push(`seq=${e.seq}: signed vote under pubkey ${pk.slice(0, 12)}... with no prior KEY leaf`);
      const expectRef = bytesToHex(await sha256(hexToBytes(pk)));
      if (String(e.user_ref).toLowerCase() !== expectRef) violations.push(`seq=${e.seq}: user_ref is not SHA256(client_pubkey)`);
      let nonces = noncesPer.get(pk);
      if (!nonces) {
        nonces = new Set();
        noncesPer.set(pk, nonces);
      }
      if (nonces.has(e.client_nonce)) violations.push(`seq=${e.seq}: nonce reused under pubkey ${pk.slice(0, 12)}... (replayed signature)`);
      nonces.add(e.client_nonce);
    }
  }
  return { violations, signedVotes, unsignedVotes, enrolls, issues, keys };
}

// RSA-PSS parameters of the blind signature (RFC 9474 RSABSSA-SHA384-PSS-Deterministic):
// the unblinded signature verifies as an ordinary RSA-PSS signature with these.
const BLIND_RSA_PSS = { name: "RSA-PSS", hash: "SHA-384" };
const BLIND_RSA_SALT_LENGTH = 48;

// The cryptographic halves of G, H and I:
//   G. every signed vote's Ed25519 signature verifies under its pubkey over
//      voteSignatureMessage(site, target_id, reaction, nonce);
//   H. every KEY leaf's key_sig is a valid RSA-PSS signature under the pinned blind
//      public key over epochKeyMessage(epoch, pubkey);
//   I. every ISSUE leaf's account_sig is a valid Ed25519 signature under its
//      account_pubkey over issueMessage(epoch, blinded_hash).
// blindPubkeySpkiB64 empty -> H is not attempted (keysSkipped counts what was left).
// Returns { voteViolations, keyViolations, issueViolations, votesChecked, keysChecked, keysSkipped, issuesChecked }.
export async function verifyIdentitySignatures(entries, { blindPubkeySpkiB64 } = {}, onProgress) {
  const voteViolations = [];
  const keyViolations = [];
  const issueViolations = [];
  let votesChecked = 0;
  let keysChecked = 0;
  let keysSkipped = 0;
  let issuesChecked = 0;
  let blindKey = null;
  if (blindPubkeySpkiB64) {
    blindKey = await crypto.subtle.importKey("spki", base64ToBytes(blindPubkeySpkiB64), BLIND_RSA_PSS, false, ["verify"]);
  }
  let done = 0;
  for (const e of entries) {
    done++;
    if (isSignedVote(e)) {
      if (!isHex(e.client_pubkey, 64) || !isHex(e.client_sig, 128)) continue; // shape: invariant A
      votesChecked++;
      const msg = voteSignatureMessage(e.site, e.target_id, e.reaction ?? null, e.client_nonce ?? null);
      const ok = await verifySignature(Buffer.from(hexToBytes(e.client_pubkey)).toString("base64"), hexToBytes(e.client_sig), msg).catch(() => false);
      if (!ok) voteViolations.push(`seq=${e.seq}: vote signature does not verify under client_pubkey ${e.client_pubkey.slice(0, 12)}...`);
    } else if (e.op === OP_ISSUE) {
      if (!isHex(e.account_pubkey, 64) || !isHex(e.account_sig, 128) || !isHex(e.blinded_hash, 64) || !isEpoch(e.epoch)) continue;
      issuesChecked++;
      const msg = issueMessage(BigInt(e.epoch), hexToBytes(e.blinded_hash));
      const ok = await verifySignature(Buffer.from(hexToBytes(e.account_pubkey)).toString("base64"), hexToBytes(e.account_sig), msg).catch(() => false);
      if (!ok) issueViolations.push(`seq=${e.seq}: account_sig does not verify under account_pubkey ${e.account_pubkey.slice(0, 12)}... (epoch ${e.epoch})`);
    } else if (e.op === OP_KEY) {
      if (!isHex(e.client_pubkey, 64) || !isHex(e.key_sig, 512) || !isEpoch(e.epoch)) continue;
      if (!blindKey) {
        keysSkipped++;
        continue;
      }
      keysChecked++;
      const msg = epochKeyMessage(BigInt(e.epoch), hexToBytes(e.client_pubkey));
      const ok = await crypto.subtle.verify({ ...BLIND_RSA_PSS, saltLength: BLIND_RSA_SALT_LENGTH }, blindKey, hexToBytes(e.key_sig), msg).catch(() => false);
      if (!ok) keyViolations.push(`seq=${e.seq}: key_sig does not verify under the pinned blind key (epoch ${e.epoch}, pubkey ${e.client_pubkey.slice(0, 12)}...)`);
    }
    if (onProgress) onProgress(done, entries.length);
  }
  return { voteViolations, keyViolations, issueViolations, votesChecked, keysChecked, keysSkipped, issuesChecked };
}

// Default grace for an in-progress or resumed account wipe. A wipe normally lands
// within seconds, and a resumed one emits revokes with a fresh ts, restarting the
// clock. 48h gives two daily verifier runs of slack while bounding how long a
// half-wiped pseudonym can sit unreported. A policy knob, not a proof parameter —
// auditors of a quiescent log may tighten it to 0.
export const WIPE_GRACE_MS = 48 * 3_600_000;

// Invariant F — account-wipe completeness. Revocations are whole-account: the log
// operator has no per-vote reversal, so once ANY op=4 leaf cites a pseudonym's leaf,
// EVERY op∈{1,2,3} leaf carrying that user_ref must be cited by some op=4 leaf. A
// partially revoked pseudonym is the signature of a surgical vote removal dressed up
// as an account operation, so it is flagged. Completeness is per-pseudonym: user_refs
// rotate per epoch and cannot be linked across epochs (a privacy property of the log),
// so each pseudonym of one account is checked independently.
//
// tipTs is the checkpoint ts; grace is anchored to the pseudonym's FIRST (oldest) citing
// revoke — the moment its wipe began — not the newest. A real account erasure revokes
// every one of a pseudonym's leaves in a single operation (seconds, not days), so the
// window measured from the first revoke is generous. Anchoring to the newest instead let
// an operator keep a pseudonym "in grace" forever by dripping a fresh add+revoke pair
// every <graceMs, and never revoking one inconvenient vote it surgically kept. A revoke
// timestamped AFTER the checkpoint would keep its pseudonym in grace at every future
// verification, so it is flagged instead of trusted (honest leaves predate the checkpoint
// that covers them).
//
// Returns an array of human-readable violation strings (empty = all hold).
export function checkWipeCompleteness(entries, tipTs, graceMs = WIPE_GRACE_MS) {
  const violations = [];
  const bySeq = new Map(); // seq -> op∈{1,2,3} entry
  const byRef = new Map(); // user_ref -> op∈{1,2,3} entries
  const cited = new Set(); // seqs cited by any op=4
  const wipeStartedAt = new Map(); // user_ref -> FIRST (oldest) citing revoke ts
  for (const e of entries) {
    if (e.op === 1 || e.op === 2 || e.op === 3) {
      bySeq.set(String(e.seq), e);
      if (e.user_ref != null) {
        const list = byRef.get(e.user_ref) ?? [];
        list.push(e);
        byRef.set(e.user_ref, list);
      }
    } else if (e.op === 4) {
      if (Number(e.ts) > tipTs) {
        violations.push(`seq=${e.seq}: revoke ts=${e.ts} is after the checkpoint ts=${tipTs}`);
        continue;
      }
      const t = e.revoke_seq == null ? null : bySeq.get(String(e.revoke_seq));
      if (!t || t.user_ref == null) continue; // dangling/forward -> invariant D reports it
      cited.add(String(t.seq));
      const prev = wipeStartedAt.get(t.user_ref);
      if (prev === undefined || Number(e.ts) < prev) wipeStartedAt.set(t.user_ref, Number(e.ts));
    }
  }
  for (const [ref, startedTs] of wipeStartedAt) {
    if (tipTs - startedTs <= graceMs) continue; // wipe began within the grace window
    for (const leaf of byRef.get(ref) ?? []) {
      if (!cited.has(String(leaf.seq)))
        violations.push(
          `seq=${leaf.seq}: op=${leaf.op} leaf by wiped user_ref=${String(ref).slice(0, 12)}… not covered by any revoke (account-wipe incomplete)`,
        );
    }
  }
  return violations;
}

// Recompute a leaf hash from an /log/entries row (does NOT trust row.leaf_hash).
// Rows written before the identity fields existed carry none of them; an absent
// field reads as NULL, which for op 1..3 is exactly the legacy 8-field leaf.
export function leafHashFromEntry(e) {
  const bytesOrNull = (hex) => (hex == null ? null : hexToBytes(hex));
  if (e.op === OP_REVOKE) {
    // A revoke leaf serializes user_ref as NULL and appends revoke fields; any
    // user_ref present on the row is NOT part of the canonical bytes.
    return leafHash({
      seq: BigInt(e.seq),
      ts: e.ts,
      op: OP_REVOKE,
      site: e.site,
      targetId: e.target_id,
      reaction: null,
      prevReaction: null,
      userRef: null,
      revokeSeq: e.revoke_seq == null ? 0 : BigInt(e.revoke_seq),
      reasonCode: e.reason_code ?? null,
      evidenceHash: e.evidence_hash ? hexToBytes(e.evidence_hash) : null,
    });
  }
  if (e.op === OP_ENROLL || e.op === OP_ISSUE || e.op === OP_KEY) {
    // Identity leaves serialize every vote field as NULL; the DB's zero-sentinel
    // user_ref on the row is not part of the bytes (same as op=4).
    return leafHash({
      seq: BigInt(e.seq),
      ts: e.ts,
      op: e.op,
      site: null,
      targetId: null,
      reaction: null,
      prevReaction: null,
      userRef: null,
      nullifier: e.nullifier ?? null,
      iss: e.iss ?? null,
      aud: e.aud ?? null,
      kid: e.kid ?? null,
      proofHash: bytesOrNull(e.proof_hash),
      saltCommitment: bytesOrNull(e.salt_commitment),
      epoch: e.epoch == null ? 0 : BigInt(e.epoch),
      clientPubkey: bytesOrNull(e.client_pubkey),
      keySig: bytesOrNull(e.key_sig),
      accountPubkey: bytesOrNull(e.account_pubkey),
      blindedHash: bytesOrNull(e.blinded_hash),
      accountSig: bytesOrNull(e.account_sig),
    });
  }
  return leafHash({
    seq: BigInt(e.seq),
    ts: e.ts,
    op: e.op,
    site: e.site,
    targetId: e.target_id,
    reaction: e.reaction,
    prevReaction: e.prev_reaction,
    userRef: e.user_ref,
    clientPubkey: bytesOrNull(e.client_pubkey),
    clientSig: bytesOrNull(e.client_sig),
    clientNonce: e.client_nonce ?? null,
  });
}
