# Protocol: what the verifier checks, byte by byte

Everything here is needed to re-implement the checks in `src/`. The README says what the tool proves in plain words; this file says how.

## Log entries

Every entry (leaf) of the log has a sequence number `seq` (1-based), a timestamp `ts` (Unix milliseconds) and an operation `op`:

| `op` | Meaning |
| --- | --- |
| 1 | a reaction was added |
| 2 | a reaction was changed; the leaf records the new reaction and the previous one |
| 3 | a reaction was removed by the user |
| 4 | a revocation tombstone: a later leaf that reverses an earlier `op=1`, `op=2` or `op=3` leaf |
| 5 | ENROLL: an account key registered with a zero-knowledge proof over an OpenID token |
| 6 | ISSUE: a blind-signed epoch-key grant authorised by an enrolled account |
| 7 | KEY: a registered epoch public key with its unblinded blind signature; the signature was blinded, so the log shows that a key was issued, never to whom |

A normal "unreact" is `op=3`. Tombstones are append-only corrections: when an account is erased or a counted reaction has to be reversed, the original leaf is never edited or deleted; an `op=4` leaf is appended instead, with `revoke_seq` pointing at the reversed leaf, a public machine-readable `reason_code` (`erasure_self`, `erasure_admin`, or an abuse-correction label) and an `evidence_hash` that may pin a published evidence report (`null` for routine account erasure).

Votes carry a pseudonym `user_ref`. A signed vote ends in `client_pubkey || client_sig || client_nonce` and its pseudonym is `user_ref = SHA256(client_pubkey)`; a vote cast by extension 1.0.0 has none of the three. Pseudonyms rotate per epoch and cannot be linked across epochs, a privacy property of the log.

### Leaf bytes

`lp(s)` is `u32be(len) || utf8(s)`, `lpb(b)` is `u32be(len) || b`, and a NULL string or byte field is `u32be(0xffffffff)`. Every leaf starts with `base`:

```
base = u64be(seq) || u64be(ts) || u8(op) || lp(site) || lp(target_id) || lp(reaction) || lp(prev_reaction) || lp(user_ref)
```

All five strings are NULL on `op=4..7`. After `base`:

| Leaf | Bytes after `base` |
| --- | --- |
| `op=1..3`, signed | `lpb(client_pubkey32) \|\| lpb(client_sig64) \|\| lp(client_nonce)` (a 1.0.0 vote appends nothing) |
| `op=4` | `u64be(revoke_seq) \|\| lp(reason_code) \|\| lpb(evidence_hash)` |
| `op=5` ENROLL | `lp(nullifier) \|\| lp(iss) \|\| lp(aud) \|\| lp(kid) \|\| lpb(proof_hash32) \|\| lpb(salt_commitment32) \|\| lpb(account_pubkey32)` |
| `op=6` ISSUE | `lp(nullifier) \|\| u64be(epoch) \|\| lpb(account_pubkey32) \|\| lpb(blinded_hash32) \|\| lpb(account_sig64)` |
| `op=7` KEY | `u64be(epoch) \|\| lpb(client_pubkey32) \|\| lpb(key_sig256)` |

`nullifier` is hashed as its 64-character hex string (`lp`), the byte fields as raw bytes (`lpb`). On the wire (the published chunks) `account_pubkey`, `account_sig` and `blinded_hash` are hex where the leaf carries them and ABSENT where it does not - a field is omitted rather than spelled out as `null`, and a reader must treat the two the same: a row that lacks the key hashes it as NULL. An ENROLL row carries `proof_hash`, the SHA-256 of its proof, as 64 hex characters; the proof itself is 14 KB and is not in the row (see "Enrolment proofs" below).

```
leaf_hash  = SHA256(0x00 || leaf bytes)
node_hash  = SHA256(0x01 || left || right)
entry_hash(seq) = SHA256(0x00 || entry_hash(seq-1) || leaf_hash(seq)),  entry_hash(0) = 32 zero bytes
```

The Merkle root is the binary-counter fold over the leaf hashes in `seq` order: each new leaf is carried up while a node of the same level is waiting, and the root joins the waiting nodes from the lowest level up (`node_hash(higher, lower)`). Prefix roots at every historical `tree_size` come out of the same single pass.

### Signed checkpoint (STH)

```
sth = u64be(tree_size) || root_hash32 || u64be(ts)
```

signed with the log's Ed25519 key. `checkpoints/latest.json` in the log repository carries `{ tree_size, root_hash, ts, signature }`; `checkpoints/*.ndjson` shards hold every checkpoint ever published, one per line.

### Signed messages

Domain prefixes are raw UTF-8 (no length):

| Signer | Message |
| --- | --- |
| a vote, Ed25519 under `client_pubkey` | `"emojery-vote-v1" \|\| lp(site) \|\| lp(target_id) \|\| lp(reaction) \|\| lp(nonce)` |
| an ISSUE, Ed25519 under the account key | `"emojery-issue-v1" \|\| u64be(epoch) \|\| blinded_hash32` |
| a KEY, RSA-PSS (SHA-384, salt 48; RFC 9474 RSABSSA) under the blind key | `"emojery-epoch-key-v1" \|\| u64be(epoch) \|\| pubkey32` |

## The checks, in order

Each check has a key in the `--json` summary. A check that cannot run reports `skip`, which is never counted as a pass.

| Key | What must hold |
| --- | --- |
| `signature` | the checkpoint's Ed25519 signature verifies under the pinned (or `--pubkey`) key. |
| `freshness` | the live tip is at most `--max-checkpoint-age-hours` old (default 168; `0` skips). Judged on the tip, never on a checkpoint an offline run stepped back to. A `ts` more than 1 hour in the future is a failure of its own: the `ts` is inside the signed tree head, and a forward-dated one would sail under any threshold forever. |
| `leaf_hashes` | every served leaf, re-serialized from its fields, hashes to the served `leaf_hash`. |
| `merkle_root` | all `tree_size` leaves were fetched, and the root recomputed from the verifier's own leaf hashes equals the checkpoint's `root_hash`. |
| `hash_chain` | the published `entry_hash` chain replays from genesis with the recomputed leaf hashes. The root pins which leaves the tree holds; the chain pins their order. A row without `entry_hash` stops the replay at that row. |
| `archive` | with `--repo`: every line of `checkpoints/*.ndjson` parses; no two archived checkpoints disagree on one `tree_size`; every archived signature verifies; `ts` is monotone in `tree_size`; no archived `tree_size` exceeds the live tip; the live checkpoint is present; and every archived root equals the root recomputed from today's leaves at that `tree_size`, so the whole published history lies on one append-only line and an internally consistent rewrite still fails. |
| `rekor` | with `--repo` (unless `--no-rekor`): the newest `rekor/<tree_size>.json` sidecar at or below the tip names the same `root_hash` as the archived checkpoint (repo-local, a mismatch is a hard fail), and the entry it names in the pinned Rekor instance (`https://rekor.sigstore.dev`, never the URL the sidecar carries) holds exactly the STH bytes (as content, or as their SHA-256), our Ed25519 signature, and a PEM of the SPKI DER of the log key (`302a300506032b6570032100 \|\| raw32`). An unreachable Rekor or an unparseable entry is a skip; only disagreeing bytes fail. |
| `revocations` | the set of `seq` values `revocations/latest.json` lists equals the set of `op=4` leaves in the log, clamped to the audited `tree_size`. A log with no tombstone publishes no file, which is a skip. |
| `served_counts` | the exact `total` the public badge carries for the `--counts-sample` largest targets equals the fold of the log for those targets. The one check that holds the log against a number a reader is actually shown; The default base is pinned to the same deployment as the log key, so a run with another `--pubkey` needs `--counts-base`; `--counts-sample 0` skips it. |
| `invariants` | the structural invariants A, B, C, D, E below hold. |
| `wipe_completeness` | invariant F below holds. |
| `identity_structure` | invariants G (structural half), H (count half) and I hold; unsigned votes fail here unless `--allow-unsigned-votes`. |
| `vote_signatures` | every `client_sig` verifies under `client_pubkey` over the vote message. Skip while the log holds no signed vote. |
| `issue_signatures` | every `account_sig` verifies under the leaf's `account_pubkey` over the ISSUE message. Skip while there is no ISSUE leaf. |
| `key_signatures` | every `key_sig` verifies under the pinned blind public key over the KEY message. Skip while there is no KEY leaf, or no pinned blind key. |
| `enroll_proofs` | invariant J. Skip under `--no-proofs`, while there is no ENROLL leaf, or while a needed pin is empty. |
| `ots` | with `--ots`: see the Bitcoin section. Skip otherwise. |
| `ots_external` | only with `--ots-external`. |

Exit code `0` = every check passed or skipped, `1` = a check failed, `2` = usage error. Checks `signature` through `wipe_completeness` establish the integrity of the record; the identity track bounds who could have written it: every counted vote traces to an epoch key whose grant was signed by the enrolled account's own key, and that account's enrollment is proven against a real OpenID provider account. The operator can inflate a count only with real provider accounts, each visible as an ENROLL in the log.

### Counters

The per-`(site, target_id, reaction)` counters are folded from the verified leaves: `op=1` adds 1 to `reaction`, `op=2` adds 1 to `reaction` and subtracts 1 from `prev_reaction`, `op=3` subtracts 1 from `prev_reaction`, and `op=4` applies the inverse of the leaf `revoke_seq` points at (a revoke of an unseen or later `seq` is a no-op; a second revoke of the same leaf is idempotent). A counter driven below zero is clamped to zero at the end of the fold; invariant C reports the underflow. Nothing is compared with the live counter surface: the totals are derived independently from the public log alone.

### Invariants

- **A. per-leaf validity.** `op=1` has `reaction` and no `prev_reaction`; `op=2` has both, distinct; `op=3` has `prev_reaction` and no `reaction`; `op=4` has a `revoke_seq`; a vote with a `client_pubkey` has a 32-byte key, a 64-byte signature and a non-empty nonce; identity leaves carry no vote field and their byte fields have the right widths (`key_sig` 256 bytes, `account_sig` 64, ENROLL has a 32-byte proof digest and an account key, ISSUE has an epoch); any other `op` is unexpected.
- **B. per-`(user_ref, site, target)` state machine.** No double add while a reaction is active; a change or removal names the currently active reaction as `prev_reaction`. A change or removal may be the first event seen for an author, which alone is not a violation.
- **C. non-negativity.** No `(site, target, reaction)` count is ever driven below zero.
- **D. revocation targets.** A `revoke_seq` must name an earlier `op=1..3` leaf: not dangling, not forward, not the revoke itself.
- **E. no double revoke.** One leaf is cited by at most one tombstone.
- **F. account-wipe completeness.** Revocations are whole-account: once any leaf of a pseudonym is cited by a revocation, every leaf of that pseudonym must be, so a single inconvenient vote cannot be reversed under an account-operation label. Completeness is checked per pseudonym. A pseudonym whose wipe began less than `--wipe-grace-hours` (default 48) before the checkpoint `ts` counts as a wipe in flight; the window is anchored to the pseudonym's first citing revoke, so an operator cannot keep a pseudonym "in grace" by dripping fresh add-and-revoke pairs. A revoke timestamped after the checkpoint is flagged. A dangling revoke is left to D (no double report).
- **G. signed votes.** A signed vote names a `client_pubkey` an earlier KEY leaf registered, `user_ref == SHA256(client_pubkey)`, and no nonce repeats under one key. Unsigned votes fail unless `--allow-unsigned-votes`.
- **H. epoch keys.** Per epoch, `count(KEY) <= count(ISSUE)`; no pubkey registers twice; every `key_sig` verifies under the blind key.
- **I. grants.** Every ISSUE cites an earlier ENROLL with the same `(nullifier, account_pubkey)` pair, its `blinded_hash` is unique across ISSUE leaves, its `account_sig` verifies under that account key, and no `(nullifier, epoch)` holds more than `--keys-per-account` grants (default 10, `0` lifts the bound; a growth policy, since every grant carries the account's own signature, so exceeding it means one account asked for many keys, not that the operator minted any). An ENROLL `(nullifier, account_pubkey)` pair is unique; a reinstall makes a new account key and so a new ENROLL under the same nullifier.
- **J. enrollment proofs.** The body behind every ENROLL `proof_hash` is fetched, refused unless it hashes to that digest, and then verifies (UltraHonk, via `@aztec/bb.js`) under the pinned verification key `keys/enroll-v1.vk` from the log repository, with public inputs the verifier rebuilds itself (below). The `iss` must be an admitted issuer and the `aud` a pinned client id. The archived provider key `jwks/<provider>/<kid>.json` is cross-checked against the provider's live JWKS: unreachable is a note, a key the provider has since rotated out is a note, a different modulus is a failure. If `keys/enroll-v1.json` declares a `public_inputs` layout, it must end with `account_pubkey[32]`.

### ENROLL public inputs

The circuit's public inputs, one field each, in this order:

```
modulus[18] || redc[18] || iss[96] || iss_len || aud[128] || aud_len || nullifier[32] || salt_commitment[32] || account_pubkey[32]
```

- `modulus`: the provider's RSA-2048 modulus as 18 little-endian limbs of 120 bits, as `noir-jwt` 0.5.1 lays them out; `redc` is the Barrett parameter `floor(2^(2*2048+6) / n)` in the same limbs.
- `iss` and `aud`: fixed-width byte vectors (capacities 96 and 128) followed by their lengths.
- `nullifier`, `salt_commitment`, `account_pubkey`: 32 byte-fields each.

What a passing proof establishes: the operator held an RS256 `id_token` signed by that provider's published key, naming that `iss` and `aud` and some subject, whose `nonce` commits to the leaf's `account_pubkey`, and the leaf's nullifier is `SHA256("emojery-nullifier-v1" || lp(iss) || lp(sub) || lp(aud) || salt)` for the salt whose SHA-256 is the pinned `salt_commitment`. The subject is never revealed and the verifier never sees the token. The verification key is pinned, so a different circuit cannot be substituted; the salt commitment is pinned, so nullifiers from two salts cannot be mixed; and because the account key is inside the signed token's nonce, it was chosen by whoever held the provider session, before the provider signed. An ISSUE then needs that key's signature, so the operator cannot grant an epoch key to an account it did not sign in as.

`@aztec/bb.js` is pinned to an exact version in `package.json`, the same `bb` the operator proves with as recorded in `keys/enroll-v1.json` (a drift is reported next to the check). It is imported lazily, so a run with `--no-proofs`, or a log with no ENROLL leaf, never loads it. On first use it downloads the BN254 structured reference string into `~/.bb-crs` (a few MB) and takes about ten seconds to initialise the wasm prover. `pnpm install --ignore-scripts` is enough; its native optional dependency `msgpackr-extract` has a pure-JS fallback.

### Pins

`src/verify.mjs` pins `PINNED_PUBKEY_B64` (the log key), `PINNED_BLIND_PUBKEY_SPKI_B64` (the RSA-2048 blind-signing key, SPKI base64, also published as `keys/blind-rsa-v1.json`), `PINNED_ENROLL_VK_SHA256` (SHA-256 of `keys/enroll-v1.vk`), `PINNED_SALT_COMMITMENT`, `PINNED_AUDIENCES` and `PINNED_ISSUERS`. An empty identity pin makes the check that needs it a skip naming the pin. `PINNED_ENROLL_VK_SHA256` is the exception: were it ever left at the placeholder `REPLACE_WITH_ENROLL_V2_VK_SHA256`, a log with ENROLL leaves fails the proof check unless `--enroll-vk-hash` supplies the real digest. `keys/enroll-v1.json` in the log repository records the `bb` version, the salt commitment and the public-input layout.

## Reading the log

### Leaves

The log is published as files, and nothing about reading it goes through an API.

- `entries/<from>-<to>.ndjson` — a chunk: the leaves one publish covered, one JSON object per line. A chunk is written once and never touched again, so a copy of it is either the published bytes or refused.
- `entries/manifest/<first leaf>.ndjson` — one line per chunk, `{from, to, count, bytes, sha256}`, at most 1000 lines per file. The file names need no listing: the first is leaf 1, and the next one starts at the `to` of the last line of the one before it. No directory listing means no GitHub API, and no rate limit between a reader and the manifest.
- `entries/mirrors.json` — `{"base": "<url>"}`, where the bodies are served from. `--entries-base <url>` overrides it. A chunk is admitted only if its bytes hash to the `sha256` the manifest committed to, so which host served it decides nothing; anyone may publish a copy and name it in their own file.

A publish lands a tick behind the checkpoint that covers it, so the manifest routinely stops one chunk short of the signed tip. The run then steps back to the newest archived checkpoint the chunks fully cover, names it and the tip, and audits that one (the tip's own Rekor sidecar is still checked). Chunks that reach no archived checkpoint report the Merkle check as a skip: an incomplete mirror is not evidence against the log. The whole log is held in memory (about a gigabyte around a million leaves); past a few million, fold and verify from a streamed source instead.

### Enrolment proofs

An ENROLL leaf names its proof by digest rather than carrying it: a proof is 14 KB, and a line carrying one costs every reader of the chunk that much whether or not they check proofs. The body is served from the entries base as `proofs/<first two hex of the digest>/<digest>.bin`, and the verifier refuses any body that does not hash to the digest the leaf committed to before it reaches the prover — bytes that are not the ones the log committed to must never be reported as "a proof that did not verify".

Proof bodies are published with the chunk that names them, so an ENROLL past the manifest has none yet. A 404 past what the manifest says is mirrored is that window and is counted, not failed; a 404 inside it is a failure, and so is one on a log whose manifest cannot be read at all.

A log that has never signed anything publishes no `checkpoints/latest.json`; the verifier reports that as an empty log (PASS, `checks: { log: "empty" }`). Any other failure to read it fails the run.

The GitHub Contents API lists a directory up to 1000 entries without paginating; past that the verifier re-lists through the Git Trees API, and a Trees listing that itself truncates is reported so the archive and Rekor completeness checks are read as "over the listed subset". `GITHUB_TOKEN` lifts the unauthenticated quota; a rate-limited listing is a skip. The entries manifest is never listed - its file names are derived - so reading the leaves does not depend on that quota at all. Transient HTTP failures (429, 5xx) on the API and the raw repository are retried up to 4 times, honouring `Retry-After`.

### Tombstone file

`revocations/latest.json` carries every `op=4` leaf the log holds, as `{ tree_size, revocations: [{ seq, ts, revoke_seq, reason_code, evidence_hash, target: { site, target_id } }] }`, ascending by `seq`. Nothing in it is new: every field is already in the chunk line of the leaf it names. It exists for the readers who never fold the log - the site renders it - and the verifier compares its set of `seq` values with the `op=4` leaves, clamped to the audited `tree_size`, so a tombstone appended after the checkpoint under test is not read as a mismatch. A log with no tombstone publishes no file.

## Bitcoin anchor (`--ots`)

The verifier reads `ots/latest.json`, `ots/<tree_size>.json` and `ots/<tree_size>.ots` from `--repo`. The sidecar's `root_hash` must be a 64-hex digest (it is repo-controlled and, with `--ots-external`, becomes an argument of a spawned process), the sidecar must be a validly signed STH, and the `.ots` proof, parsed locally with no OpenTimestamps dependency, must commit that root in a Bitcoin block: the proof's Bitcoin attestation must equal the merkle root in the attested block header, and each header must double-SHA256 to the block id the explorer returned for its height, so the merkle root is read from bytes pinned to that block. A multi-calendar proof anchors in several blocks; the sidecar's `btc_block_height` must be one of them. The chain header-to-id-to-attestation is confirmed; Bitcoin's proof-of-work is not re-verified, so the check pairs with the explorer's best-chain view rather than standing in for a full node. `--btc-api` names any Esplora-compatible API (default `https://blockstream.info/api`).

`--ots-external <bin>` additionally runs `<bin> verify -d <root_hash> <proof.ots>` (the official Python client as `ots`; a `.cmd`/`.bat` wrapper works on Windows). A missing binary or a broken environment (the Python client needs a loadable OpenSSL, which it does not always find on Windows) fails the run, since the cross-check was asked for explicitly.

## Machine-readable output

`--json` is the shape an automated caller consumes (the operator's scheduled run, a fork's own): the human lines go to stderr as flat `PASS  msg` text and stdout carries the one JSON object, also on a crash (`{ result: "fail", error, checks }`).

## Known-answer tests

`pnpm selftest` replays these vectors, which the backend pins byte for byte on its side:

- revoke leaf `{ seq: 42, ts: 1700000000000, op: 4, revoke_seq: 7, reason_code: "erasure_admin", evidence_hash: 0x00..0x1f }`:
  canonical bytes `000000000000002a0000018bcfe5680004000000066769746875620000000667683a6f2f72ffffffffffffffffffffffff00000000000000070000000d657261737572655f61646d696e00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, `leaf_hash` `e927976c582f793b28d02a7371d5492164c67a2c88f863063e2cd9d850812837`. The vector's base carries `site=github` and `target_id=gh:o/r` with the other three strings NULL.
- the identity vectors in `src/identity.selftest.mjs`: nullifier, salt commitment, `user_ref = SHA256(pubkey)`, the signed-vote, ENROLL, ISSUE and KEY leaf hashes, and the three signed-message byte strings.

## Self-tests

Offline, synthetic fixtures, no network, `@aztec/bb.js` never loaded:

- `src/revoke.selftest.mjs`: the revoke KAT, the counter fold with revocations (idempotent re-revoke, forward revoke as a no-op, re-credit of a revoked switch), invariants D and E, invariant F (complete wipe, partial wipe after and within grace, un-wiped pseudonyms unchecked, the grace clock, a revoke after the checkpoint, no double report with D).
- `src/ots.selftest.mjs`: the dependency-free OpenTimestamps parser and Bitcoin verifier, and the external-client driver.
- `src/archive.selftest.mjs`: prefix roots from one pass equal direct recomputation, a tampered leaf changes the prefix root, the hash chain replays and breaks on a rewritten link, a reorder and a missing `entry_hash`, the checkpoint an offline run picks when the shards trail the tip, and the per-day aggregates derivable from the entries.
- `src/revocations.selftest.mjs`: the HTTP layer against a stubbed `fetch`: the revocation feed shortcut and range walk, the clamp to the audited tree, the entries-source cross-check, retry on 429 and its bound, the shard tail fill and the empty-shard and broken-mirror cases, the empty-log answer, and the Git Trees fallback past the 1000-file listing cap.
- `src/identity.selftest.mjs`: the identity KATs, invariant A over the identity leaves, invariants G, H and I (including the `--keys-per-account` cap and the ENROLL-to-ISSUE account-key chain), Ed25519 vote and account-key signatures and the blind RSA-PSS check on freshly generated keys, the `noir-jwt` public-input layout, and the proof driver's skip and failure paths against stubbed fetchers.
