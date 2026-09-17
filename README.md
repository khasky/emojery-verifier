# Emojery Verifier

A standalone, open-source tool that re-derives the Emojery counters from the **public** log and checks them against the signed, externally-anchored checkpoint — so the totals are provable, not just promised. It talks only to the public API and the public log; it has no privileged access.

This verifier is paired with the public data repository [`emojery-log`](https://github.com/khasky/emojery-log). That repository holds the signed checkpoints and OpenTimestamps proofs; this repository holds the code that checks them.

## Install

```
pnpm install
```

## Run

Fast check, without cloning:

```
npx github:khasky/emojery-verifier --api https://api.emojery.app \
  --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

or from a checkout:

```
node src/verify.mjs --api https://api.emojery.app \
  --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

Fully offline audit — no request ever reaches the operator's API; the checkpoint comes from the log repo's `checkpoints/latest.json` and the raw leaves from its public `entries/` shards:

```
node src/verify.mjs --entries repo \
  --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

The shards are published in batches, so the newest few hundred leaves of a live log are not mirrored yet. An offline run therefore audits the newest **published checkpoint the shards fully cover** rather than the tip — it says which one, and the tip's own Rekor sidecar is still cross-checked. Adding `--api` audits the tip instead: the shards carry the bulk and only the missing tail is fetched.

```
node src/verify.mjs --entries repo --api https://api.emojery.app \
  --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

Example result:

```bash
checkpoint: tree_size=389 ts=1788854468525
── Checkpoint ────────────────────────────────────────────────────────── 3 ✓
   ✓  checkpoint Ed25519 signature
   ✓  checkpoint is fresh (1.9h old, threshold 168h — a quiet log ages legitimately; tune --max-checkpoint-age-hours)
   ✓  GitHub anchor matches signed root (tree_size=389)

── Leaves & Merkle ───────────────────────────────────────────────────── 4 ✓
   reading entries shards  ████████████████ 389/389  0.0s
   recomputing leaf hashes ████████████████ 389/389  0.0s
   ✓  every recomputed leaf_hash matches the served leaf (0 mismatch)
   ✓  fetched all 389 leaves (got 389, source: repo)
   ✓  recomputed Merkle root == checkpoint root_hash
   ✓  hash chain replays from genesis (389 leaves, 0 break(s))

── Checkpoint archive ────────────────────────────────────────────────── 7 ✓
   ✓  checkpoint archive parses (22 STH line(s) in 5 shard(s))
   ✓  no two archived STHs disagree on one tree_size (0 conflict(s))
   verifying archived STHs ████████████████ 22/22  0.1s
   ✓  every archived STH signature verifies (22 checked, 0 bad)
   ✓  archived STH timestamps are monotone in tree_size (0 regression(s))
   ✓  archive never exceeds the live tree (max archived 389 <= 389)
   ✓  the live checkpoint is present in the archive shards
   ✓  every archived root replays from today's leaves (22 checkpoint(s), 0 mismatch)

── Independent witness ───────────────────────────────────────────────── 4 ✓
   ✓  rekor sidecar 389 matches the archived checkpoint
   ✓  Rekor entry 108e9186e8c5... holds the STH bytes of checkpoint 389
   ✓  Rekor entry carries our Ed25519 checkpoint signature
   ✓  Rekor entry public key is the published log key

── Entries cross-check ───────────────────────────────────────────────── 1 ✓
   ✓  /log/entries agrees with the repo shards over the first 389 leaves (served 389)
folded 268 (site,target,reaction) counters from 389 events

── Log semantics ─────────────────────────────────────────────────────── 3 ✓
revocations: 80 tombstone(s)
   revoke seq=132 -> revoke_seq=2 reason=erasure_self target=x/2095162197433348142
   revoke seq=133 -> revoke_seq=3 reason=erasure_self target=x/2095156958189724041
   revoke seq=134 -> revoke_seq=4 reason=erasure_self target=x/2094793461228818555
   revoke seq=135 -> revoke_seq=5 reason=erasure_self target=x/2056672338423206234
   revoke seq=136 -> revoke_seq=6 reason=erasure_self target=x/2073520150452506786
   ...and 75 more
   ✓  /log/revocations matches op=4 leaves in the log (80)
   ✓  structural invariants hold (0 violation(s))
   ✓  account wipes are complete (0 violation(s); grace 48h)

┌─ VERIFIED ───────────────────────────────────────────────────────────────┐
│  RESULT     PASS   22 passed                                             │
│  tree size  389   root 83a4552e3d...4a6491                                 │
│  log key    XeLiQ5CMhs... (pinned in verify.mjs)                           │
│  witnesses  GitHub anchor · Rekor 108e9186e8c5...                          │
│  sources    api.emojery.app · khasky/emojery-log@main · entry shards     │
│  elapsed    1.9s                                                         │
└──────────────────────────────────────────────────────────────────────────┘
  reproduce: node src/verify.mjs --api https://api.emojery.app --repo https://raw.githubusercontent.com/khasky/emojery-log/main --entries repo
```

An offline run whose shards trail the tip says so and steps back:

```bash
checkpoint: tree_size=1433 ts=1787716853962 (from repo latest.json — offline audit)
   entries/ shards cover 1349 of 1433 leaves — the newest tail is not mirrored yet, and an offline audit cannot fill it
   auditing published checkpoint tree_size=1349 instead — the newest the shards fully cover (live tip 1433)
```

The published signing key is pinned in `src/verify.mjs`, so `--pubkey` is optional for the main deployment. The current pinned key is:

```text
XeLiQ5CMhsjLmnQbIWSwWHNjcJg01Zs0veQDiwluT6c=
```

Pass `--pubkey` only to verify a different deployment or fork.

Every flag is listed below, and anything else is rejected with exit code `2` — a mistyped flag can no longer run a smaller audit in silence and still print PASS.

- `--api` (required unless running the fully offline audit): the public API base URL — serves `/log/*`.
- `--repo` (optional): GitHub raw base of the public log; cross-checks the signed root against the published anchor and replays the full checkpoint archive.
- `--entries api|repo` (optional, default `api`): where to read the raw leaves. `repo` reads the public `entries/<start>-<end>.ndjson` shards from `--repo`; combined with omitting `--api` that is a **fully offline audit** of a clone/mirror — the operator's API is never contacted (the `/log/revocations` endpoint comparison and the split-view anchor comparison are skipped; everything else, including the Rekor cross-check, still runs). `repo` is also the mode to use on a large log: 10000 leaves per shard file against 1000 per API page, and the shards are not charged against the API's per-IP `/log/*` rate limit. The shards are published in batches, so they trail the live checkpoint by a few hundred leaves; with `--api` the missing tail is fetched in one page, and a fully offline run audits the newest published checkpoint the shards do cover, naming it and the tip it stepped back from. A mirror that carries no complete checkpoint at all reports the Merkle check as a skip — the shards are incomplete, which is not evidence against the log.
- `--shard-size N` (optional, default 10000): the fixed entries-shard size (matches the published layout; only needed if a deployment ever changes it).
- `--pubkey` (optional): the published Ed25519 public key (base64 raw). Defaults to the key pinned in `src/verify.mjs`.
- `--wipe-grace-hours N` (optional, default 48): grace window for the account-wipe completeness check — a pseudonym whose newest revocation is younger than this (relative to the checkpoint) counts as a wipe still in flight. A policy knob, not a proof parameter; auditors of a quiescent log may tighten it to `0`.
- `--max-checkpoint-age-hours N` (optional, default 168, `0` disables): flag a checkpoint older than this — a frozen snapshot passing every other check is still a stale view. A quiet log ages legitimately (checkpoints only advance on new votes), hence the generous default.
- `--stats` (optional): print a per-day CSV (reactions, distinct pseudonymous authors, revocations) derived from the entries alone.
- `--counters` (optional): print the re-derived totals themselves as CSV (`site,target_id,reaction,count`, ascending, zero-valued keys omitted) — the numbers an auditor publishes instead of quoting the operator's. They come from the fold of leaves this run already checked against the signed root; nothing is read from the live counter surface.
- `--no-rekor` (optional): skip the Rekor cross-check. It runs **by default** whenever `--repo` is set — the newest `rekor/<tree_size>.json` sidecar is cross-checked against the actual Sigstore Rekor entry, an independently operated public log that must hold exactly our signed checkpoint bytes. An unreachable Rekor (outage / Rekor-side migration) downgrades to a skip, not a fail; only a sidecar that disagrees with the archived checkpoint, or a resolved Rekor entry whose bytes don't match our STH, fails. (`--rekor` is still accepted as an explicit no-op.)
- `--ots` (optional): also run the OpenTimestamps→Bitcoin deep audit (below). Needs `--repo`; slower and only passes after an OTS proof has matured.
- `--btc-api <url>` (optional, with `--ots`): override the Esplora-compatible Bitcoin block-header source (default: `https://blockstream.info/api`).
- `--ots-external <bin>` (optional, with `--ots`): also cross-check the same proof with an external OpenTimestamps CLI such as `ots`. A `.cmd`/`.bat` wrapper works on Windows too. The external tool is trusted to run: if the binary is missing or its own environment is broken (the official Python client needs a loadable OpenSSL, which it does not always find on Windows), the run FAILS — you asked for that cross-check explicitly, so it is not downgraded to a skip.
- `--allow-unsigned-votes` (optional): admit vote leaves that carry no client signature. Votes cast by extension 1.0.0 are unsigned; while that version is still served the operator's own scheduled run passes this flag, and once the OpenID cutover retires it an unsigned vote is a failure again. Without the flag, any unsigned vote fails the `identity_structure` check.
- `--no-proofs` (optional): skip the ENROLL proof check (`enroll_proofs`), the one check that loads `@aztec/bb.js`. Everything else in the identity section still runs. Use it for a lighter audit, or on a machine where the wasm prover will not load.
- `--blind-pubkey <spki b64>`, `--enroll-vk-hash <hex>`, `--salt-commitment <hex>`, `--audiences <id,...>`, `--issuers <provider=iss,...>` (optional): override the identity pins in `src/verify.mjs` (see [Identity track](#identity-track-openid-enrollment-epoch-keys-signed-votes)) to verify a different deployment or fork. An `--issuers` entry whose `iss` starts with `^` is a regular expression (Microsoft's issuer carries the tenant id).
- `--keys-per-account N` (optional, default 10): how many ISSUE leaves one enrolled account may hold per epoch (a second device, a reinstall). The `identity_structure` check fails on the first ISSUE past it. Every ISSUE is signed by the account's own key, so this bounds devices per account rather than what the operator can mint.
- `--json` (optional): print one machine-readable summary (`{ result, tree_size, ts, checks, duration_sec }`) on stdout instead of the human report — used by the status job below. Human/info lines then go to stderr; the exit code is unchanged.
- `--no-color` (optional): drop the colour. It is already off when stdout is not a terminal, when `NO_COLOR` is set, and under `--json`; `FORCE_COLOR=1` forces it back on through a pipe.
- `--ascii` (optional): draw the report with ASCII characters only, for a console on a legacy code page where the box-drawing glyphs would be mojibake. Chosen automatically on Windows unless the environment names a UTF-8 terminal (`WT_SESSION`, `TERM`, `ConEmuANSI`).

## What it checks

1. The checkpoint's Ed25519 signature against the pinned public key.
2. The checkpoint is fresh (`--max-checkpoint-age-hours`) — a frozen-but-consistent snapshot is flagged, not silently accepted.
3. (with `--repo` **and** `--api`) the signed root matches the public GitHub anchor — catches a "split view" where the API shows you one history and everyone else another. A fully offline run reads its checkpoint from that anchor, so there is no second source to compare it with and the check is skipped rather than compared against itself.
4. Every log entry is refetched and the Merkle root is recomputed from scratch; it must equal the checkpoint's `root_hash`.
5. The published hash chain replays from genesis: `entry_hash(seq) == SHA256(0x00 || entry_hash(seq-1) || leaf_hash(seq))`, with the leaf hashes this run recomputed rather than the ones served. The Merkle root pins *which* leaves the tree holds; the chain pins their *order*, and every `/log/entries` row publishes its `entry_hash`.
6. (with `--repo`) the **checkpoint archive replays**: every checkpoint ever published to `checkpoints/*.ndjson` has a valid signature, no two published checkpoints disagree on one `tree_size`, timestamps are monotone, and every archived root equals the root recomputed from today's leaves at that `tree_size` — so the entire published history lies on ONE append-only line, and even an internally-consistent rewrite of the log fails.
7. The per-target counters are re-derived from the log (accounting for changes and removals), so the totals can be stated from the public log alone instead of taken on the operator's word. `--counters` prints them.
8. The published revocation list matches the revocations actually present in the log.
9. The log is internally consistent — every entry is well-formed and no count is ever driven impossibly negative.
10. Account wipes are complete — revocations are whole-account, so once any entry of a pseudonym is revoked, every entry of that pseudonym must be revoked. A partially revoked pseudonym is flagged, after a 48-hour grace window for wipes still in flight (`--wipe-grace-hours`).
11. The identity track (below): every signed vote verifies under an epoch key the log registered earlier, every registered key carries the operator's blind signature and no epoch registers more keys than it issued, every key grant cites an enrollment and is signed by that enrollment's own account key, and every enrollment carries a zero-knowledge proof over an OpenID provider's signed token that commits to that account key.
12. (by default, with `--repo`; `--no-rekor` to skip) the newest Rekor sidecar resolves to a real Sigstore Rekor entry carrying exactly our signed checkpoint bytes, signature, and public key. An unreachable Rekor is a skip, not a fail.
13. (with `--ots`) the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

Exit code `0` = PASS, `1` = FAIL. A failure means the published numbers don't match the log, or the log doesn't match its signed, anchored checkpoint — exactly what this is built to catch. Checks 1-10 establish the **integrity** of the record; the identity track adds the bound on **who could have written it**: every counted vote traces to an epoch key whose grant was signed by the enrolled account's own key, and that account's enrollment is proven against a real OpenID provider account. No epoch key can be granted without a signature from the enrolled account's own key, so the operator can inflate a count only with real provider accounts, each visible as an ENROLL in the log.

### Identity track: OpenID enrollment, epoch keys, signed votes

Since the OpenID sign-in, the log carries three more leaf kinds and a signed tail on votes:

- `op=5` — **ENROLL**: one per account key. Carries the account's `nullifier` (a hash of the provider's subject under a secret salt, so the provider account is not published), the provider `iss`, the OAuth client id `aud`, the provider key id `kid`, a zero-knowledge `proof`, the `salt_commitment` (SHA-256 of that salt), and the `account_pubkey` — an Ed25519 key the extension generated and kept; the proof binds it to the provider's token. A reinstall makes a new account key and so a new ENROLL under the same nullifier.
- `op=6` — **ISSUE**: one blind-signed epoch-key grant for one `epoch`, authorised by the enrolled account: it names the `nullifier` and `account_pubkey` of an earlier ENROLL, the `blinded_hash` (SHA-256 of the blinded message the grant was signed over), and the `account_sig` the account key put on that grant. At most `--keys-per-account` (default 10) per account and epoch.
- `op=7` — **KEY**: one registered Ed25519 epoch public key, with the unblinded RSA-PSS signature (`key_sig`) the operator issued for it. Because the signature was blinded, the log shows *that* a key was issued, never *to whom*.
- votes (`op=1..3`) now end in `client_pubkey || client_sig || client_nonce`, and their pseudonym is `user_ref = SHA256(client_pubkey)`. A 1.0.0 vote has none of the three and hashes as before.

The five checks, and their `--json` keys:

| Check | Key | What must hold |
| --- | --- | --- |
| structure | `identity_structure` | a signed vote names a pubkey an **earlier** KEY leaf registered, `user_ref == SHA256(pubkey)`, no nonce repeats under one key; per epoch `count(KEY) <= count(ISSUE)` and no pubkey registers twice; every ISSUE cites an earlier ENROLL with the same `(nullifier, account_pubkey)` pair, its `blinded_hash` is unique across ISSUE leaves, and no `(nullifier, epoch)` holds more than `--keys-per-account` of them; an ENROLL `(nullifier, account_pubkey)` pair is unique. Unsigned votes fail here unless `--allow-unsigned-votes`. |
| vote signatures | `vote_signatures` | every `client_sig` is a valid Ed25519 signature under `client_pubkey` over `"emojery-vote-v1" \|\| lp(site) \|\| lp(target_id) \|\| lp(reaction) \|\| lp(nonce)`. Skip while the log holds no signed vote. |
| issue signatures | `issue_signatures` | every `account_sig` is a valid Ed25519 signature under the leaf's `account_pubkey` over `"emojery-issue-v1" \|\| u64be(epoch) \|\| blinded_hash`. Skip while there is no ISSUE leaf. |
| key signatures | `key_signatures` | every `key_sig` is a valid RSA-PSS (SHA-384, salt 48; RFC 9474 RSABSSA) signature under the pinned blind public key over `"emojery-epoch-key-v1" \|\| u64be(epoch) \|\| pubkey`. Skip while there is no KEY leaf, or no pinned blind key. |
| enrollment proofs | `enroll_proofs` | every ENROLL `proof` verifies (UltraHonk, via `@aztec/bb.js`) under the pinned verification key `keys/enroll-v1.vk` from the log repo, with public inputs the verifier **rebuilds itself**: the provider's RSA modulus from the archived `jwks/<provider>/<kid>.json` (18 limbs of 120 bits plus its Barrett parameter, as `noir-jwt` lays them out), the leaf's `iss` and `aud` as fixed-width byte vectors, the `nullifier`, the pinned `salt_commitment`, and the leaf's `account_pubkey` as the last 32 fields. The `iss` must be an admitted issuer and the `aud` a pinned client id. The archived provider key is cross-checked against the provider's live JWKS: unreachable is a note, a key the provider has since rotated out is a note, a **different** modulus is a failure. If `keys/enroll-v1.json` declares a `public_inputs` layout, it must end with `account_pubkey[32]`. `--no-proofs` skips this check. |

What a passing proof establishes: the operator held an RS256 `id_token` signed by that provider's published key, naming that `iss` and `aud` and *some* subject, whose `nonce` commits to the leaf's `account_pubkey`, and the leaf's nullifier is the hash of that subject under the committed salt. It does not reveal the subject, and the verifier never sees the token. The proof is checked against a pinned verification key, so a different circuit cannot be substituted; the salt commitment is pinned, so nullifiers from two salts cannot be mixed; and because the account key is inside the signed token's nonce, it was chosen by whoever held the provider session, before the provider signed. An ISSUE then needs that key's signature, so the operator cannot grant an epoch key to an account it did not sign in as.

The leaf bytes, in the order they are hashed. `lp(s)` is `u32be(len) || utf8(s)`, `lpb(b)` is `u32be(len) || b`, and a NULL string or byte field is `u32be(0xffffffff)`. `base` is the eight fields every leaf starts with: `u64be(seq) || u64be(ts) || u8(op) || lp(site) || lp(target_id) || lp(reaction) || lp(prev_reaction) || lp(user_ref)`, all five strings NULL on `op=4..7`.

| Leaf | Bytes after `base` |
| --- | --- |
| `op=1..3`, signed | `lpb(client_pubkey32) \|\| lpb(client_sig64) \|\| lp(client_nonce)` (a 1.0.0 vote appends nothing) |
| `op=4` | `u64be(revoke_seq) \|\| lp(reason_code) \|\| lpb(evidence_hash)` |
| `op=5` ENROLL | `lp(nullifier) \|\| lp(iss) \|\| lp(aud) \|\| lp(kid) \|\| lpb(proof) \|\| lpb(salt_commitment32) \|\| lpb(account_pubkey32)` |
| `op=6` ISSUE | `lp(nullifier) \|\| u64be(epoch) \|\| lpb(account_pubkey32) \|\| lpb(blinded_hash32) \|\| lpb(account_sig64)` |
| `op=7` KEY | `u64be(epoch) \|\| lpb(client_pubkey32) \|\| lpb(key_sig256)` |

`nullifier` is hashed as its 64-character hex string (`lp`), the byte fields as raw bytes (`lpb`). On the wire (`/log/entries` and the shards) `account_pubkey`, `account_sig` and `blinded_hash` are hex or `null`; a row that lacks the key hashes it as NULL. The signed messages, all with a raw UTF-8 prefix (no length): votes sign `"emojery-vote-v1" || lp(site) || lp(target_id) || lp(reaction) || lp(nonce)`, the account key signs `"emojery-issue-v1" || u64be(epoch) || blinded_hash32`, and the blind signer signs `"emojery-epoch-key-v1" || u64be(epoch) || pubkey32`.

**Pins.** Four values are pinned in `src/verify.mjs` next to the log key — `PINNED_BLIND_PUBKEY_SPKI_B64`, `PINNED_ENROLL_VK_SHA256`, `PINNED_SALT_COMMITMENT`, `PINNED_AUDIENCES` — plus the issuer list `PINNED_ISSUERS`. Until the operator publishes the OpenID material they are empty, and each check that needs one reports a **skip naming the pin** rather than a pass; the flags above override them for another deployment. `PINNED_ENROLL_VK_SHA256` is the exception: it is set, and were it ever left at the placeholder `REPLACE_WITH_ENROLL_V2_VK_SHA256`, a log that carries ENROLL leaves would **fail** the proof check unless `--enroll-vk-hash` supplied the real digest, so a run can never pass on a pin nobody set. The blind key is also published as `keys/blind-rsa-v1.json` in the log repo and the verification-key metadata (`bb` version, salt commitment, public-input layout) as `keys/enroll-v1.json`.

**Dependency.** The proof check is the one place this tool needs more than `@noble/ed25519`: `@aztec/bb.js` is pinned to an exact version (the same `bb` the operator proves with, recorded in `keys/enroll-v1.json`; a drift is reported next to the check). It is imported lazily, so a run with `--no-proofs`, or a log with no ENROLL leaf yet, never loads it. On first use it downloads the BN254 structured reference string into `~/.bb-crs` (a few MB, from the Aztec CDN) and takes about ten seconds to initialise the wasm prover; `pnpm install --ignore-scripts` is enough (its native optional, `msgpackr-extract`, has a pure-JS fallback).

### Revocations and account deletion

The log records counter-changing events, not just final state:

- `op=1` — a reaction was added.
- `op=2` — a reaction was changed; the leaf records both the new reaction and the previous one.
- `op=3` — a reaction was removed by the user.
- `op=4` — a revocation tombstone: a later public leaf that reverses an earlier `op=1`, `op=2`, or `op=3` leaf.

So a normal user "unreact" is `op=3`, not a tombstone. Tombstones are for append-only corrections. If an account is erased, or if a counted reaction has to be reversed, Emojery does not edit or delete the original log leaf. It appends an `op=4` revocation leaf instead:

- `revoke_seq` points at the original `op=1/2/3` leaf being reversed.
- `reason_code` is a public machine-readable reason, such as `erasure_self`, `erasure_admin`, or an abuse-correction label.
- `evidence_hash` may pin a published evidence report; it is `null` for routine account erasure.

The verifier resolves each `revoke_seq` to the original leaf, applies the inverse effect while folding counters, checks that revokes are not dangling, forward, self-referential, or duplicated, and confirms that `GET /log/revocations` matches the `op=4` leaves actually present in the anchored log.

#### Reading the revocation feed yourself

The revoke track has three read paths, and **every one of them answers `has_more`** — a page that had to stop short says so, so a partial answer can never be mistaken for the whole list:

| Request | Returns | `has_more` means | `next_from` |
| --- | --- | --- | --- |
| `GET /log/revocations/range?from=&to=` | the `op=4` leaves in that `seq` range, capped at 1000 `seq` values | always `false` — the range itself bounds the answer | `null` |
| `GET /log/revocations/target?target=site/id[&from=]` | one target's tombstones, 1000 per page, keyset-paginated by `seq` | more pages exist for this target | pass it back as `&from=` |
| `GET /log/revocations` | the 1000 newest tombstones | older tombstones exist | `null` — use the range path to walk back |

`revocations` is always ascending by `seq`.

The two parameterised forms used to be query variants of `/log/revocations`, which could not state which parameters each one required. They are their own paths now, and the bare feed refuses those parameters with a `400` naming the path that answers them (`{"error": "bad_range", "use": "/log/revocations/range"}`) rather than silently serving the newest-first feed — an auditor still spelling the old form gets a failure it can read, not a verdict on a list it never asked for.

This verifier reads the range path and pages it itself, so it always sees the whole track. If you write your own auditor, page it the same way: the bare feed is a browsable "what happened lately" view, not the full history, and stopping at its first response undercounts a log with more than 1000 tombstones.

Revocations are whole-account. There is no per-vote reversal: erasing or deactivating an account revokes every entry that account wrote. The verifier enforces this as its account-wipe completeness check — if any entry of a pseudonym is cited by a revocation, all of that pseudonym's entries must be, so a single inconvenient vote cannot be quietly reversed under an account-operation label. Pseudonyms rotate per epoch, so completeness is checked per pseudonym; linking pseudonyms across epochs is impossible by design, as a privacy property of the log.

### `--ots`: OpenTimestamps → Bitcoin deep audit

This walks the matured `.ots` proof to a Bitcoin block and confirms the signed checkpoint root was committed there — proof the history couldn't be backdated. It is **opt-in** because it is network-bound (it queries a Bitcoin block explorer) and a checkpoint's Bitcoin attestation only matures hours after the checkpoint is signed.

With `--ots` the verifier reads `ots/latest.json`, `ots/<tree_size>.json`, and `ots/<tree_size>.ots` from `--repo`, re-checks the checkpoint signature, parses the OpenTimestamps proof locally, and checks that the proof's Bitcoin commitment equals the merkle root in the attested block header. Each block header is required to double-`SHA256` to the block id the explorer returned for its height, so the merkle root is read from bytes pinned to that block, not from whatever the explorer served. The built-in path has no `opentimestamps` npm dependency. It confirms the header-to-id-to-attestation chain; it does not itself re-verify Bitcoin's proof-of-work, so it pairs that with the explorer's best-chain flag rather than standing in for a full node.

By default `--btc-api` is `https://blockstream.info/api`; any Esplora-compatible API can be used instead. For an independent cross-check, install the official Python OpenTimestamps client and pass `--ots-external ots`; the verifier will also run `ots verify -d <root_hash> <proof.ots>` against the same proof.

### Status reporting (`--json` + scheduled report)

The verifier doubles as the **independent** check behind the public status page at `emojery.app/status`. The workflow `.github/workflows/verify-and-report.yml` runs daily (and on demand), executes `node src/verify.mjs --json ...` against the public API + log, and POSTs the verdict to the API's `POST /status/ingest` endpoint; the status page renders it as the "Independent verification" component.

The job is a matrix over the deployments it watches, and each one signs its own log, so the key and the ingest secret live **per GitHub environment**, not on the repository:

- Settings → Environments → `production` (and `staging`) → **variable** `LOG_PUBKEY`, that deployment's published key.
- The same environments → **secret** `STATUS_INGEST_KEY`, matching that deployment's API secret. Reporting is skipped where it is absent.

A repository-level value does not resolve here — the workflow reads `vars.LOG_PUBKEY` inside an `environment:`, so a repo variable arrives empty and the run stops with `--pubkey needs a value` rather than quietly falling back to the pinned production key.

The identity pins ride the same way, as optional environment **variables** — `BLIND_PUBKEY_SPKI`, `ENROLL_VK_SHA256`, `SALT_COMMITMENT`, `OIDC_AUDIENCES`, `OIDC_ISSUERS` — passed as flags only when set (staging signs and proves under its own material, and adds its test issuer to `OIDC_ISSUERS`). Both targets currently run with `--allow-unsigned-votes`, the compatibility window for extension 1.0.0; the flag comes off at the cutover.

The job runs without `--ots` — OpenTimestamps matures over days, and the status page tracks the Bitcoin anchor separately — so a young log isn't reported as failing.

### Fork and audit

You don't need the ingest secret to become an independent watcher: **fork this repository, enable Actions on the fork, and set the `LOG_PUBKEY` environment variable** as above — your fork then runs the full verification daily on infrastructure the operator doesn't control, and the run history on your fork is your own public audit trail (the report step skips without `STATUS_INGEST_KEY`). A failed verification fails the job, so a red run in that history means the log did not verify — the trail is only worth keeping if it can go red. Watch one deployment instead of both by trimming the matrix in the workflow. The more independent forks watching, the less anyone has to take the operator's word for anything.

## Self-test

```
pnpm selftest
```

Runs `src/revoke.selftest.mjs`, `src/ots.selftest.mjs`, `src/archive.selftest.mjs`, `src/revocations.selftest.mjs`, and `src/identity.selftest.mjs` — offline checks of the revocation/`op=4` counter-folding logic, the dependency-clean OTS verifier, the checkpoint-archive replay primitive, the hash-chain replay, the checkpoint an offline run picks when the entries shards trail the tip, the per-day aggregates derived from the entries, the HTTP layer (revocation paging, shard-tail fill, rate-limit retry) against a stubbed `fetch`, and the identity track (the pinned `op=5/6/7` and signed-vote byte vectors shared with the backend, invariants G/H/I including the `--keys-per-account` cap and the ENROLL-to-ISSUE account-key chain, the Ed25519 vote and account-key signatures and the blind RSA-PSS check on freshly generated keys, the `noir-jwt` public-input layout, and the proof driver's skip and failure paths against stubbed fetchers). No network, synthetic fixtures throughout; `@aztec/bb.js` is not loaded. Exit `0` = PASS.

Example result:

```bash
KAT canonical = 000000000000002a0000018bcfe5680004000000066769746875620000000667683a6f2f72ffffffffffffffffffffffff00000000000000070000000d657261737572655f61646d696e00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
KAT leaf_hash = e927976c582f793b28d02a7371d5492164c67a2c88f863063e2cd9d850812837
PASS  fold: lone add => 1
PASS  fold: add+revoke => 0
PASS  fold: add+revoke+re-revoke => 0 (idempotent)
PASS  fold: forward revoke is a no-op
PASS  fold: revoke of switch re-credits prev
PASS  invariants: valid revoke passes ()
PASS  invariants D: dangling revoke_seq flagged
PASS  invariants D: self-revoke flagged
PASS  invariants D: forward revoke flagged
PASS  invariants E: double-revoke flagged
PASS  invariant F: complete wipe passes
PASS  invariant F: partial wipe flagged after grace
PASS  invariant F: partial wipe within grace passes
PASS  invariant F: un-wiped pseudonyms are not checked
PASS  invariant F: a resumed wipe's newest revoke restarts the grace clock
PASS  invariant F: revoke timestamped after the checkpoint is flagged
PASS  invariant F: dangling revoke left to invariant D (no double-report)

RESULT: PASS
```

## License

[GPL-3.0-or-later](LICENSE).
