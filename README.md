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

…or from a checkout:

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
checkpoint: tree_size=1433 ts=1787716853962
PASS  checkpoint Ed25519 signature
PASS  checkpoint is fresh (0.3h old, threshold 168h — a quiet log ages legitimately; tune --max-checkpoint-age-hours)
PASS  GitHub anchor matches signed root (tree_size=1433)
PASS  every recomputed leaf_hash matches the served leaf (0 mismatch)
PASS  fetched all 1433 leaves (got 1433, source: api)
PASS  recomputed Merkle root == checkpoint root_hash
PASS  hash chain replays from genesis (1433 leaves, 0 break(s))
PASS  checkpoint archive parses (66 STH line(s) in 19 shard(s))
PASS  no two archived STHs disagree on one tree_size (0 conflict(s))
PASS  every archived STH signature verifies (66 checked, 0 bad)
PASS  archived STH timestamps are monotone in tree_size (0 regression(s))
PASS  archive never exceeds the live tree (max archived 1433 <= 1433)
PASS  the live checkpoint is present in the archive shards
PASS  every archived root replays from today's leaves (66 checkpoint(s), 0 mismatch)
PASS  rekor sidecar 1433 matches the archived checkpoint
PASS  Rekor entry 108e9186e8c5… holds the STH bytes of checkpoint 1433
PASS  Rekor entry carries our Ed25519 checkpoint signature
PASS  Rekor entry public key is the published log key
folded 1126 (site,target,reaction) counters from 1433 events
revocations: 182 tombstone(s)
   revoke seq=463 -> revoke_seq=459 reason=erasure_self target=github/example/repo
   revoke seq=464 -> revoke_seq=456 reason=erasure_self target=threads/Db0eMtEHAc6
   …
PASS  /log/revocations matches op=4 leaves in the log (182)
PASS  structural invariants hold (0 violation(s))
PASS  account wipes are complete (0 violation(s); grace 48h)

RESULT: PASS
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
- `--json` (optional): print one machine-readable summary (`{ result, tree_size, ts, checks, duration_sec }`) on stdout instead of the human report — used by the status job below. Human/info lines then go to stderr; the exit code is unchanged.

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
11. (by default, with `--repo`; `--no-rekor` to skip) the newest Rekor sidecar resolves to a real Sigstore Rekor entry carrying exactly our signed checkpoint bytes, signature, and public key. An unreachable Rekor is a skip, not a fail.
12. (with `--ots`) the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

Exit code `0` = PASS, `1` = FAIL. A failure means the published numbers don't match the log, or the log doesn't match its signed, anchored checkpoint — exactly what this is built to catch. It checks the **integrity** of the record; it does not, by itself, prove each reaction comes from a unique person — that is a separate concern.

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

`GET /log/revocations` has three forms, and **every one of them answers `has_more`** — a page that had to stop short says so, so a partial answer can never be mistaken for the whole list:

| Request | Returns | `has_more` means | `next_from` |
| --- | --- | --- | --- |
| `?from=&to=` | the `op=4` leaves in that `seq` range, capped at 1000 `seq` values | always `false` — the range itself bounds the answer | `null` |
| `?target=site/id[&from=]` | one target's tombstones, 1000 per page, keyset-paginated by `seq` | more pages exist for this target | pass it back as `&from=` |
| no parameters | the 1000 newest tombstones | older tombstones exist | `null` — use the range form to walk back |

`revocations` is always ascending by `seq`.

This verifier reads the range form and pages it itself, so it always sees the whole track. If you write your own auditor, page it the same way: the bare form is a browsable "what happened lately" view, not the full history, and stopping at its first response undercounts a log with more than 1000 tombstones.

Revocations are whole-account. There is no per-vote reversal: erasing or deactivating an account revokes every entry that account wrote. The verifier enforces this as its account-wipe completeness check — if any entry of a pseudonym is cited by a revocation, all of that pseudonym's entries must be, so a single inconvenient vote cannot be quietly reversed under an account-operation label. Pseudonyms rotate per epoch, so completeness is checked per pseudonym; linking pseudonyms across epochs is impossible by design, as a privacy property of the log.

### `--ots`: OpenTimestamps → Bitcoin deep audit

This walks the matured `.ots` proof to a Bitcoin block and confirms the signed checkpoint root was committed there — proof the history couldn't be backdated. It is **opt-in** because it is network-bound (it queries a Bitcoin block explorer) and a checkpoint's Bitcoin attestation only matures hours after the checkpoint is signed.

With `--ots` the verifier reads `ots/latest.json`, `ots/<tree_size>.json`, and `ots/<tree_size>.ots` from `--repo`, re-checks the checkpoint signature, parses the OpenTimestamps proof locally, and checks that the proof's Bitcoin commitment equals the merkle root in the attested block header. Each block header is required to double-`SHA256` to the block id the explorer returned for its height, so the merkle root is read from bytes pinned to that block, not from whatever the explorer served. The built-in path has no `opentimestamps` npm dependency. It confirms the header-to-id-to-attestation chain; it does not itself re-verify Bitcoin's proof-of-work, so it pairs that with the explorer's best-chain flag rather than standing in for a full node.

By default `--btc-api` is `https://blockstream.info/api`; any Esplora-compatible API can be used instead. For an independent cross-check, install the official Python OpenTimestamps client and pass `--ots-external ots`; the verifier will also run `ots verify -d <root_hash> <proof.ots>` against the same proof.

### Status reporting (`--json` + scheduled report)

The verifier doubles as the **independent** check behind the public status page at `emojery.app/status`. The workflow `.github/workflows/verify-and-report.yml` runs daily (and on demand), executes `node src/verify.mjs --json …` against the public API + log, and POSTs the verdict to the API's `POST /status/ingest` endpoint; the status page renders it as the "Independent verification" component.

The job is a matrix over the deployments it watches, and each one signs its own log, so the key and the ingest secret live **per GitHub environment**, not on the repository:

- Settings → Environments → `production` (and `staging`) → **variable** `LOG_PUBKEY`, that deployment's published key.
- The same environments → **secret** `STATUS_INGEST_KEY`, matching that deployment's API secret. Reporting is skipped where it is absent.

A repository-level value does not resolve here — the workflow reads `vars.LOG_PUBKEY` inside an `environment:`, so a repo variable arrives empty and the run stops with `--pubkey needs a value` rather than quietly falling back to the pinned production key.

The job runs without `--ots` — OpenTimestamps matures over days, and the status page tracks the Bitcoin anchor separately — so a young log isn't reported as failing.

### Fork and audit

You don't need the ingest secret to become an independent watcher: **fork this repository, enable Actions on the fork, and set the `LOG_PUBKEY` environment variable** as above — your fork then runs the full verification daily on infrastructure the operator doesn't control, and the run history on your fork is your own public audit trail (the report step skips without `STATUS_INGEST_KEY`). A failed verification fails the job, so a red run in that history means the log did not verify — the trail is only worth keeping if it can go red. Watch one deployment instead of both by trimming the matrix in the workflow. The more independent forks watching, the less anyone has to take the operator's word for anything.

## Self-test

```
pnpm selftest
```

Runs `src/revoke.selftest.mjs`, `src/ots.selftest.mjs`, `src/archive.selftest.mjs`, and `src/revocations.selftest.mjs` — offline checks of the revocation/`op=4` counter-folding logic, the dependency-clean OTS verifier, the checkpoint-archive replay primitive, the hash-chain replay, the checkpoint an offline run picks when the entries shards trail the tip, the per-day aggregates derived from the entries, and the HTTP layer (revocation paging, shard-tail fill, rate-limit retry) against a stubbed `fetch`. No network, synthetic fixtures throughout. Exit `0` = PASS.

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
