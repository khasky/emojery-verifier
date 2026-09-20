# Emojery Verifier

Emojery shows reaction counts on pages across the web. Every reaction, change and removal is also written to a public, append-only **transparency log**, and the operator regularly signs a **checkpoint** of that log and publishes it in [`emojery-log`](https://github.com/khasky/emojery-log), in Sigstore's Rekor log and, with a delay, in the Bitcoin blockchain. A history that was edited afterwards no longer matches those signed and witnessed checkpoints.

This tool reads the public log and checks all of that, so the counts are provable rather than promised. It has no privileged access: it talks only to the public API and the public repository, and anyone can run it.

## What it proves

- The checkpoint is signed by the published log key and is not stale.
- The API and the public repository publish the same checkpoint (no "split view").
- Every log entry, refetched, hashes back to the checkpoint's Merkle root, and the published hash chain replays from the first entry in order.
- Every checkpoint ever published lies on one append-only history: each archived root is recomputed from today's entries.
- The counts are re-derived from the log alone, revocations included, and the log is internally consistent (no impossible state, no negative count).
- The public revocation list matches the revocations present in the log, and account wipes are complete (a single vote cannot be quietly reversed under an account-deletion label).
- The identity track holds: every signed vote traces to an epoch key the log registered earlier, every key grant carries the operator's blind signature and the enrolled account's own signature, and every enrollment carries a zero-knowledge proof over a real OpenID provider account.
- Sigstore Rekor, an independently operated log, holds exactly our signed checkpoint bytes.
- With `--ots`: the matured OpenTimestamps proof anchors the signed root in a Bitcoin block.

The checks and their byte-level definitions are in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Run it

Node 20 or newer. Install once with `pnpm install` (or run without a checkout: `npx github:khasky/emojery-verifier <flags>`).

Verify production:

```
node src/verify.mjs --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

Deep Bitcoin audit (slower; passes once the OpenTimestamps proof has matured, hours to days after a checkpoint):

```
node src/verify.mjs --ots --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

Machine-readable result on stdout, one JSON object (`result`, `tree_size`, `ts`, `checks`, `duration_sec`; every check is `pass`, `fail` or `skip`):

```
node src/verify.mjs --json --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

A vote that carries no client signature fails the identity check. `--allow-unsigned-votes` admits it instead, which is what a log holding such votes needs to verify at all.

## Reading the result

The report is one line per check, grouped in sections, and a closing box:

```
── Checkpoint ────────────────────────────────────────────────────────── 3 ✓
   ✓  checkpoint Ed25519 signature
   ✓  checkpoint is fresh (0.4h old, threshold 168h; a quiet log ages legitimately, tune --max-checkpoint-age-hours)
   ✓  GitHub anchor matches signed root (tree_size=627)
...
┌─ VERIFIED ───────────────────────────────────────────────────────────────┐
│  RESULT     PASS   22 passed · 4 skipped                                 │
│  tree size  627   root ea62f8c2ff...2231de                               │
│  log key    XeLiQ5CMhs... (pinned in verify.mjs)                         │
│  witnesses  GitHub anchor · Rekor 108e9186e8c5...                        │
└──────────────────────────────────────────────────────────────────────────┘
```

**PASS** (exit code 0): the published counts match the public log, and the log matches its signed, witnessed checkpoints. Nothing in the history has been rewritten.

**SKIP** (○): a check could not run and is not counted as a pass: the log holds no leaf of that kind yet, a flag turned it off, or a third party (GitHub's API, Rekor) was unreachable. An outage of those third parties never turns into a FAIL; a failed fetch from the API or the log repository does fail its check.

**FAIL** (exit code 1): the published record does not match itself. That is exactly what this tool exists to catch. Then:

1. Read the failed line; the box repeats it. It names what disagreed (a signature, a root, a count, a revocation).
2. Run it again. A third party being unreachable (GitHub's API, Rekor) shows as a skip, and a crash mid-run as a `verifier error`; a failed fetch from the API or the log repository does fail its check, so a second run separates an outage from a real mismatch.
3. Keep the full output and open an issue in this repository or in [`emojery-log`](https://github.com/khasky/emojery-log/issues), quoting it. The log history and its mirrors (Rekor, Bitcoin, third-party archives) are the evidence; nothing you need to preserve is on your machine.

Exit code 2 is a usage error: an unknown flag or a flag without its value is refused rather than silently running a smaller audit that still prints PASS.

Colour is on when stdout is a terminal and off under `--json`; `NO_COLOR` turns it off, `FORCE_COLOR=1` forces it through a pipe.

## Pinned values

The values production is verified against live in one place, `src/verify.mjs`, so a copy elsewhere cannot drift from the one the tool actually uses:

| Pin | Value |
| --- | --- |
| log signing key (Ed25519, base64) | `XeLiQ5CMhsjLmnQbIWSwWHNjcJg01Zs0veQDiwluT6c=` |
| `PINNED_ENROLL_VK_SHA256` | SHA-256 of `keys/enroll-v1.vk` in the log repository |
| `PINNED_BLIND_PUBKEY_SPKI_B64`, `PINNED_SALT_COMMITMENT`, `PINNED_AUDIENCES` | empty until the operator publishes the OpenID material; each check that needs one reports a skip naming the pin |
| `PINNED_ISSUERS` | the admitted OpenID issuers (`DEFAULT_ISSUERS` in `src/identity.mjs`) |

The Rekor instance is pinned the same way in `src/checks/rekor.mjs`. A run can never pass on a pin nobody set: were the verification-key pin ever left at its placeholder, a log with enrollments would fail the proof check unless `--enroll-vk-hash` supplied the real digest.

## Advanced: other deployments

The same tool verifies a staging deployment or a fork; the flags below replace the pins and tune the policy windows. `--help` lists them too.

| Flag | Meaning |
| --- | --- |
| `--pubkey <base64>` | the deployment's log signing key (raw Ed25519) |
| `--entries <source>` | where the leaves come from (default `manifest`): `manifest` reads the repository's `entries/manifest` and fetches each chunk body from the host it names, checking it against its `sha256`; `none` reads no leaves at all (below) |
| `--entries-base <url>` | where the chunk bodies and the ENROLL proof bodies are fetched from, instead of the host `entries/mirrors.json` names. Any copy will do: the published digest is what decides |
| `--counts-base <url>` | host serving the public reaction badges, whose exact total is **reported** against the fold. Defaults to the pinned production API, and only while `--pubkey` is the pinned log key too: another deployment signs with its own key and serves its own counts, so there this flag is required and the comparison is skipped without it. A disagreement is a note, never a failure - the fold stops at the audited checkpoint while the served count is live |
| `--counts-sample <n>` | how many of the largest targets to compare that way (default 10; 0 disables) |
| `--no-proofs` | skip the ENROLL proof check, the one that loads `@aztec/bb.js` |
| `--no-rekor` | skip the Rekor witness check |
| `--wipe-grace-hours <n>` | grace for account wipes still in flight (default 48; a quiescent log can be audited with 0) |
| `--max-checkpoint-age-hours <n>` | flag a checkpoint older than this (default 168; 0 disables). A quiet log ages legitimately |
| `--btc-api <url>` | Esplora-compatible block-header source for `--ots` (default `https://blockstream.info/api`) |
| `--ots-external <bin>` | also run an external OpenTimestamps client (`ots verify`) on the same proof; a missing or broken binary fails the run, since the cross-check was asked for |
| `--blind-pubkey <spki b64>` | the deployment's blind-signing RSA public key |
| `--enroll-vk-hash <hex>` | SHA-256 of the deployment's `keys/enroll-v1.vk` |
| `--salt-commitment <hex>` | SHA-256 of the deployment's nullifier salt |
| `--issuers <provider=iss,...>` | the admitted OpenID issuers, **replacing** `PINNED_ISSUERS` rather than adding to it; an `iss` starting with `^` is a regular expression. A deployment that runs its own test issuer lists the real providers alongside it, or their ENROLL proofs are rejected as un-admitted |
| `--audiences <id,...>` | the deployment's OAuth client ids |
| `--keys-per-account <n>` | epoch keys one account may hold per epoch (default 10; 0 lifts the bound) |

A publish lands a tick behind the checkpoint that covers it, so a run audits the newest published checkpoint the chunks fully cover, says which one, and still cross-checks the tip's Rekor witness.

`--entries none` skips the leaves entirely: it verifies every archived checkpoint signature, refuses two signatures that disagree on one tree size, replays the chain of consistency proofs published beside them, and cross-checks the tip against its Rekor witness. That covers everything the log published about its own history, in seconds and with no download. It covers nothing about the leaves themselves - the counter fold and invariants A-J need them - and the run prints which checks it skipped.

```
node src/verify.mjs --entries none \
  --repo https://raw.githubusercontent.com/khasky/emojery-log/main
```

### Watch the log yourself

The operator runs this tool daily and posts the verdict to the status page at [emojery.app/status](https://emojery.app/status). Anyone can run the same verification on a schedule of their own, so the verdict does not depend on the operator's timer. A minimal GitHub Actions job for a fork:

```yaml
on:
  schedule:
    - cron: "0 4 * * *"
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: pnpm/action-setup@v6
      - run: pnpm install --frozen-lockfile --ignore-scripts
      - run: |
          node src/verify.mjs --json --allow-unsigned-votes \
            --repo https://raw.githubusercontent.com/khasky/emojery-log/main > result.json
          cat result.json
          [ "$(node -p "require('./result.json').result")" = pass ] || exit 1
```

A red run means the log did not verify; `result.json` names the check. The job runs without `--ots`, since a young checkpoint has no matured Bitcoin proof yet.

## How it works

- [docs/PROTOCOL.md](docs/PROTOCOL.md): the byte layouts, the invariants, the identity track and the known-answer tests, everything needed to re-implement the checks.
- [`emojery-log`](https://github.com/khasky/emojery-log): the public data repository this tool reads (checkpoints, the entries manifest, the tombstone file, Rekor and OpenTimestamps sidecars, keys).
- [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) and [OpenTimestamps](https://opentimestamps.org/): the two independent witnesses.

## Self-test

```
pnpm selftest
```

Offline, synthetic fixtures, no network, `@aztec/bb.js` not loaded. Exit code 0 = PASS. What each suite covers is listed in [docs/PROTOCOL.md](docs/PROTOCOL.md#self-tests).

## License

[GPL-3.0-or-later](LICENSE).
