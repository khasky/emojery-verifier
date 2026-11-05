# Emojery Verifier

Emojery shows reaction counts on pages across the web. Every reaction, change and removal is also an entry in a public, append-only **transparency log**, published at [`log.emojery.app`](https://log.emojery.app) as [C2SP tiles](https://c2sp.org/tlog-tiles), its checkpoints anchored in [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) and mirrored in [`emojery-tlog`](https://github.com/khasky/emojery-tlog). This tool reads that log and checks it, so the counts are provable rather than promised. It has no privileged access: it reads only public files, and anyone can run it.

[docs/concepts.md](docs/concepts.md) explains the log in plain words; [docs/PROTOCOL.md](docs/PROTOCOL.md) is the byte-level specification.

## What it checks

- Every checkpoint is signed by the log key pinned in this tool, and every anchor is in a pinned Rekor shard and in the mirror's shared history, so no reader can be shown a history the others were not.
- Each new checkpoint extends the last one this machine saw, and nothing before it was rewritten.
- With `--full`: every entry decodes, every vote is signed by a registered device key, every registration carries a zero-knowledge proof that a real Google, Microsoft or Apple account stands behind it, under a provider key a witness has seen, and the counts follow from the entries alone.
- A rewind, if there ever is one, starts from the old log's exact prefix; every one is reported for the life of the log.

## Run it

Node 22 or newer.

```text
npx @emojery/verifier                       # the quick check: seconds
npx @emojery/verifier --full                # replay everything from the first entry
npx @emojery/verifier --leaf <n> --pubkey <key> --counter <c>   # one vote of yours, from its receipt
npx @emojery/verifier --target github/khasky/emojery            # one target's count against the API
```

The quick check keeps a small state file (`~/.emojery-verifier/state.json`, or `--state <path>`) with the last anchored checkpoint it verified; the next run checks that the log extends it. `--json` prints the verdict as one JSON object. `--help` lists every option.

## Reading the result

- **PASS** (exit 0): everything read is consistent. Notes may follow: what could not be read, a mirror a little behind, a provider key not yet witnessed.
- **WAIT** (exit 3): the log is behind on anchoring, or the mirror is out of reach. Run it again later.
- **FAIL** (exit 1): something read contradicts something else — a signature, a root, two histories, a count. That is what this tool exists to catch: keep the output and open an issue here, quoting it.

An unreachable source is never a failure on its own.

## Watch the log yourself

The operator's mirror runs this tool every 30 minutes. Anyone can run it on a schedule of their own; a minimal GitHub Actions job:

```yaml
on:
  schedule:
    - cron: "17 */6 * * *"
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - uses: actions/cache@v4
        with:
          path: ~/.emojery-verifier
          key: emojery-verifier-${{ github.run_id }}
          restore-keys: emojery-verifier-
      - run: npx --yes @emojery/verifier --json
```

The cache carries the state between runs, so each run checks that the log extends what the previous one saw.

## The 1.0.0 log

The log of Emojery 1.0.0 ([`emojery-log`](https://github.com/khasky/emojery-log)) used another format and is frozen. Tag [`v1.0.0`](https://github.com/khasky/emojery-verifier/tree/v1.0.0) of this repository verifies it.

## Packages

| Package | What |
| --- | --- |
| [`@emojery/verifier`](packages/verifier) | this command-line tool |
| [`@emojery/shared`](packages/shared) | the log format, signed messages, tree and tiles, fold, site rules and palette, shared by the verifier, the extension and the publisher |

`pnpm install`, then `pnpm test` runs both packages' tests, including the vectors typed from PROTOCOL.md and the third-party tree and note vectors.

## License

Apache-2.0. Contributions from outside the project sign off their commits (Developer Certificate of Origin); see [CONTRIBUTING.md](CONTRIBUTING.md).
