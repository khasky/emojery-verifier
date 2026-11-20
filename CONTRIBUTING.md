# Contributing

Issues and pull requests are welcome. A failing verification is worth an issue on its own: quote the full output.

## Sign-off

Every commit in a pull request from outside the project carries a `Signed-off-by:` line, certifying the [Developer Certificate of Origin](https://developercertificate.org/): that you wrote the change or have the right to submit it under the project's license. `git commit -s` adds the line. There is no contributor license agreement.

## Changes to the format

The log format in [docs/PROTOCOL.md](docs/PROTOCOL.md) is frozen by the log's first checkpoint. A change that reads published entries differently is a change to the protocol, not to this tool: open an issue first. Rules for published entries only ever loosen; a new entry kind or version ships in this verifier before any log carries it.

## Tests

`pnpm install`, then `pnpm test`. The vectors under `packages/shared/vectors/handwritten/` are typed from PROTOCOL.md by hand and are the oracle for the encoder: when the two disagree, the text decides, and a change to those vectors needs a change to the text.
