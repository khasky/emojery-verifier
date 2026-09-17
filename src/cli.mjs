// SPDX-License-Identifier: GPL-3.0-or-later
// Command-line parsing and help. Every accepted flag is listed: an unknown flag or a
// value flag without its value is a usage error (exit 2), never a smaller audit that
// still prints PASS.

import { ENROLL_VK_PLACEHOLDER, parseIssuersFlag, parseListFlag } from "./identity.mjs";
import { EPOCH_KEYS_PER_ACCOUNT } from "./transparency.mjs";

const VALUE_FLAGS = new Set([
  "--api",
  "--repo",
  "--pubkey",
  "--entries",
  "--wipe-grace-hours",
  "--max-checkpoint-age-hours",
  "--btc-api",
  "--ots-external",
  "--blind-pubkey",
  "--enroll-vk-hash",
  "--salt-commitment",
  "--issuers",
  "--audiences",
  "--keys-per-account",
]);
const BARE_FLAGS = new Set(["--allow-unsigned-votes", "--ots", "--json", "--help", "--no-proofs", "--no-rekor"]);

export const USAGE = "usage: node src/verify.mjs --api <url> [--repo <raw base>] [options]   (--help lists them)";

export const HELP = `Emojery log verifier: re-derives the public counts from the transparency log and
checks them against the signed, independently witnessed checkpoint.

${USAGE}

  --api <url>               public API base, e.g. https://api.emojery.app
  --repo <url>              raw base of the public log repository, e.g.
                            https://raw.githubusercontent.com/khasky/emojery-log/main
                            (adds the anchor, archive replay and Rekor witness checks)
  --pubkey <base64>         the log's Ed25519 public key; defaults to the production
                            key pinned in src/verify.mjs (pass it for staging or a fork)
  --allow-unsigned-votes    admit votes that carry no client signature. Temporary:
                            votes cast by extension 1.0.0 are unsigned, and the flag
                            goes away when that version is retired
  --ots                     deep audit: walk the OpenTimestamps proof to a Bitcoin
                            block (needs --repo; passes once the proof has matured)
  --json                    one machine-readable summary on stdout, report on stderr
  --help                    this text

advanced (another deployment, a policy window, a lighter run):
  --entries api|repo        where the leaves come from (default api). repo reads the
                            log repository's entries/ shards; with no --api that is a
                            fully offline audit of a clone or mirror
  --no-proofs               skip the ENROLL proof check (the one that loads @aztec/bb.js)
  --no-rekor                skip the Sigstore Rekor witness check
  --wipe-grace-hours <n>    grace for account wipes still in flight (default 48)
  --max-checkpoint-age-hours <n>
                            flag a checkpoint older than this (default 168, 0 disables)
  --btc-api <url>           Esplora-compatible block-header source for --ots
                            (default https://blockstream.info/api)
  --ots-external <bin>      also run an external OpenTimestamps client on the proof
  --blind-pubkey <spki b64> the deployment's blind-signing RSA public key
  --enroll-vk-hash <hex>    SHA-256 of the deployment's keys/enroll-v1.vk
  --salt-commitment <hex>   SHA-256 of the deployment's nullifier salt
  --issuers <p=iss,...>     admitted OpenID issuers (an iss starting with ^ is a regex)
  --audiences <id,...>      the deployment's OAuth client ids
  --keys-per-account <n>    epoch keys one account may hold per epoch (default ${EPOCH_KEYS_PER_ACCOUNT},
                            0 lifts the bound)

exit code: 0 the log verified, 1 it did not, 2 usage error`;

function valueOf(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const value = args[i + 1];
  return value && !value.startsWith("--") ? value : undefined;
}

// A value never legitimately starts with "-" (URLs, base64 keys, non-negative
// numbers), so `--pubkey --json` is an error rather than --json swallowed as the key.
function argvErrors(args) {
  const errors = [];
  for (let i = 0; i < args.length; i++) {
    const token = args[i];
    if (BARE_FLAGS.has(token)) continue;
    if (VALUE_FLAGS.has(token)) {
      const value = args[i + 1];
      if (!value || value.startsWith("-")) errors.push(`${token} needs a value`);
      else i++;
      continue;
    }
    errors.push(token.startsWith("-") ? `unknown flag ${token}` : `unexpected argument ${token}`);
  }
  return errors;
}

const SHA256_HEX = /^[0-9a-f]{64}$/i;

// Returns { help: true }, { error }, or { options }.
export function parseCli(args) {
  if (args.includes("--help")) return { help: true };
  const badArgs = argvErrors(args);
  if (badArgs.length) return { error: badArgs.join("; ") };

  const options = {
    api: valueOf(args, "--api"),
    repo: valueOf(args, "--repo"),
    pubkey: valueOf(args, "--pubkey"),
    entriesMode: valueOf(args, "--entries") ?? "api",
    wipeGraceHours: Number(valueOf(args, "--wipe-grace-hours") ?? "48"),
    maxAgeHours: Number(valueOf(args, "--max-checkpoint-age-hours") ?? "168"),
    ots: args.includes("--ots"),
    btcApi: valueOf(args, "--btc-api"),
    otsExternal: valueOf(args, "--ots-external"),
    json: args.includes("--json"),
    rekorDisabled: args.includes("--no-rekor"),
    proofsDisabled: args.includes("--no-proofs"),
    allowUnsignedVotes: args.includes("--allow-unsigned-votes"),
    blindPubkey: valueOf(args, "--blind-pubkey"),
    enrollVkHash: valueOf(args, "--enroll-vk-hash"),
    saltCommitment: valueOf(args, "--salt-commitment"),
    audiences: valueOf(args, "--audiences") ? parseListFlag(valueOf(args, "--audiences")) : undefined,
    issuers: undefined,
    keysPerAccount: Number(valueOf(args, "--keys-per-account") ?? EPOCH_KEYS_PER_ACCOUNT),
  };
  try {
    if (valueOf(args, "--issuers")) options.issuers = parseIssuersFlag(valueOf(args, "--issuers"));
  } catch (e) {
    return { error: e.message };
  }
  for (const [flag, value] of [
    ["--enroll-vk-hash", options.enrollVkHash],
    ["--salt-commitment", options.saltCommitment],
  ]) {
    if (value && value !== ENROLL_VK_PLACEHOLDER && !SHA256_HEX.test(value)) return { error: `${flag} needs a 64-hex SHA-256` };
  }
  if (!Number.isInteger(options.keysPerAccount) || options.keysPerAccount < 0) return { error: "--keys-per-account needs a non-negative integer (0 = no bound)" };
  if (!Number.isFinite(options.maxAgeHours) || options.maxAgeHours < 0) return { error: "--max-checkpoint-age-hours needs a non-negative number (0 disables)" };
  if (options.entriesMode !== "api" && options.entriesMode !== "repo") return { error: "--entries must be 'api' or 'repo'" };
  // --api is optional only for the offline audit (--entries repo with --repo).
  if (!options.api && !(options.entriesMode === "repo" && options.repo)) return { error: "--api is required unless --entries repo and --repo make an offline audit" };
  if (options.entriesMode === "repo" && !options.repo) return { error: "--entries repo needs --repo" };
  if (!Number.isFinite(options.wipeGraceHours) || options.wipeGraceHours < 0) return { error: "--wipe-grace-hours needs a non-negative number" };
  if (options.otsExternal && !options.ots) return { error: "--ots-external requires --ots" };
  return { options };
}
