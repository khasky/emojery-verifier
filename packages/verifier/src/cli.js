#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// npx @emojery/verifier [--full | --leaf <seq> | --target <site>/<id>...] [options]

import { parseArgs } from "node:util";
import { fromBase64Url, fromHex } from "@emojery/shared/core";
import { countsPath } from "@emojery/shared/api";
import { fastCheck } from "./fast.js";
import { fullCheck } from "./full.js";
import { pinsFor } from "./pins.js";
import { Report } from "./report.js";
import { leafCheck, targetCheck } from "./single.js";
import { host, read, text } from "./source.js";
import { DEFAULT_STATE, loadState, saveState } from "./state.js";

const USAGE = `Usage: emojery-verifier [mode] [options]

Modes (one):
  (none)                     the quick check: anchors, mirror, tiles, the pinned state
  --full                     replay the whole log: every entry, signature, proof and count
  --leaf <seq>               one entry and its inclusion in the newest anchored checkpoint
      --pubkey <key>         your device key (base64url or hex); required for a REACT
      --counter <n>          the counter on your receipt
  --target <site>/<id>       one target's count against the API's (repeatable)

Options:
  --log <name>               log.emojery.app (default) or log-staging.emojery.app
  --state <path>             state file (default ${DEFAULT_STATE})
  --no-proofs                skip ENROLL proofs (--full, --leaf)
  --bucket <url>             read the log from another copy of the bucket
  --mirror <url>             read the mirror from another copy
  --api <url>                ask another counts API (--target)
  --json                     print the verdict as JSON

Exit code: 0 PASS, 1 FAIL, 3 WAIT, 2 usage.`;

/** @param {string} s */
function key(s) {
  return /^[0-9a-f]{64}$/.test(s) ? fromHex(s) : fromBase64Url(s);
}

async function main() {
  let args;
  try {
    args = parseArgs({
      options: {
        full: { type: "boolean" },
        leaf: { type: "string" },
        pubkey: { type: "string" },
        counter: { type: "string" },
        target: { type: "string", multiple: true },
        log: { type: "string", default: "log.emojery.app" },
        state: { type: "string", default: DEFAULT_STATE },
        "no-proofs": { type: "boolean" },
        bucket: { type: "string" },
        mirror: { type: "string" },
        api: { type: "string" },
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
      },
    }).values;
  } catch (e) {
    console.error(`${/** @type {Error} */ (e).message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }
  const modes = [args.full, args.leaf !== undefined, args.target !== undefined].filter(Boolean).length;
  if (modes > 1) {
    console.error(`one mode at a time\n\n${USAGE}`);
    return 2;
  }
  const pins = pinsFor(args.log);
  const log = (/** @type {string} */ s) => process.stderr.write(`${s}\n`);
  const report = new Report();
  const ctx = {
    logName: args.log,
    pins,
    bucket: host(args.bucket ?? pins.bucket, { log }),
    mirror: host(args.mirror ?? pins.mirror, { log }),
    report,
    now: Math.floor(Date.now() / 1000),
    checkProofs: !args["no-proofs"],
    /** @param {string} url */
    getJson: async (url) => {
      const r = await read(url, { log });
      if (!r.ok) throw new Error(`${url}: ${r.status}`);
      return JSON.parse(text(r));
    },
  };

  if (args.leaf !== undefined) {
    const seq = Number(args.leaf);
    if (!Number.isSafeInteger(seq) || seq < 0) {
      console.error("--leaf takes a leaf number");
      return 2;
    }
    await leafCheck(ctx, { seq, pubkey: args.pubkey ? key(args.pubkey) : undefined, counter: args.counter === undefined ? undefined : Number(args.counter) });
  } else if (args.target) {
    const targets = args.target.map((t) => {
      const i = t.indexOf("/");
      return { site: t.slice(0, i), targetId: t.slice(i + 1) };
    });
    const api = (args.api ?? pins.api).replace(/\/+$/, "");
    await targetCheck(
      {
        ...ctx,
        fetchCounts: async (site, targetId) => {
          const r = await read(`${api}${countsPath(site, targetId)}`, { log });
          if (!r.ok) throw new Error(`the counts API answered ${r.status} for ${site}/${targetId}`);
          const size = r.headers.get("x-emojery-published-size");
          return { ...JSON.parse(text(r)), size: size === null ? null : Number(size), origin: r.headers.get("x-emojery-published-origin") };
        },
      },
      targets,
    );
  } else {
    const file = await loadState(args.state);
    const next = await (args.full ? fullCheck : fastCheck)(ctx, file.logs[args.log]);
    if (next) {
      file.logs[args.log] = next;
      await saveState(args.state, file);
    }
  }
  console.log(args.json ? JSON.stringify(report.toJSON({ log: args.log })) : report.toText({ log: args.log }));
  return report.exitCode;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(process.env.DEBUG ? (e?.stack ?? e) : `error: ${e?.message ?? e}`);
    process.exitCode = 1;
  },
);
