import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { bytesToHex, hexToBytes, sha256 } from "./transparency.mjs";
import { BITCOIN_TAG, Reader, applyOp, bytesEq, parseDetached } from "./ots-core.mjs";

const DEFAULT_BTC_API = "https://blockstream.info/api";
const EXTERNAL_TIMEOUT_MS = 120_000;

function cleanBaseUrl(base) {
  return (base || DEFAULT_BTC_API).replace(/\/+$/, "");
}

async function fetchText(url, fetchFn) {
  const res = await fetchFn(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return (await res.text()).trim();
}

async function fetchJson(url, fetchFn) {
  const res = await fetchFn(url);
  if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
  return res.json();
}

function readBitcoinHeight(payload) {
  const r = new Reader(payload);
  const height = r.varuint();
  if (!r.eof()) throw new Error("ots: trailing bytes in Bitcoin attestation");
  return height;
}

async function collectBitcoinAttestations(msg, stamp, out, errors) {
  for (const a of stamp.attestations) {
    if (!bytesEq(a.tag, BITCOIN_TAG)) continue;
    try {
      out.push({ height: readBitcoinHeight(a.payload), msg });
    } catch (e) {
      errors.push(e.message);
    }
  }
  for (const { op, child } of stamp.ops) {
    try {
      await collectBitcoinAttestations(await applyOp(op, msg), child, out, errors);
    } catch (e) {
      errors.push(e.message);
    }
  }
}

async function blockHeaderByHeight(height, btcApi, fetchFn) {
  const base = cleanBaseUrl(btcApi);
  const hash = (await fetchText(`${base}/block-height/${height}`, fetchFn)).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`Bitcoin block ${height}: invalid block hash response`);

  const status = await fetchJson(`${base}/block/${hash}/status`, fetchFn);
  if (status?.in_best_chain === false) throw new Error(`Bitcoin block ${height}: not in best chain`);

  const headerHex = await fetchText(`${base}/block/${hash}/header`, fetchFn);
  if (!/^[0-9a-f]{160}$/i.test(headerHex)) throw new Error(`Bitcoin block ${height}: invalid 80-byte header`);
  const header = hexToBytes(headerHex);

  // The merkle root below is read straight out of these header bytes, so the header
  // itself must be pinned to the block id: a Bitcoin block hash IS the double-SHA256 of
  // its 80-byte header, byte-reversed. Recompute it and require it to equal the id the
  // explorer returned for this height. Without this the whole --ots guarantee rests on
  // trusting whatever /header returned. (This proves header<->id consistency, not the
  // chain's proof-of-work; full trustless validation would also verify PoW against the
  // difficulty target and the header chain, beyond this CLI's scope — it pairs the check
  // with the best-chain flag above.)
  const id = bytesToHex((await sha256(await sha256(header))).reverse());
  if (id !== hash) throw new Error(`Bitcoin block ${height}: header does not hash to the block id (${id} != ${hash})`);

  return { hash, header };
}

export async function verifyDetachedOtsProof({
  rootHashHex,
  otsBytes,
  btcApi = DEFAULT_BTC_API,
  fetchFn = fetch,
}) {
  const rootHash = hexToBytes(rootHashHex);
  const detached = parseDetached(otsBytes);
  if (!bytesEq(detached.digest, rootHash)) {
    throw new Error(`OTS detached digest ${bytesToHex(detached.digest)} != signed root ${rootHashHex}`);
  }

  const attestations = [];
  const errors = [];
  await collectBitcoinAttestations(detached.digest, detached.stamp, attestations, errors);
  if (attestations.length === 0) {
    const suffix = errors.length ? ` (${errors.slice(0, 3).join("; ")})` : "";
    throw new Error(`OTS: no Bitcoin attestation found${suffix}`);
  }

  // Validate every attestation, not just the first that passes: a proof merged from
  // several calendars anchors in several blocks, and the sidecar's recorded height must
  // be checked against the full set of genuinely anchored heights. The returned
  // height/blockHash/merkleRoot describe the earliest anchored block; `heights` lists all.
  const attempts = [];
  const anchored = new Map(); // height -> { blockHash, merkleRoot }
  for (const att of [...attestations].sort((a, b) => a.height - b.height)) {
    if (anchored.has(att.height)) continue;
    try {
      if (att.msg.length !== 32) {
        throw new Error(`attested message is ${att.msg.length} bytes, expected 32-byte merkle root`);
      }
      const { hash, header } = await blockHeaderByHeight(att.height, btcApi, fetchFn);
      const merkleRoot = header.subarray(36, 68);
      if (bytesEq(att.msg, merkleRoot)) {
        anchored.set(att.height, { blockHash: hash, merkleRoot: bytesToHex(merkleRoot) });
      } else {
        attempts.push(`block ${att.height}: merkle_root ${bytesToHex(merkleRoot)} != OTS ${bytesToHex(att.msg)}`);
      }
    } catch (e) {
      attempts.push(`block ${att.height}: ${e.message}`);
    }
  }

  if (anchored.size === 0) {
    throw new Error(`OTS: no Bitcoin attestation validated (${attempts.join("; ")})`);
  }
  const heights = [...anchored.keys()].sort((a, b) => a - b);
  return { height: heights[0], ...anchored.get(heights[0]), heights };
}

// Node refuses to spawn a .cmd/.bat without a shell (the CVE-2024-27980 fix), and
// on Windows the OpenTimestamps client is routinely a wrapper script — so the whole
// --ots-external path died with EINVAL there. The shell is used ONLY for those two
// extensions, and every argument is ours: a validated hex digest and a temp path.
const needsShell = (command) => process.platform === "win32" && /\.(cmd|bat)$/i.test(command);

// Node does not escape argv when `shell` is set, and a Windows temp path can hold a
// space, so quote here. A token carrying a quote character is refused rather than
// escaped: none of ours ever does, and cmd.exe quoting rules are not worth guessing.
function shellQuote(token) {
  if (token.includes('"')) throw new Error(`refusing to shell-quote a token containing a quote: ${token}`);
  return /\s/.test(token) ? `"${token}"` : token;
}

function spawnCapture(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const useShell = needsShell(command);
    const child = useShell
      ? spawn(shellQuote(command), args.map(shellQuote), { windowsHide: true, shell: true })
      : spawn(command, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => {
      child.kill();
      finish(reject, new Error(`external OTS verifier timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d) => {
      stdout += d;
      if (stdout.length > 8192) stdout = stdout.slice(-8192);
    });
    child.stderr?.on("data", (d) => {
      stderr += d;
      if (stderr.length > 8192) stderr = stderr.slice(-8192);
    });
    child.on("error", (e) => finish(reject, e));
    child.on("close", (code) => finish(resolve, { code, stdout, stderr }));
  });
}

export async function runExternalOts({
  command,
  commandArgs = [],
  rootHashHex,
  otsBytes,
  timeoutMs = EXTERNAL_TIMEOUT_MS,
}) {
  // rootHashHex reaches a shell as an argv on Windows (.cmd/.bat wrappers spawn with
  // shell:true), and it originates from the repo's OTS sidecar. Reject anything that is
  // not a 64-hex digest BEFORE spawning: the caller already validates it, this is the
  // last line of defence against a shell-injection payload smuggled through root_hash.
  if (!/^[0-9a-f]{64}$/i.test(String(rootHashHex ?? ""))) {
    throw new Error("external OTS verifier: root hash is not a 64-hex digest");
  }
  const dir = await mkdtemp(path.join(tmpdir(), "emojery-ots-"));
  const proofPath = path.join(dir, "proof.ots");
  try {
    await writeFile(proofPath, Buffer.from(otsBytes));
    const result = await spawnCapture(command, [...commandArgs, "verify", "-d", rootHashHex, proofPath], timeoutMs);
    if (result.code !== 0) {
      const detail = (result.stderr || result.stdout || "").trim();
      throw new Error(`external OTS verifier exited ${result.code}${detail ? `: ${detail}` : ""}`);
    }
    return result;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export { DEFAULT_BTC_API };
