// SPDX-License-Identifier: GPL-3.0-or-later
// Terminal presentation for the human report: colour, sections, phase progress and
// the closing verdict block. Nothing here decides anything — it only renders what
// verify.mjs already concluded, so a hostile terminal cannot turn a FAIL into a PASS.
//
// --json keeps the historical flat "PASS  msg" lines: the scheduled ingest reads
// stdout as JSON and the human lines only as a run log, so every decoration below
// is a no-op in that mode.

const argv = process.argv;
const JSON_MODE = argv.includes("--json");

// stdout is the report stream; --json moves the human lines to stderr so stdout
// carries the machine summary alone.
const stream = JSON_MODE ? process.stderr : process.stdout;

const forceColor = process.env.FORCE_COLOR;
const COLOR =
  !JSON_MODE &&
  !argv.includes("--no-color") &&
  !process.env.NO_COLOR &&
  (forceColor && forceColor !== "0" ? true : Boolean(stream.isTTY) && process.env.TERM !== "dumb");

// A Windows console on a legacy code page renders the box-drawing set as mojibake and
// no API reports which code page is active, so the glyphs are opt-out on win32 unless
// the environment names a terminal that is UTF-8 by construction. --ascii forces the
// fallback anywhere.
const UNICODE =
  !JSON_MODE &&
  !argv.includes("--ascii") &&
  (process.platform !== "win32" || Boolean(process.env.WT_SESSION || process.env.TERM || process.env.ConEmuANSI));

// Progress is transient cursor work, so it belongs on stderr and only when stderr is
// a terminal — redirected output keeps the settled one-line-per-phase summary instead.
const PROGRESS = !JSON_MODE && Boolean(process.stderr.isTTY);

const CSI = String.fromCharCode(27) + "[";
const SGR_RE = new RegExp(String.fromCharCode(27) + "\[[0-9;]*m", "g");
const SGR = { bold: "1", dim: "2", red: "31", green: "32", yellow: "33", cyan: "36", grey: "90" };

function paint(text, ...names) {
  if (!COLOR || !names.length) return text;
  return `${CSI}${names.map((n) => SGR[n]).join(";")}m${text}${CSI}0m`;
}

const GLYPH = UNICODE
  ? { pass: "✓", fail: "✗", skip: "○", bar: "█", empty: "░", line: "─", tl: "┌", tr: "┐", bl: "└", br: "┘", v: "│", dot: "·" }
  : { pass: "+", fail: "x", skip: "-", bar: "#", empty: ".", line: "-", tl: "+", tr: "+", bl: "+", br: "+", v: "|", dot: "-" };

export const ELL = UNICODE ? "…" : "...";

const TONE = { pass: "green", fail: "red", skip: "yellow" };
const WORD = { pass: "PASS", fail: "FAIL", skip: "SKIP" };

const WIDTH = Math.max(52, Math.min(stream.columns || 76, 78));

function visibleWidth(text) {
  return text.replace(SGR_RE, "").length;
}

function write(text) {
  stream.write(`${text}\n`);
}

// --- sections --------------------------------------------------------------
//
// A section buffers its lines and prints them under one header carrying the
// tally, so the reader sees "Checkpoint: 3/3" rather than counting glyphs. The
// buffer is flushed by the next section(), by verdict(), and by the crash path —
// a run that dies mid-section must still show what it had already checked.

let current = null;
let printedSection = false;
const totals = { pass: 0, fail: 0, skip: 0 };
const failures = [];

export function section(title) {
  if (JSON_MODE) return;
  flush();
  current = { title, lines: [], pass: 0, fail: 0, skip: 0 };
}

export function flush() {
  if (!current) return;
  const s = current;
  current = null;
  if (!s.lines.length) return;
  const parts = [];
  if (s.pass) parts.push(paint(`${s.pass} ${UNICODE ? GLYPH.pass : WORD.pass}`, "green"));
  if (s.skip) parts.push(paint(`${s.skip} ${UNICODE ? GLYPH.skip : WORD.skip}`, "yellow"));
  if (s.fail) parts.push(paint(`${s.fail} ${UNICODE ? GLYPH.fail : WORD.fail}`, "red", "bold"));
  const tally = parts.join(paint(` ${GLYPH.dot} `, "grey"));
  const head = `${GLYPH.line.repeat(2)} ${s.title} `;
  const fill = Math.max(2, WIDTH - visibleWidth(head) - visibleWidth(tally) - 1);
  if (printedSection) write("");
  printedSection = true;
  write(`${paint(GLYPH.line.repeat(2), "grey")} ${paint(s.title, "bold")} ${paint(GLYPH.line.repeat(fill), "grey")} ${tally}`);
  for (const l of s.lines) write(l);
}

function line(text) {
  if (current) current.lines.push(text);
  else write(text);
}

// An ordinary report line (the checkpoint header, the fold summary).
export function out(...args) {
  line(args.join(" "));
}

// A subordinate detail under the check it belongs to: dimmed, so a page of
// revocation rows reads as context and never competes with the verdicts.
export function detail(text) {
  line(paint(`   ${text}`, "grey"));
}

// Machine-readable payload (--stats / --counters CSV): never decorated, never
// buffered — it is piped into files and spreadsheets.
export function raw(text) {
  flush();
  write(text);
}

export function mark(status, msg) {
  totals[status]++;
  if (status === "fail") failures.push(msg);
  if (current) current[status]++;
  if (JSON_MODE) {
    write(`${WORD[status]}  ${msg}`);
    return;
  }
  line(`   ${paint(UNICODE ? GLYPH[status] : WORD[status], TONE[status])}  ${msg}`);
}

// --- phase progress --------------------------------------------------------
//
// The long legs of an audit (paging the leaves, rehashing them, verifying every
// archived signature) are minutes of silence on a large log, which reads as a
// hung process. The live bar is stderr-only and erases itself; the settled line
// stays in the report, so a redirected run still shows what each leg cost.

function bar(label, done, total) {
  const width = 16;
  const ratio = total > 0 ? Math.min(1, done / total) : 1;
  const filled = Math.round(ratio * width);
  const meter = GLYPH.bar.repeat(filled) + GLYPH.empty.repeat(width - filled);
  return `   ${label.padEnd(24)}${meter} ${done}/${total}`;
}

let auditing = false;
export function beginAudit() {
  auditing = true;
}

export function phase(label) {
  const startedAt = Date.now();
  let lastPaint = 0;
  let live = false;
  return {
    tick(done, total) {
      if (!PROGRESS || !auditing) return;
      const now = Date.now();
      if (now - lastPaint < 80) return;
      lastPaint = now;
      live = true;
      process.stderr.write(`\r${bar(label, done, total)}`);
    },
    end(done, total) {
      if (live) process.stderr.write(`\r${" ".repeat(WIDTH)}\r`);
      const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
      if (JSON_MODE || !auditing) return;
      line(paint(`${bar(label, done, total)}  ${secs}s`, "grey"));
    },
  };
}

// --- verdict ---------------------------------------------------------------
//
// The closing block answers the question the flat log never did: what exactly was
// proved, against which key, from which sources, and how to reproduce it. The
// reproduce line sits outside the box so it stays copy-pasteable at any width.

function clip(text, room) {
  if (visibleWidth(text) <= room) return text;
  const budget = room - 1;
  let kept = "";
  let shown = 0;
  let coloured = false;
  for (let i = 0; i < text.length && shown < budget; ) {
    SGR_RE.lastIndex = i;
    const esc = SGR_RE.exec(text);
    if (esc && esc.index === i) {
      kept += esc[0];
      coloured = true;
      i += esc[0].length;
      continue;
    }
    kept += text[i];
    shown++;
    i++;
  }
  return `${kept}${ELL}${coloured ? `${CSI}0m` : ""}`;
}

function boxRow(label, value) {
  const room = WIDTH - 16;
  const body = `  ${paint(label.padEnd(11), "grey")}${visibleWidth(value) > room ? clip(value, room) : value}`;
  const pad = Math.max(0, WIDTH - 2 - visibleWidth(body));
  return `${paint(GLYPH.v, "grey")}${body}${" ".repeat(pad)}${paint(GLYPH.v, "grey")}`;
}

export function verdict({ ok, treeSize, rootHash, keyLabel, witnesses, sources, elapsedSec, reproduce }) {
  flush();
  if (JSON_MODE) return;
  const join = (parts) => parts.filter(Boolean).join(paint(` ${GLYPH.dot} `, "grey"));
  const tone = ok ? "green" : "red";
  const title = ok ? " VERIFIED " : " VERIFICATION FAILED ";
  const fill = Math.max(2, WIDTH - 3 - title.length);
  write("");
  write(`${paint(GLYPH.tl + GLYPH.line, "grey")}${paint(title, tone, "bold")}${paint(GLYPH.line.repeat(fill) + GLYPH.tr, "grey")}`);

  const tally = [
    paint(`${totals.pass} passed`, "green"),
    totals.skip ? paint(`${totals.skip} skipped`, "yellow") : "",
    totals.fail ? paint(`${totals.fail} failed`, "red", "bold") : "",
  ]
    .filter(Boolean)
    .join(paint(` ${GLYPH.dot} `, "grey"));
  write(boxRow("RESULT", `${paint(ok ? "PASS" : "FAIL", tone, "bold")}   ${tally}`));
  write(boxRow("tree size", `${treeSize}   ${paint(`root ${rootHash}`, "grey")}`));
  write(boxRow("log key", keyLabel));
  write(boxRow("witnesses", join(witnesses) || paint("none cross-checked", "yellow")));
  write(boxRow("sources", join(sources)));
  write(boxRow("elapsed", `${elapsedSec}s`));
  for (const f of failures.slice(0, 5)) write(boxRow("failed", paint(clip(f, WIDTH - 16), "red")));
  if (failures.length > 5) write(boxRow("failed", paint(`…and ${failures.length - 5} more`, "red")));
  write(paint(GLYPH.bl + GLYPH.line.repeat(WIDTH - 2) + GLYPH.br, "grey"));
  write(`  ${paint("reproduce:", "grey")} ${reproduce}`);
}
