// SPDX-License-Identifier: GPL-3.0-or-later
// Terminal rendering of the human report: sections, check lines, phase progress and
// the closing verdict block. Nothing here decides an outcome.

let jsonMode = false;
let stream = process.stdout;
let color = false;
let progress = false;
let width = 76;

// Under --json stdout carries the machine summary alone, so every human line goes
// to stderr and the check lines fall back to flat "PASS  msg" text.
export function configureReport({ json }) {
  jsonMode = json;
  stream = json ? process.stderr : process.stdout;
  const forceColor = process.env.FORCE_COLOR;
  color = !json && !process.env.NO_COLOR && (forceColor && forceColor !== "0" ? true : Boolean(stream.isTTY) && process.env.TERM !== "dumb");
  progress = !json && Boolean(process.stderr.isTTY);
  width = Math.max(52, Math.min(stream.columns || 76, 78));
}

const CSI = `${String.fromCharCode(27)}[`;
const SGR_RE = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");
const SGR = { bold: "1", dim: "2", red: "31", green: "32", yellow: "33", cyan: "36", grey: "90" };

function paint(text, ...names) {
  if (!color || !names.length) return text;
  return `${CSI}${names.map((n) => SGR[n]).join(";")}m${text}${CSI}0m`;
}

// A Windows console on a legacy code page renders box drawing as mojibake and no API
// reports the active code page, so win32 gets the ASCII set unless the environment
// names a terminal that is UTF-8 by construction.
const UNICODE = process.platform !== "win32" || Boolean(process.env.WT_SESSION || process.env.TERM || process.env.ConEmuANSI);
const GLYPH = UNICODE
  ? { pass: "✓", fail: "✗", skip: "○", bar: "█", empty: "░", line: "─", tl: "┌", tr: "┐", bl: "└", br: "┘", v: "│", dot: "·" }
  : { pass: "+", fail: "x", skip: "-", bar: "#", empty: ".", line: "-", tl: "+", tr: "+", bl: "+", br: "+", v: "|", dot: "-" };
const TONE = { pass: "green", fail: "red", skip: "yellow" };
const WORD = { pass: "PASS", fail: "FAIL", skip: "SKIP" };

function visibleWidth(text) {
  return text.replace(SGR_RE, "").length;
}

function write(text) {
  stream.write(`${text}\n`);
}

// A section buffers its lines and prints them under one header carrying the tally.
// The buffer is flushed by the next section(), by verdict(), and by the crash path,
// so a run that dies mid-section still shows what it had already checked.
let current = null;
let printedSection = false;
const totals = { pass: 0, fail: 0, skip: 0 };
const failures = [];

export function section(title) {
  if (jsonMode) return;
  flush();
  current = { title, lines: [], pass: 0, fail: 0, skip: 0 };
}

export function flush() {
  if (!current) return;
  const s = current;
  current = null;
  if (!s.lines.length) return;
  const parts = [];
  if (s.pass) parts.push(paint(`${s.pass} ${GLYPH.pass}`, "green"));
  if (s.skip) parts.push(paint(`${s.skip} ${GLYPH.skip}`, "yellow"));
  if (s.fail) parts.push(paint(`${s.fail} ${GLYPH.fail}`, "red", "bold"));
  const tally = parts.join(paint(` ${GLYPH.dot} `, "grey"));
  const head = `${GLYPH.line.repeat(2)} ${s.title} `;
  const fill = Math.max(2, width - visibleWidth(head) - visibleWidth(tally) - 1);
  if (printedSection) write("");
  printedSection = true;
  write(`${paint(GLYPH.line.repeat(2), "grey")} ${paint(s.title, "bold")} ${paint(GLYPH.line.repeat(fill), "grey")} ${tally}`);
  for (const l of s.lines) write(l);
}

function line(text) {
  if (current) current.lines.push(text);
  else write(text);
}

export function out(...args) {
  line(args.join(" "));
}

// A subordinate line under the check it belongs to, dimmed so a page of revocation
// rows never competes with the verdicts.
export function detail(text) {
  line(paint(`   ${text}`, "grey"));
}

export function details(items, limit) {
  for (const item of items.slice(0, limit)) detail(item);
  if (items.length > limit) detail(`...and ${items.length - limit} more`);
}

export function mark(status, msg) {
  totals[status]++;
  if (status === "fail") failures.push(msg);
  if (current) current[status]++;
  if (jsonMode) {
    write(`${WORD[status]}  ${msg}`);
    return;
  }
  line(`   ${paint(GLYPH[status], TONE[status])}  ${msg}`);
}

// The long legs of an audit (paging leaves, rehashing, verifying archived
// signatures) show a live bar on a terminal stderr and leave one settled line
// in the report either way.
function bar(label, done, total) {
  const meterWidth = 16;
  const ratio = total > 0 ? Math.min(1, done / total) : 1;
  const filled = Math.round(ratio * meterWidth);
  const meter = GLYPH.bar.repeat(filled) + GLYPH.empty.repeat(meterWidth - filled);
  return `   ${label.padEnd(24)}${meter} ${done}/${total}`;
}

export function phase(label) {
  const startedAt = Date.now();
  let lastPaint = 0;
  let live = false;
  return {
    tick(done, total) {
      if (!progress) return;
      const now = Date.now();
      if (now - lastPaint < 80) return;
      lastPaint = now;
      live = true;
      process.stderr.write(`\r${bar(label, done, total)}`);
    },
    end(done, total) {
      if (live) process.stderr.write(`\r${" ".repeat(width)}\r`);
      const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
      if (jsonMode) return;
      line(paint(`${bar(label, done, total)}  ${secs}s`, "grey"));
    },
  };
}

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
  return `${kept}...${coloured ? `${CSI}0m` : ""}`;
}

function boxRow(label, value) {
  const room = width - 16;
  const body = `  ${paint(label.padEnd(11), "grey")}${visibleWidth(value) > room ? clip(value, room) : value}`;
  const pad = Math.max(0, width - 2 - visibleWidth(body));
  return `${paint(GLYPH.v, "grey")}${body}${" ".repeat(pad)}${paint(GLYPH.v, "grey")}`;
}

// The closing block: what was proved, against which key, from which sources, and
// how to reproduce it. The reproduce line sits outside the box so it stays
// copy-pasteable at any width.
export function verdict({ ok, treeSize, rootHash, keyLabel, witnesses, sources, elapsedSec, reproduce }) {
  flush();
  if (jsonMode) return;
  const join = (parts) => parts.filter(Boolean).join(paint(` ${GLYPH.dot} `, "grey"));
  const tone = ok ? "green" : "red";
  const title = ok ? " VERIFIED " : " VERIFICATION FAILED ";
  const fill = Math.max(2, width - 3 - title.length);
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
  for (const f of failures.slice(0, 5)) write(boxRow("failed", paint(clip(f, width - 16), "red")));
  if (failures.length > 5) write(boxRow("failed", paint(`...and ${failures.length - 5} more`, "red")));
  write(paint(GLYPH.bl + GLYPH.line.repeat(width - 2) + GLYPH.br, "grey"));
  write(`  ${paint("reproduce:", "grey")} ${reproduce}`);
}
