// SPDX-License-Identifier: Apache-2.0
// The verdict of a run (docs/PROTOCOL.md §12.3): FAIL on a contradiction in data that
// was read, WAIT when the log is behind on anchoring, PASS otherwise - with notes for
// whatever could not be read or is only partly witnessed.

export const EXIT = Object.freeze({ PASS: 0, FAIL: 1, WAIT: 3 });

export class Report {
  constructor() {
    /** @type {string[]} */
    this.failures = [];
    /** @type {string[]} */
    this.waits = [];
    /** @type {string[]} */
    this.warnings = [];
    /** @type {string[]} */
    this.info = [];
  }

  /** A contradiction: the verdict is FAIL. @param {string} s */
  fail(s) {
    this.failures.push(s);
  }

  /** @param {string} s */
  wait(s) {
    this.waits.push(s);
  }

  /** A note on a PASS. @param {string} s */
  warn(s) {
    this.warnings.push(s);
  }

  /** @param {string} s */
  note(s) {
    this.info.push(s);
  }

  get verdict() {
    if (this.failures.length) return "FAIL";
    if (this.waits.length) return "WAIT";
    return "PASS";
  }

  get exitCode() {
    return EXIT[this.verdict];
  }

  /** @param {Record<string, unknown>} [extra] */
  toJSON(extra = {}) {
    return { verdict: this.verdict, failures: this.failures, waits: this.waits, warnings: this.warnings, info: this.info, ...extra };
  }

  /** @param {Record<string, unknown>} [extra] */
  toText(extra = {}) {
    const lines = [`${this.verdict}${Object.entries(extra).map(([k, v]) => ` ${k}=${v}`).join("")}`];
    for (const s of this.failures) lines.push(`  FAIL  ${s}`);
    for (const s of this.waits) lines.push(`  WAIT  ${s}`);
    for (const s of this.warnings) lines.push(`  WARN  ${s}`);
    for (const s of this.info) lines.push(`        ${s}`);
    return lines.join("\n");
  }
}
