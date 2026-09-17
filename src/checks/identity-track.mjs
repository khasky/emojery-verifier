// SPDX-License-Identifier: GPL-3.0-or-later
// The identity track (op 5..7 and signed votes): structure over the entries alone,
// then the vote, ISSUE and KEY signatures, then the ENROLL proofs.

import { getBytes, getJson } from "../http.mjs";
import { verifyEnrollProofs } from "../identity.mjs";
import { check, skipCheck } from "../outcomes.mjs";
import { details, out, phase } from "../report.mjs";
import { checkIdentityInvariants, verifyIdentitySignatures } from "../transparency.mjs";

export async function checkIdentityTrack(entries, { repo, keysPerAccount, allowUnsignedVotes, blindPubkey, proofsDisabled, enrollVkHash, saltCommitment, issuers, audiences, bbVersion }) {
  const identity = await checkIdentityInvariants(entries, { keysPerAccount });
  out(`identity: ${identity.enrolls} enroll, ${identity.issues} issue, ${identity.keys} key leaf(s); ${identity.signedVotes} signed and ${identity.unsignedVotes} unsigned vote(s)`);
  details(identity.violations, 20);
  check(identity.violations.length === 0, `identity invariants hold (${identity.violations.length} violation(s))`, "identity_structure");
  if (identity.unsignedVotes > 0 && !allowUnsignedVotes) {
    check(false, `${identity.unsignedVotes} vote(s) carry no client signature (pass --allow-unsigned-votes while 1.0.0 clients are served)`, "identity_structure");
  }

  const signing = phase("verifying vote, issue and key signatures");
  const sigs = await verifyIdentitySignatures(entries, { blindPubkeySpkiB64: blindPubkey }, (done, total) => signing.tick(done, total));
  signing.end(entries.length, entries.length);
  details(sigs.voteViolations, 10);
  if (sigs.votesChecked === 0) skipCheck("vote signatures (no signed votes in the log yet)", "vote_signatures");
  else check(sigs.voteViolations.length === 0, `every signed vote verifies under its epoch key (${sigs.votesChecked} checked, ${sigs.voteViolations.length} bad)`, "vote_signatures");
  details(sigs.issueViolations, 10);
  if (identity.issues === 0) skipCheck("issue signatures (no ISSUE leaves in the log yet)", "issue_signatures");
  else check(sigs.issueViolations.length === 0, `every ISSUE leaf is signed by its enrolled account key (${sigs.issuesChecked} checked, ${sigs.issueViolations.length} bad)`, "issue_signatures");
  details(sigs.keyViolations, 10);
  if (identity.keys === 0) skipCheck("epoch-key signatures (no KEY leaves in the log yet)", "key_signatures");
  else if (!blindPubkey) skipCheck(`epoch-key signatures (${sigs.keysSkipped} KEY leaf(s), no pinned blind key: set PINNED_BLIND_PUBKEY_SPKI_B64 or pass --blind-pubkey)`, "key_signatures");
  else check(sigs.keyViolations.length === 0, `every KEY leaf carries a valid blind RSA-PSS signature (${sigs.keysChecked} checked, ${sigs.keyViolations.length} bad)`, "key_signatures");

  if (proofsDisabled) {
    skipCheck("ENROLL proofs (--no-proofs)", "enroll_proofs");
    return;
  }
  let proving = null;
  const proofs = await verifyEnrollProofs(entries, {
    repo,
    getJson,
    getBytes,
    vkSha256: enrollVkHash,
    saltCommitment,
    issuers,
    audiences,
    bbVersion,
    onProgress: (done, total) => {
      proving ??= phase("verifying ENROLL proofs");
      proving.tick(done, total);
    },
  });
  proving?.end(proofs.checked, proofs.checked);
  details(proofs.notes, 20);
  if (proofs.status === "skip") skipCheck(`ENROLL proofs (${proofs.reason})`, "enroll_proofs");
  else check(proofs.status === "pass", `every ENROLL proof verifies under the pinned verification key (${proofs.reason})`, "enroll_proofs");
}
