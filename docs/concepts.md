# Concepts

What the Emojery log is, in plain words, and what this verifier checks. The byte-level rules are in [PROTOCOL.md](PROTOCOL.md); this page explains them.

## The log

Every reaction anyone sets, changes or clears with Emojery becomes an entry in a public, append-only log: the **log**. Entries are never edited or deleted. The counts the extension shows are not stored anywhere as numbers you have to trust; they are what you get by replaying the log from the first entry.

The log has a name, `log.emojery.app`, and an **origin** that adds a generation: `log.emojery.app/g0`. The generation changes only in an emergency (see [Rewinds](#rewinds)).

## Entries

There are four kinds of entry:

- **REACT** — an account set, changed or cleared its reaction on one target (a GitHub repository, an X post, a film page). It names the reaction before and after, carries a counter that only goes up, and is signed by the device key that made it. The operator cannot forge it, move it to another target or change the reaction.
- **ENROLL** — a device key was registered. It carries a zero-knowledge proof that a real Google, Microsoft or Apple account signed off on this key, without revealing which account. From the account, the proof derives a **pseudonym** (the nullifier): one account always gets the same pseudonym, and the pseudonym says nothing about who it is.
- **REVOKE** — the operator withdrew every vote of one account, for a public reason (`coordinated_voting`, `multiple_accounts`, `automation`, `abuse_other`) and under a decision id. It is visible to everyone: the operator can remove votes, and it shows.
- **RETIRE** — an account was deleted, either by its owner (signed with their own device key, so the operator cannot fake a self-deletion) or by the operator at the owner's request or under a legal obligation.

Entries carry no time. Their order is their position in the log.

## Counting

To count a target, replay the log: keep, for every pseudonym and target, the reaction it currently holds. A REACT replaces it; a REVOKE empties all of that pseudonym's reactions; a RETIRE empties them and also kills the pseudonym's old registrations, so its old signatures can never be replayed. The count of 🔥 on a target is the number of pseudonyms currently holding 🔥 there.

## Checkpoints and tiles

The operator publishes the log as **tiles**: fixed-size files of entries and of hashes, in the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) format used by other transparency logs. A **checkpoint** is a short signed note that names the origin, the number of entries and the root hash of the Merkle tree over all of them. Anyone holding two checkpoints can check, from a handful of hashes, that the newer log extends the older one and rewrote nothing.

## Anchors

Every 30 minutes the operator also writes the checkpoint into [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/), a public transparency log run by the Linux Foundation's Sigstore project, and publishes the receipt as an **anchor**. Rekor keeps no secret and answers to no one at Emojery: once a checkpoint is in Rekor, the operator cannot later show a different history for that point without leaving two contradicting entries under its own key.

## The mirror

The repository [`emojery-tlog`](https://github.com/khasky/emojery-tlog) is a partial mirror of the log on GitHub. A workflow runs this verifier every 30 minutes and commits every anchor, append-only, together with its verdict. GitHub shows the same history to everyone, and Software Heritage archives it, so the mirror is how a reader knows that the anchor they were shown is the one everybody else was shown. The mirror is run by the operator; it is a record, not an independent auditor.

## Provider keys

An ENROLL proof is only as good as the provider key it was checked against: a key the operator made up would let it mint accounts. So the verifier requires every provider key to be **witnessed** — seen in the provider's own published key list, in an Internet Archive snapshot of that list, or in the mirror's dated archive of keys. A key that only the operator's own files hold is a warning for 7 days and a failure after that.

## Rewinds

If the operator's database is lost or the log holds an entry the code should never have written, the only fix in an append-only log is to close the generation and start the next one from an earlier point: a **rewind**. It is a signed record in `index.json` that names the point `N` where the new generation forks, how far the old one had reached (`M`), and why. The new generation must start from the old one's exact first `N` entries — a rewind can drop entries, never rewrite them — and the verifier reports every rewind, with how many published and anchored entries it dropped, for the life of the log. Because a signature names its generation, the operator cannot re-add a chosen subset of the dropped votes afterwards.

## What the proof does and does not say

The ENROLL proof shows that a real provider account stands behind a pseudonym, and that one account has one pseudonym. It does not show that a different living person stands behind every pseudonym: someone with ten accounts has ten pseudonyms. The proof makes fake accounts cost real accounts; it does not make them impossible.

## Running the verifier

```text
npx @emojery/verifier                       # the quick check, seconds
npx @emojery/verifier --full                # replay everything from the first entry
npx @emojery/verifier --leaf <n> --pubkey <key> --counter <c>   # one vote of yours
npx @emojery/verifier --target github/khasky/emojery            # one target's count
```

- The **quick check** reads the current checkpoint, the newest anchor and the mirror, checks them against each other and against what the last run pinned, and pins the new anchor. It is what monitors run.
- **`--full`** replays the whole log: every entry, signature and proof, the tree, every count.
- **`--leaf`** checks one vote from its receipt (the extension's history shows it): the entry, its inclusion in the newest anchored checkpoint, and that it was signed by your device key with your counter. On an ENROLL entry it checks the registration's proof, so anyone can check that a pseudonym in the log stands for a real provider account.
- **`--target`** replays the log for one target and compares the result with the count the API serves, at the same log size. It reads the whole log, so it takes minutes at today's size and grows with the log.

A run ends in **PASS** (everything checks; notes may say what could not be read), **WAIT** (the log is behind on anchoring, or the mirror is out of reach) or **FAIL** (something read contradicts something else). An unreachable source is never a failure on its own.
