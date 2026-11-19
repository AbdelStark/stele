# E16-40k: one-shot qualification launcher review

Source: `0dd0818f562fc667f851f43b1e8d58ceab9e63bd`.
[Input manifest](e16-40k-qualification-pins.json) SHA-256:
`3b8e62a1843fbd11bc7941600a4c453165e13ef80d93c98364604953c5c65ac1`.

This is the one implementation/qualification campaign scoped by E16-40k, after
terminal diagnostic 6726 and independent candidate reviews. A candidate failure
must be retained and reported before any further optimization; no automatic retry.

## Spec / owning GPU

Reviewer `/root/qualification_launcher_spec_review`: **PASS to submit after the
Linux preflight**. The archive equals `git archive --prefix=source/` at the exact
candidate. Original inventory, seeds and storage modes are unchanged. Builds use
locked provisioning followed by frozen compilation from the archived directory.
The required preparation regression, complete masked-parity receipts and original
1,000-case CPU/GPU inventories cannot succeed by skipping CUDA or selecting zero
tests. All round polynomials, initial/folded tables and completed-case/campaign
digests must match. Watchdogs fail closed and clean up process groups. No finding.

## Standards / another lane

Reviewer `/root/qualification_launcher_standards_review`: **PASS to submit after
Linux preflight**. All 2,359 archive files match the candidate, with no unsafe
paths or links. The serial stages and immutable pins preserve campaign identity;
requeue is disabled. Reviewed validators and process cleanup are reused. No
hard-standard breach or actionable smell. Forged, duplicated, missing, skipped,
wrong-device, wrong-seed and incomplete inventory receipts were rejected.
No protocol, proof, verifier, challenge or commitment change.

## Preflight and limits

Both reviewers verified every manifest hash. Local Python 3.12.12 passed the
three parser/receipt controls, with three GNU-time/process controls explicitly
reserved for Linux. The target's Python 3.12.3 then passed **all six controls
with zero skips**, including case/campaign deadlines and cleanup of a
TERM-resistant descendant. Remote hashes and shell syntax also passed before
submission; retained log: `stele-validation/e16-40k-qualification-preflight.log`.

The campaign records cold setup, builds, command costs and raw receipts; these
are not yet a validated performance ledger. Full-proof parity, actual-size
coverage, complete device-memory accounting and ADR-127 GO remain unestablished.
Repository and intended-merge-tree gates remain required. This review approves
submission, not successful qualification or task completion.
