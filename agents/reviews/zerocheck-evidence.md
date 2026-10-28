# E3-03 acceptance evidence

Reviewer: codex-root, also the author. Same-author soundness-auditor,
sumcheck-prover-engineer and benchmark-runner passes; not independent audit.
Scope: measured ledgers and task completion on merge after required gates pass.

I tried to break it by changing one unused original slice final, and the control
ClaimMismatch rejected it (NC-0209). The same production controls/accounting gates
preceded both recorded field runs; all measured proofs passed public consumption.

Acceptance mapping:
- Reference parity: both named tests execute 1,000 cases per degree/field, 10,000
  total; every eligible shape through m=4 plus maximum skip with a tail at m=5.
- c_sc improvement: both ledgers show lower aggregate k=1 dense prover cost than
  k=0 for degrees 1..4; complete prover+consumer costs also decrease in aggregate.
  Some OM31 individual samples lose; these are observations, not confidence bounds.
- Both modes: eq-only and skips 1/2/4 measured; all eligible k through 4 tested.
- Cross-language evidence: 130 fixed bytes/claims/records/continuations and 314
  shared public decisions; every original claim is consumed, including unused inputs.
- Controls: NC-0207..0209 and actual early-challenge/ZeroFinal NC-0800/0802 extensions.
- Registry/accounting: twelve entries, three ordered SC phases, descriptor checks;
  gate mutants reject wrong numerators, final labels, omitted consumers/claims and tests.
- Complete cost/memory: all 34 cases per field, three samples, original input and
  proof payloads, separate prove/consume timing, process peaks and conservative
  scratch bounds. Skip losses retained; no automatic k or fitted constant claimed.

Both records were produced from clean commit 4541fb8c77c3c99462a23999b09dfb85db07d98d.
Imports change whitespace only; parsed JSON equality with the original runner outputs
was asserted and both imported records pass stele-bench validation. Source metadata,
plan digest, samples, SC records, proof hashes and all numeric values are unchanged.
The benchmark reference is exhaustive, not a tuned linear-time baseline.

Workflow 03: no new public API/challenge/binding/certificate; final claims and
consumers unchanged; no padding/mask or GPU change; deterministic source/plan
capture and byte comparisons; exact SC records retained; core no_std unchanged;
c_sc/T_misc evidence is in bench/ledger, not a hand-edited cost-model fit; glossary unchanged.

Sign-off: approve E3-03 completion on successful gated merge of this evidence and
its prerequisites. This does not complete the MVP or certify a soundness profile.
