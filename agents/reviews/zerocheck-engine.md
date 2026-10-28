# E3-03 zerocheck engine review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes, not independent audit. Scope: A3's dense engine,
public consumer and controls; broader corpus/reference and performance work remains.

I tried to break it by changing one unused slice final, and the control
ClaimMismatch rejected it. Skip and tail changes reject at their specified
checks; omitting ZeroFinal changes one A1 continuation final and rejects.
All variants use actual prover/verifier code and assert a one-value mutation.
The gate also rejects altered SC numerators, a changed final label and a bypassed
public consumer. Both fields match all 130 oracle descriptors, proofs, claims,
phased records and continuation challenges; these are finite checks, not a theorem.

Workflow 03 checklist:
- Public items: Zerocheck, Proof, Reduction implement RFC-0006 A3. Borrowed A1
  polynomial storage requires claimed_sum=0; A3 asserts every row is zero.
- Challenges: Zero then j ZeroWeight; optional ZeroSkip then Sumcheck; each
  weighted endpoint check and Round precede Sumcheck. No division by challenges.
- Claims/consumers: every original (Boolean prefix,tail point) claim survives;
  public eq-dot consumes all, other callers retain reduction/PCS obligations.
- Bindings: NC-0207/0208/0209 and the three skip variants of NC-0802 pass both fields.
- Ledger: three ordered SC records j,D,j*δ; actual bytes/records/continuations
  checked by both gates. Twelve fixed registry entries match the inventory.
- Certificates: field-only identities; integer/range certification remains external.
- Padding/masks: verifier plan owns them; no new intermediate commitment or ZK claim.
- Determinism: plan-fixed k, ordered term/input/slice vectors, leading tail folds.
- Parity: 130 Rust/Python honest cases; no GPU or 10^3-per-degree completion claim.
- Costs: dense algorithm and retained originals; c_sc and consumer benchmarks pending.
- Verifier: no_std; descriptor, all proof lengths and public shapes checked;
  checked size arithmetic/fallible allocations, canonical field types, abort on error.
- Glossary: existing terms; successful reduction verification is conditional.

Sign-off: approve the engine/controls with E3-03's remaining acceptance criteria
retained. Q12 and full composition/PCS/ZK/profile accounting remain unresolved.
