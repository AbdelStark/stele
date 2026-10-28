# E3-04 small-value engine review

Reviewer: codex-root, also the author. Same-author soundness-auditor and
sumcheck-prover-engineer passes, not independent audit. Scope: RFC-0006 A5's
initial typed strategy and actual NC-0204; E3-04 remains in progress.

I tried to break it by truncating an unused original value of 65536 to zero
in the actual Small strategy, and the control NC-0204 rejected it with
ClaimMismatch. Both fields preserve all rounds and change exactly one final.
The honest Dense proof passes the same unchanged public consumer first.

Workflow 03 checklist:
- Public items: Small, SmallTable and InvalidSmallValue implement RFC-0006 A5.
  Structural Instance/Term equality prevents reuse of a cached grid for a different
  polynomial, shape, identity or claimed sum. Dense's internal tail constructor
  checks every table dimension and is not a verifier entry point.
- Challenges: unchanged A1 Instance, then Round before each Sumcheck challenge,
  then Final; the strategy receives K challenges and never draws or narrows them.
- Claims/consumers: direct prefix eq-dot materializes every original input,
  including unused ones. A1's public eq-dot consumes every final at its derived
  point; other callers still owe the original reduction/PCS obligations.
- Bindings: NC-0204 checks original-value binding with actual Small misuse.
  Constructor failures are separate directed tests and earn no control credit.
- Ledger: unchanged SC m*delta/p^d, d=4 or 8, no new transcript labels or losses.
  Both accounting/control gates require both field tests and NC-0204; a regression
  removes the OM31 test name and requires rejection rather than an empty success.
- Certificates: typed representation establishes eligibility only; modular M31
  products are not no-wrap integer identities or authenticated range proofs.
- Padding/masks: no new selector, commitment or masking rule. K-valued masked
  tables cannot enter this typed interface merely because their source was small.
- Determinism: ordered monomial/factor/suffix/MSB-axis loops; fixed interpolation
  nodes, full K folding, constants and conservative zero-coefficient degree.
- Parity: directed degrees 0..4, k=2..4, with/without tail, both fields,
  signed/unsigned extrema, extension coefficients, constants and unused inputs;
  proof equality and continuation, plus zero/one folds. No GPU change.
- Costs: A5 moves c_sc/T_misc via M31 prefix grids, 16-bit retained inputs and
  a*N/2^k K tail; construction/transition capacities must be counted. No measured
  speed or memory improvement is claimed in this implementation PR.
- Verifier: unchanged no_std consumer. Constructor validates before indexing;
  k<=4 and degree<=4 bound grid products; checked address shifts and fallible
  allocation. As required by Error's contract, abort after any strategy error.
- Glossary: existing names; optimization eligibility is distinct from a proof
  of range, and successful reduction verification remains conditional.

Sign-off: approve this implementation slice conditional on required gates. The
1,000 seeded cases per degree/field, independent Rust/Python decisions and actual
complete-cost/memory ledgers remain mandatory before E3-04 can be done. Q12,
full inference composition, PCS and ZK/profile accounting remain unresolved.
