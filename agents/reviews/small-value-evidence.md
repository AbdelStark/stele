# E3-04 acceptance evidence

Reviewer: codex-root, also the author. Same-author soundness-auditor,
sumcheck-prover-engineer and benchmark-runner passes; not independent audit.
Scope: actual ledgers and task completion on gated merge of all prerequisites.

I tried to break it by truncating an unused original value, and the control
NC-0204 rejected it with ClaimMismatch. Both field runs passed the actual
controls/accounting gates before measurement, and every produced proof passed
public consumption and continuation checks. No binding was disabled.

Acceptance mapping:
- NC-0204: actual Small misuse and unchanged original consumer in both fields,
  honest Dense baseline, exactly one changed unused final; constructor failures
  earn no control credit. Benchmark warmup tampering also rejects.
- Measured memory reduction: m=18 degree1 shows lower prover peak RSS for every
  Small k=2/3/4 versus Dense in both fields. This includes construction/transition
  overlap, allocator retention and original typed caller inputs. Complete native
  pipeline peak is consumer-dominated and does not materially decrease; no
  complete-pipeline memory improvement is claimed.
- Parity: 1,000 seeded cases per degree/field, 10,000 total, compare Small/Dense
  and direct original-MLE recomputation; actual public claims, SC and continuation.
  All supported small (m,k) through m=4 plus k=4 with a tail at m=5 appear.
- Boundaries: directed typed extrema, constructor k/count/shape/degree/capacity
  errors, cached-instance mismatch, constants/empty/unused inputs, zero coefficients,
  extension coefficients and zero/one folds. Fixture narrowing is checked.
- Independent decisions: 302 shared Rust/Python cases, 76 accepted chains and
  226 exact rejections, every original claim, SC record and A1 continuation;
  named tests, descriptor records, consumer and corpus mutations fail gates.
- Complete costs: 24 cases per field, three samples, one warmup and three measured
  proofs per case/sample. All 576 proofs are fully consumed. c_sc ns/point and
  prove+consume costs, typed/proof payloads and separate native worker RSS are
  recorded. m8 losses and individual losing samples are retained; no auto-k,
  significance, universal crossover or fitted constant claim.

Both ledgers come from clean commit 3a77a9d5a5996df63025efb81dc1e082a49d028c.
Parsed JSON equality with the original runner outputs was asserted on import;
only whitespace changed. Device/toolchain, plan digest, all samples, SC records,
proof/continuation hashes and every number are preserved. Required validation
checks both imported ledgers before publication/merge.

Workflow 03: no new API/challenge/binding/certificate; original claims and
consumers unchanged; no padding/mask or GPU change; deterministic source/plan
capture and byte parity; exact SC records retained; no_std core unchanged;
c_sc/T_misc observations live in bench/ledger, without changing global fitted
constants or weight-pass count; existing glossary and range-proof distinctions retained.

Sign-off: approve E3-04 completion on successful gated merge of this evidence
and its prerequisites. This does not complete the MVP, Q12, inference composition,
PCS/ZK work or profile certification.
