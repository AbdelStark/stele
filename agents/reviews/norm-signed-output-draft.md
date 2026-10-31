# Signed-output review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Scope and evidence](../../research/cqis-bounds/NORM-SIGNED-OUTPUT.md).

- Public items: revealing Draft RFC-0004 A3 research for RFC-0022 §2.3's
  signed output. No Accepted cut, role or profile changes.
- Challenges: the complete expected function bytes, six external roots and
  both verified child states precede parent weights, rounds and finals.
  Both children retain every existing range, lookup and A3 transcript.
  Parent degree is two; q=0 never gates child verification or a challenge.
- Claims: all three originals q,s,sy have separate consumers at their emitted
  points. Changing s or sy when q=0, or q when s=sy, rejects ClaimMismatch.
  Changing both sign finals together also rejects their original consumers.
- Bindings: all six expected-root mutations rejected their named consumers.
  A valid signed Y with the wrong nonzero sign rejects SignedOutput.
  At rounded zero, false product sign and false nonzero predicate reject
  inside ProductSign; a false signed-Y magnitude rejects Output:Positive.
  Actual product/left/division proofs share xy, t and q roots in composition.
- Ledger: inherited A3 numerator131a+148 plus43a+35 and parent3a gives
  177a+183. Each nonlookup label has74a+75 draws. Ordered lookup dimensions
  are six(a+2), four(a+3), three(a+2), each retaining its separate identity
  and unsquared reduction. All16 complete matrix receipts and draw counts
  agree; their digest is frozen. The maximum proof and accounting gate remain
  pending.
- Bounds: verified q<=32768 and Boolean s/sy bound each nonnegative parent
  side by32768<p/2. Actual two-byte magnitude and verified flag planes
  determine every view. No observed bound or supplied certificate is used.
- Padding: both complete signed-source children enforce canonical raw,
  magnitude and sign zeros. Product predicates remain checked on padding.
  Fresh false padded raw/magnitude/sign witnesses reject CapRelation.
  Parent views include every padded position with expected zero values.
- Determinism: fixed role and child order, canonical function bytes and
  integer views. The10000-case NumPy corpus is frozen. Namespace endpoints
  and disjoint child spans passed static boundary checks; no retry exists.
- Parity: native CPU/SIMD/CUDA unchanged. NumPy int64 signed-source/view
  checks are research evidence. Boundary and actual left/division composition
  passed; complete configured branch selection remains separate.
- Costs: O(N) views and one degree-two parent A3, plus complete child range,
  hash and independent MLE consumers in c_a/c_sc/c_lu/T_misc. No benchmark,
  measured constant, per-row proof loop or additional weight pass is claimed.
- Verifier: native no_std unchanged. Expected schema derives dimensions and
  namespaces before payloads. Proof keys, roots, parent shapes and canonical
  field tuples are strict. Acceptance never calls a plaintext sign predicate;
  it verifies the complete children and their actual derived source views.
- Glossary/history: append-only Draft/accounting evidence; original blocked
  criteria remain. Configured rounding, normalization, native/model/private
  inference and fidelity remain open. Required local gates passed; hosted CI remains pending.

I tried to break it by changing the canonical product sign when a negative
product rounded to zero, and the control ProductSign:Sign:RoundSumMismatch
rejected it before the zero output could hide the false sign.

Required local repository gates, including the accounting gate, passed.
Full-row proof evidence and hosted validation remain pending.
