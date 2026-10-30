# RMSNorm reciprocal-product review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is a same-author review, not independent audit.
[Evidence and scope](../../research/cqis-bounds/NORM-PRODUCT.md).

- Public items: Draft RFC-0004 A3 research for the existing RFC-0021/RFC-0022
  norm product. No Accepted role, cut, native field API or profile changes.
- Challenges: expected function/role bytes, all six roots and five complete
  child states precede the parent's weights, rounds and finals. The scalar
  reciprocal join adds no challenge; it hashes the actual verified offset
  reconstruction in the same canonical-u32 representation as rsqrt.
- Claims: five complete wide-range consumers check actual source bytes,
  complements, carries and endpoints. All seven parent originals remain
  consumed, including zero-hidden J views and high output/carry columns.
- Bindings: tests precede implementation and cover changed roots, fresh false
  products/carries, an alias separated by p, altered originals that preserve
  the final relation, zero-hidden reciprocal substitutions and explicit
  padding/cap attacks. All 16 matrix proofs and all controls passed, with no
  verifier or rejection-reason repair. The full-row proof remains in progress.
- Ledger: five separate lookup identities and reductions retain dimensions
  a+3,2,a+4,a+4,a+2. A3 is 39a+85; each nonlookup label has 17a+36 draws.
  Full-row values are 631 and 274, respectively. Runtime account assertions
  passed in all 16 matrix proofs; full-row evidence remains pending.
- Bounds: closed product caps give maximum side 81663 with 2*81663<p.
  xy and t have whole bounds 2^30 and 2^44. Actual offset bytes in [0,8192]
  reconstruct J in [8192,16384] by integer arithmetic before root comparison.
  No centered whole-value field equality or caller certificate is trusted.
- Padding: whole-value ranges keep all eight output planes; two are zero.
  C0 and C6..C8 are fixed public zero. The fourth wide-carry plane and all
  padded row slots have zero caps in their actual range consumers.
- Determinism: fixed child/plane/row order, exact integer arithmetic and full
  expected function bytes. The 10000-case NumPy int64 corpus passed and its
  hash is frozen. The complete 16-proof matrix hash is also frozen.
- Parity: no native CPU/SIMD/CUDA change. This revealing prototype still
  retains full rsqrt membership and actual xy proof composition. Both actual
  source joins passed, and a different reciprocal rejected its pinned root.
  Neither a reciprocal range nor a plaintext product earns that credit.
- Costs: O(N) source/range/view/A3 work in c_a/c_lu/c_sc/T_misc, including the
  padded carry plane. No per-element proof loop, extra weight pass or benchmark.
- Verifier: native no_std unchanged. Expected metadata and resource limits
  precede proof access; exact proof keys, canonical fields, roots and finals
  are checked. The full row stays within 131072 word-byte cells per range.
- Glossary/history: append-only Draft/accounting evidence; original task
  status, sign/zero predicates, output branches, physical ownership, privacy
  and fidelity requirements remain open. Required local gates are pending.

I tried to break it by supplying an offset of 8193 under the expected cap
8192, and the control Offset:CapRelation:RoundSumMismatch rejected it at the
actual cap consumer. All other controls passed; the full-row proof is pending.
