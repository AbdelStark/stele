# Typed selection source — same-author skill review

Scope: Q20 / Draft RFC-0006 A4. Author/reviewer: codex-root, applying
gkr-reduction-author, pcs-engineer and soundness-auditor; not independent audit.
Evidence: [source study](../../research/stacked-gkr/SELECTION-SOURCE.md).

- RFC/public items: research representation of the already named index cut;
  no Accepted format or new committed tensor. Virtual range/mask tables stay virtual.
- Challenges: Source precedes A3 Zero/ZeroWeight/round/ZeroFinal; range A1 nodes
  follow the actual root final. Every final precedes its successor. Exact label
  counts are checked; there is no added challenge kind, RLC or resampling.
- Claims: public masks/equality values are recomputed. Every F/bit-view claim
  reaches the same fixed original tensor, including unused and zero-mask finals.
  The terminal range leaf is zero. A conditional receipt alone is not admission.
- Bindings/controls: false Boolean/range/padding sources, changed masks/constant
  leaves, a false unused F final, source scope substitution, 0/p alias and omitted
  Source are checked against actual reference consumers. No catalog NC credit.
- Ledger: A3 phase records and all A1 nodes are retained. Numerator 7D, plus
  3a(k+1) for C<2^k; 4D plus a(k+2) draws. Stage, PCS/batching, FS/H and ZK
  costs/losses remain additional. The accounting gate is required before publication.
- Certificates: Boolean logic gives injective integer interpretation without a
  wide field recombination. No accepted CQIS bound-record schema is introduced.
- Padding: validity masks exclude source holes and unused planes from bitness;
  a separate relation enforces zero there. The range root masks padded rows.
  k=0 has one canonical zero dummy plane, not an unconstrained source.
- Determinism: fixed plane/axis/chain order, canonical bytes, exact instance and
  virtual-tensor ranges. The folded prover agrees with the exhaustive A3 oracle;
  existing vectors and stage/selection corpora remain unchanged.
- Parity: no native/GPU change or CPU/SIMD/CUDA proof-parity claim.
- Costs: source expansion, conversion, folds, range chains, original openings,
  proof elements and prepared/scratch memory are separate. The 16-fold message
  example is a size formula, not a benchmark or a default-layout recommendation.
- Verifier: production no_std code is untouched. Closed metadata/count limits,
  u64 block checks and stage linkage apply; actual private PCS, complete plan
  identity validation and proof-byte/resource admission remain unresolved.
- Glossary: claim, source, range and coefficient retain their existing meanings;
  no private authentication, masking or full inference is claimed.

I tried to break it by substituting index 0 for a field-congruent p source, and
the control rejected it with SourceClaimMismatch at the actual original consumer.
I also altered an unused zero-mask final and omitted Source before a successor;
the original consumer and unchanged successor verifier rejected them respectively.
