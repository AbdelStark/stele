# Private selection research review (Q20 / E3-06)

Reviewer: codex-root, also author. Same-author gkr-reduction-author and
soundness-auditor passes; not independent audit. Recommendation: continue Q20;
RFC-0006 A4 remains Draft and E3-06 retains its original acceptance criteria.

Workflow 03 checklist:
- Public items: research only; no Accepted core API or production descriptor.
  Expected shape/query/value are separate from the proof. Source/view identities
  and a complete production byte grammar remain required before implementation.
- Challenges: a*M A1 Sumcheck draws, always after their round messages. No new
  draw kind or RLC. Evaluation precedes the instances; all A1 Finals precede the
  next instance, and Originals precedes any continuation. Labels are research-only.
- Claims/consumers: every public coefficient is independently checked, every
  internal child reaches one node/leaf consumer, and every original bit claim
  reaches the exact original-source oracle, including zero-coefficient originals.
  Points remain in MSB row order. Actual private consumers are still missing.
- Bindings/controls: no production edge or catalog credit. A one-value original
  mutation can pass the conditional reduction and is rejected by the reference
  original consumer. Production NC-0203 and source/bit/range/PCS controls remain.
- Ledger: candidate SC records are one (a,2) and M-1 (a,3), totaling a*(3M-1)/|K|.
  Every record/id/degree/field is checked. The candidate accounting paragraph
  preserves all missing source/range/PCS/FS/H/ZK terms and profile restrictions.
- Bounds: field-only relation, conditional on actual canonical source bits and
  I<C. No integer packing proof or field-faithfulness certificate is supplied.
  The 0/p alias and padded-category example show why those obligations matter.
- Padding/masks: initial A is the MLE of validity times Boolean equality weights;
  it is not a product of separate MLEs. Padded bit rows are zero, affine factor
  rows are 1-s_j, and unused product leaves are one. None is silently omitted.
- Determinism: fixed heap/bit order, MSB coordinates, exact fields, seeded corpus,
  fixed-width statement framing and checked continuation in both fields.
- Parity: 1000 algebra comparisons and 134 reductions per field, original claims,
  records, widths through 63, malformed inputs and exact rejection reasons.
  No native CPU/SIMD/GPU protocol or private-proof parity is claimed.
- Cost: O(N*M) preparation/proving, O(a*M+k) conditional verification and explicit
  O(n*a*k) reference consumption. Prepared cells and exact proof elements are
  accounted; scratch, metadata and private consumption are additional. No benchmark.
- Verifier: Python research with bounded dimensions/list counts; no no_std or
  native resource-admission claim. A full private resolver and parser remain open.
- Glossary/privacy: public coefficient, original claim and conditional reduction
  keep distinct meanings. One-row unmasked originals reveal the index; the study
  is not a simulator or a completed ZK construction.

I tried to break it by changing one zero-coefficient original, and the control
in `check_private_selection.py` rejected it as OriginalSourceMismatch after
conditional replay accepted. Changed padding/public finals and an omitted
Originals absorb also reject for their stated reasons. These are research checks,
not actual prover/verifier catalog controls or private source authentication.
