# Private coefficient stage — same-author skill review

Scope: Q20 / Draft RFC-0006 A4 research. Author and reviewer: codex-root using
gkr-reduction-author and soundness-auditor; this is not an independent audit.
Evidence: [composition study](../../research/stacked-gkr/PRIVATE-STAGE.md).

- RFC/public items: the research wrapper consumes the real stacked A1 coefficient
  final through weighted selection. Accepted core behavior is unchanged; A4,
  production source interfaces and full global plan validation remain unresolved.
- Challenges: PrivateStack precedes stage Instance/Round/Sumcheck/Final; Weighted
  receives the actual canonical point and final value after Final. Its A1 tree
  and Originals precede continuation. No additional draw kind or RLC appears.
- Claims: the A final reaches weighted selection, all original tensor finals
  reach their fixed reference tables, and all bit claims reach the independently
  checked original source view. Empty/zero polynomials do not discard finals.
  The conditional receipt remains unaccepted without the real private consumers.
- Bindings/controls: wrong-layer and draw-order unused finals fail ClaimMismatch;
  a wrong-coordinate child or missing PrivateStack fails FinalEvaluationMismatch.
  Closed metadata excludes values and rejects aliases/view mismatch. These
  research checks supply no production NC or source-authentication credit.
- Ledger: m+a*M existing draws, conditional numerator m*delta+a*(3M-1), records
  retained by stage/selection scope. Stage ids reserve disjoint aligned 65-id
  blocks; every actual node id is checked and overflow rejects before replay.
  Internal virtual-table ordinals still require the production tensor namespace.
  The accounting paragraph adds no certified
  private-source, FS/H or ZK claim. The accounting gate must pass before publication.
- Certificates: no integer inference identity or static bound is admitted.
  Prover source preparation does not establish verifier bit/range/packing validity.
- Padding: originals are zero padded, A excludes every invalid axis coordinate,
  and source bit planes preserve grid holes. Both canonical and elimination
  coordinates are exercised against independent consumers.
- Determinism: fixed input/term/source/heap order and exact frames; seeded both-field
  proofs, accounting and continuation agree. Existing weighted/legacy corpus
  hashes are unchanged. A shared header preserves the public descriptor grammar.
- Parity: no native/GPU code changes or CPU/SIMD/CUDA proof-parity claim.
- Costs: dense A construction, input validation, reordered copies, nested scratch,
  proof size, metadata and actual consumers are charged explicitly. Separate caps
  are not a total-memory limit; no measured constant or benchmark changes.
- Verifier: no production no_std path changes. Closed count/axis limits and
  source-id separation apply; this is not a production parser or alias schema.
- Glossary: existing claim/source/coefficient vocabulary is retained; link and
  glossary gates must pass. No independent audit or complete inference is claimed.

I tried to break it by changing one unused original final to the wrong layer,
and the control rejected it with ClaimMismatch at the actual reference consumer.
I also reproved a child at draw-order coordinates and omitted PrivateStack before
a successor; unchanged verification rejected both with FinalEvaluationMismatch.
