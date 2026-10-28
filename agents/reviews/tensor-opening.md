# Q27 conditional tensor-opening review

Reviewer: codex-root, also the author; pcs-engineer, rfc-author, soundness-auditor.
Not an independent audit. Decision: retain Draft A3 and E4-03's block until the
native statement, arbitrary/batched modes and complete soundness contract exist.

- Public items/RFC: proximity.py supplies research arithmetic for RFC-0010 A3,
  not a production PCS API. The imported theorem is DP24 Theorem 2; the near/far
  query argument is separately proved in formal/tensor-opening.md.
- Challenges/absorbs: the lemma fixes W before independent uniform row draws,
  then u/b/v before independent uniform columns. Native Transcript labels,
  unbiased sampling and authenticated descriptors remain unimplemented.
- Claims/consumers: exact repetition-code checks consume the same folded word,
  proposed u and scalar equation. No external model/input, fused sumcheck B or
  production Merkle consumer is claimed. Fixed tensor points do not certify
  the required distribution; arbitrary/batched functionals remain requirements.
- Bindings/controls: toy checks reject an altered scalar, demonstrate a fixed-point
  misuse and late-row attack, and distinguish column distance from row distance.
  The late-row example keeps b=v=0 fixed, isolating the timing of u.
  These are research checks, not NC-0600/0601/0603/0605 completion or a full forgery.
- Ledger: no production error line changes. The conditional tensor and query
  terms are explicit; setup is charged once over the specified v2 universe.
  FS/H, source/extraction, other reductions and profile admission remain open.
- Certificates: exact integer N/D/e/q derive from checked code IDs and field;
  q is minimal for the fixed 130-bit miss target. All 72 sizes are checked in
  both extension fields. No runtime integer-bound certificate is introduced.
- Padding/masks: R is exactly a power of two. No implicit padding, lookup or
  zerocheck changes. Canonical field-valued oracle interpretation is an explicit
  premise, not a conclusion inferred from a Merkle root.
- Determinism: rational/integer arithmetic only; the toy random generator has
  a fixed seed. Counter ties affect only cases with no unique near message;
  no tie changes the computed distance or far-case acceptance bound.
- Parity: 298 toy matrices enumerate all tensor points per case. Small query
  sequences and minimal q are independently checked. Native CPU/SIMD/CUDA
  proofs do not exist for this draft; no GPU change or parity claim.
- Cost model: query work/proof bytes and any added proximity work must be charged
  in the relevant verifier and T_misc/c_c terms. No measured constant, benchmark
  ledger or weight-pass change; exact query counts are not performance results.
- Verifier: production unchanged. Parameter arithmetic is not native admission;
  the gap may exceed a budget. Allocation, proof lengths and no_std consumers
  remain implementation requirements, along with multi-opening semantics.
- Glossary: distance, interleaved proximity, functional consistency and profile
  admission are kept distinct; both code catalog proven flags remain false.

I tried to break it by changing the claimed scalar while keeping the proposed row
fixed, and the control accepts rejected it through the scalar equation, including
with no column queries. The fixed-point and late-row counterexamples instead
succeed when their respective premises are removed, as the test requires.
