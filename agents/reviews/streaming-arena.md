# RFC-0006 A6 source/arena review

Reviewer: codex-root, also the author; sumcheck-prover-engineer and soundness-auditor.
Not an independent audit. Scope: generic source, explicit windows and canonical tail.

- Public items/RFC: Streaming, Source, workspace length/capacity and source metadata
  implement formal/streaming.md §§1–5. Summand identity validation runs before the
  first absorb in both engines, including m=0; existing strategies retain shape checks.
- Challenges/absorbs: no draws in the strategy. The existing engine absorbs every
  A1 round before folding its challenge, and all final values before continuation.
- Claims/consumer: all original inputs, including unused inputs, enter the tail;
  verify_public checks the same derived point against the original tables.
- Bindings/controls: no new verifier binding. Source is untrusted prover data;
  NC-0210 remains todo until the actual file/proof-artifact path is wired. Typed
  source errors and malformed/cached-instance tests do not substitute for NC-0210.
- Ledger: no new loss/challenge/label. Tests compare A1 numerator and continuation;
  existing accounting gates remain. Q12 and profile admission are unchanged.
- Certificates: no integer identity; checked dimensions and polynomial degree give
  resource bounds only. Allocation-free source methods are an implementation contract.
- Padding/masks: bit reversal is storage order only. Tail suffixes return to canonical
  order; a production gate mutant removes that reversal. No mask convention changes.
- Determinism: fixed schedule/row/node/factor order, full extension coefficients,
  scalar prefix equality weights and fixed interpolation scratch. Challenges 0/1 work.
- Parity: 1,000 seeded Dense/source cases per degree and field compare complete
  proofs, public consumers and continuation. No-input, m=0, empty/full/multiple
  windows and transition failures are included. No CUDA code or parity claim.
- Cost/capacity: one retained arena with checked full capacity; disjoint grid/block/
  row/value regions reuse storage at transitions. Tail compaction writes behind
  unread cells. A test executes with less work capacity than the dense inputs.
  Source/descriptor/proof/process costs remain separate; no measured speedup or
  total-memory claim, and no cost-model constant changes without a benchmark ledger.
- Verifier: unchanged no_std consumers. Source failures abort the attempt; later
  retries need a fresh transcript/state. Cached descriptors compare full Instance.
- Glossary: no new committed intermediate, authenticated source or profile claim.

I tried to break it by supplying extra source rows and changing the cached descriptor,
and the controls rejected them with Source and InvalidStreaming respectively.

Sign-off requires local and exact-head hosted gates. This partial E3-05 implementation
still needs the concrete file adapter, independent corpus, NC-0210 and complete ledgers.
