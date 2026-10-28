# Commitment privacy study review (Q29)

Reviewer: codex-root, also author. Same-author pcs-engineer, soundness-auditor
and rfc-author passes, not independent review or approval of a ZK protocol.
RFC-0013 A1 / RFC-0010 A7 / RFC-0011 A1 remain Draft. The original complete
privacy, source binding, native controls, one-pass and <=5% criteria remain.

The literal appended-row column leak follows by projection onto the original
rows. It is not a hash collision or fixed-root witness-indistinguishability
experiment. The rank lemma proves exact privacy for fixed linear views and
uniform masks, with explicit restrictions for public outputs and secret sets.
Adaptive challenges, commitments, paths and a full simulator are not supplied.
The extension example and lifetime attacks expose distinct additional failures;
the functional correction is necessary for honest completeness and claim binding.

Workflow 03 checklist:
- Public items: research helpers and Draft replacement requirements only.
- Challenges: deterministic test enumeration; no Transcript label or native draw.
- Claims/consumers: the masked functional must be connected to the original claim;
  source/range/phase/PCS/hidden-claim consumers remain required, not implemented.
- Bindings/controls: exact distribution/rank, visible-column, extension support,
  changed functional and reuse diagnostics. No NC-0604/0900/0901 credit.
- Ledger: no production record or loss changes. The human note distinguishes the
  uninstantiated MASK entry from a ZK theorem. Privacy errors and soundness errors
  require separate derivations; presence of a mask flag does not establish either.
- Static bounds: no new integer proof identity or bound-certificate consumer.
  Polynomial degrees/mask dimensions are fixed public integers in the example.
- Padding: no production layout change; systematic message positions are explicitly
  excluded from the positive example's private query set and tested as leaking.
- Determinism: exact integer/Fraction arithmetic and ordered exhaustive domains;
  secret mask independence is not inferred from different deterministic digests.
- Parity: independent Python Circle realization of the Accepted map, not new
  Rust/Python proof-byte or GPU parity; no native ZK path exists yet.
- Cost: entropy, dimensions/rate, lifetime queries, source reads and retained state
  need complete native ledgers. No overhead measurement or fitted constant supplied.
- Verifier: no core/no_std change. No helper or supplied rank result is verifier
  authority. A complete canonical format and privacy-aware consumer remain open.
- Glossary: existing source, claim, functional opening, mask and passport terms.

I tried to break it by checking only a view's first coordinate, omitting the
vanishing factor and reusing one coefficient in a two-mask polynomial, and the
control check_rank_criterion or check_randomized_rows rejected each isolated
implementation mutant. These detect errors in the study, not production attacks.
The exact full study, RFC status, docs links, glossary, CI-scope and diff checks
pass. Hosted CI remains required before merge. The cited primary sources were
checked for their actual mechanisms; neither is imported or treated as a Stele
simulator or a proof of its overhead target.

Delivery bookkeeping: PR #87 merged after exact-head run 40718840222 succeeded,
including the gates and SIMD throughput jobs. The merged tree matched its tested
head a94cb9a. This completes E3-06a's public coefficient delivery criteria.
E3-06's stacked runtime and every original private source/stage obligation remain
blocked on A4; this arithmetic delivery does not supply NC-0203 or full inference.
