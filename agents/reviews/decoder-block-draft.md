# Complete decoder block — same-author skill review

Scope: Q26 / RFC-0004 A8 and RFC-0003 A3, both Draft. Author/reviewer codex-root
applies cqis-numerics, rfc-author and soundness-auditor; not independent audit.
Evidence: [block study](../../research/cqis-checkpoint/DECODER-BLOCK.md).

- Public items implement only research composition of A3/A6/A7, RFC-0021 and
  the proposed A8 gated path. No Draft behavior enters a core crate.
- Challenges/claims/ledger: none added. Numerical outputs are not proof claims;
  no private opening, lookup, sumcheck, FS or joint-ZK obligation is discharged.
- Bindings/controls: malformed and mismatched local scopes reject; legal altered
  source/cache values still require actual authentication. No catalog NC credit.
- Static arithmetic: exact product units survive; combined projection numerator
  is bounded below 2^68. Int32/int64 fit is never presented as field faithfulness.
- Review found missing whole-SiLU-table admission. The new failing test was
  followed by a static F>=E check and all 465 parameter-pair checks. The proved
  SiLU range tightens the gate product bound; wider down scaling remains separate.
- Padding/masks: only real rows; strictly ordered absolute positions and explicit
  causal masks. No padded-proof layout or batch/sequence authentication is claimed.
- Determinism: immutable ordered matrices/caches and fixed loops, exact arithmetic,
  typed bounded SiLU memo; no host float, timing-dependent selection or fallback.
- Parity: independent arithmetic, complete intermediate comparisons and full/cache
  checks. Shared certified table primitives are disclosed. No GPU code is touched.
- Costs: T_witness/c_a/c_x formulas and research allocations are explicit; no
  measured constant, performance result, proof weight pass or cut change.
- Verifier/format: production no_std code is unchanged. Canonical outer bytes,
  authenticated source roles and static schemas remain unresolved.
- Glossary and original task criteria are preserved; full inference is unfinished.

I tried to break it by changing each of the seven matrices behind an existing
cache, and the CacheScope control rejected it. I also supplied a non-total SiLU
configuration; after the fix, the Overflow control rejected it before execution.
