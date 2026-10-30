# Strict RMSNorm remainder — same-author review

Codex-root applies cqis-numerics, gkr-reduction-author, rfc-author and
soundness-auditor. This is not independent audit. [Evidence](../../research/cqis-bounds/NORM-REMAINDER.md).

- Public items: RFC-0021 §2.3 strict remainder and RFC-0022 §2.3 bounds,
  under Draft RFC-0004 A3. Configured D and MD/A origins require composition.
- Challenges: full expected norm bytes, six roots and three verified range
  states precede carry Boolean, terminal and strict-column A3s in that order.
  All child source/lookup/round/final absorbs remain. Parent draws8 weights and
  8 rounds; no outside challenge, retry, supplied bound or dynamic cap.
- Claims: actual ranged words reconstruct full16-slot D/R roots; gap root and
  carry root bind before parent challenges. All seven parent claims consume
  actual byte/carry/shift views at the actual emitted points. Children retain
  every lookup/source/cap/carry/terminal and original/public consumer.
- Bindings: genuine ranged R=D, D=0 and R=p,D=1 all fail strict columns.
  Non-Boolean carry and terminal1 fail their named consumers; preserving the
  final column composition while altering R/G claims fails the original-value
  consumer. Stale gap/source, high external slots and malformed values reject.
  Actual paired A/D, M/MD, sum and strict proof composition passed; valid changed
  R or D proofs cannot replace the independently pinned roots.
- Ledger: inherited7bD+14bR plus parent20 A3 numerator; separate lookup
  dimensions bD+1,bR+1,bR+1 and their repeated identities/reductions. Full
  nonlookup draws3bD+6bR+8 per label. Main matrix checks exact accounts/draws;
  all20 proofs passed. Accounting and required local gates passed; no profile certified.
- Bounds: Dmax is static from complete expected parameters. Each scalar width
  is derived separately, preserving power-of256 transitions. Actual bytes and
  Boolean carries bound both column sides by511;2*511<p. Integer summation
  with fixed c0=1,c16=0 supplies strict R<D and D>0 without a whole-field lift.
- Padding: all16 external slots, carry words and columns remain. Source range
  widths zero-extend independently; high roots cannot be replaced by prefixes.
- Determinism: canonical complete norm bytes and fixed three-child/A3 order;
  exact integer shifts and NumPy integer additions. No floats or timing order.
- Parity: native CPU/SIMD/CUDA unchanged; revealing full field/repetition matrix,
  10000-case corpus and all controls/composition passed.
- Costs: three full scalar range consumers and fixed16-column A3s in c_a/c_sc/
  c_lu/T_misc. No benchmark claim, measured constant or added weight pass.
- Verifier: native no_std unchanged; expected metadata precedes bounded shapes.
  Canonical fields/roots/rounds are checked before use; producer gap arithmetic
  does not confer acceptance. No verifier or expected-reason repair was needed.
- Glossary/history: append-only Draft/accounting evidence and original blocked
  acceptance criteria; no Accepted role, public-MLE kind, native NC/cut credit.

I tried to break it by supplying genuine range proofs for R=D with zero gap,
and the control StrictColumns:RoundSumMismatch rejected it.
