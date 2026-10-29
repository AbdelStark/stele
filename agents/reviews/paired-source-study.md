# Two-bit source — same-author skill review

Scope: Draft RFC-0006 A4 / Q20. Author/reviewer: codex-root, applying
gkr-reduction-author, pcs-engineer and soundness-auditor; not independent audit.
Evidence: [paired source](../../research/stacked-gkr/PAIRED-SOURCE.md).

- RFC/public items: research representation of the existing index cut; no
  accepted format or new committed intermediate. The bit tensor stays virtual.
- Challenges: PairedSource precedes optional unused-bit A3, then the original
  Source/core sequence and actual A1 resolvers. Finals precede successors.
  Exact challenge labels/order are checked; no new kind, RLC or resampling.
- Claims: every virtual bit claim has a degree-four consumer. Equality finals
  are recomputed; each remaining symbol claim maps to the same original source,
  including unused originals and both general and plane-restricted points.
- Controls: false symbols, spare/unused bits, grid holes, range, integer aliases,
  changed equality/original finals, source scope, missing frames and direct
  polynomial-at-MLE substitution reject. No production catalog credit.
- Ledger: retain all core/A3 phase records; add optional 3a and 4*sum(m_i),
  with optional 2a and sum(m_i) draws. Selection adds 4ak and ak draws.
  Actual openings, PCS/batching, FS/H and ZK losses remain required.
- Bounds: both derived bits are Boolean and P=2H+L holds identically, giving
  symbols 0..3. k<2 additionally constrains P to 0/2. No wide field recombination
  defines the integer. No Accepted CQIS certificate schema is introduced.
- Padding: both virtual bits enforce zero symbols in holes/unused planes;
  k=0/1 additionally enforces the absent low bit. Range uses the existing core.
- Determinism: fixed frames, term order, ids and point-derived plane choice.
  Zero leading coefficients retain degree four. Legacy core proof bytes are unchanged.
- Parity: no native/GPU changes or CPU/GPU proof-parity claim.
- Cost: message payload halves for k>=2; virtual preparation, absent-bit checks,
  bit-consumer proofs and original openings remain. Only two general claims
  scan the full symbol tensor; range/selection claims scan their source plane.
  Working memory does not halve. No benchmark or default-layout claim.
- Verifier: production no_std code unchanged; bounded metadata and disjoint
  namespace blocks are checked. Full plan/axis identity, private PCS, byte/parser
  resource admission and joint masking remain unresolved.
- Glossary: original claims, virtual views and conditional algebraic evidence
  are distinct; no private authentication, full inference or ZK is claimed.

I tried to break it by substituting high(MLE(P)) for MLE(high(P)), and the actual
sumcheck consumer rejected with RoundSumMismatch. A changed unused original
symbol final survived the algebra but failed SourceClaimMismatch at the real
reference consumer. Omitting only PairedSource changed an actual successor's
final and the unchanged verifier rejected it.
