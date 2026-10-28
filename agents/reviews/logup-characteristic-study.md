# LogUp characteristic study review (Q31)

Reviewer: codex-root, also author. Same-author gkr-reduction-author,
soundness-auditor and rfc-author passes; no independent audit or approval of
a LogUp implementation. RFC-0008 A2 and RFC-0012 A8 stay Draft.

The p-copy failure holds as a rational identity, including extension challenges;
it does not rely on a rare denominator collision. The bounded-count proof uses
a nonzero bad-value residue, not range checking a prover's table coefficients.
Its tuple bound fixes one bad tuple before beta and excludes collision with
table tuples; collisions among lookup values cannot cancel positive counts
below p. The count and Boolean-selector hypotheses are essential.

Workflow 03 checklist:
- Public items: exact research arithmetic and Draft requirements; no core API.
- Challenges: exhaustive finite values, no native draw/label. Proposed unit or
  batching challenges require Accepted schedules/accounting before implementation.
- Claims/consumers: full fraction roots must reduce to actual selected sources
  and committed table multiplicities. No supplied root or study equality suffices.
- Bindings/controls: exact count, pole/padding and partition-cancellation examples,
  plus a sign mutant. No NC-0400..0403 or production lookup coverage credit.
- Ledger: no production loss or record changes. Conditional identity bounds
  exclude GKR/PCS/FS/ZK. Shared failures are not automatically squared.
- Static bounds: selected capacity is public and below char(K), not an observed
  count or |K|. Neither extension field raises the characteristic.
- Padding: neutral (0,1) is distinguished from (0,0); an actual selector consumer
  and pole policy are required before acceptance. No check may be skipped.
- Determinism: ordered exact finite enumeration and integer shape arithmetic;
  no dependency, floats, random seed or production mode introduced.
- Parity: F_9 exercises the extension obstruction; this is not Rust/Python proof
  parity or GPU evidence. Native lookup remains a scaffold.
- Cost: partition/multiplicity counts are exact shapes, not benchmarks; table,
  commitment, tree, consumer and peak-state costs remain unmeasured.
- Verifier: no core/no_std change. All count/unit/root/selector/plan bindings
  need the real consumer, canonical bytes, typed errors and resource bounds.
- Glossary: existing lookup, selector, multiplicity and claim terminology.

I tried to break it by replacing the parent numerator's addition with subtraction,
and the control check_tree rejected the isolated sign mutant against independently
summed inverses. The exact study and local RFC status, docs links, glossary,
CI-scope and diff checks pass; hosted full gates remain required before merge.
