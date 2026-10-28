# RFC-0006 A5 review

Reviewer: codex-root, also the author. Same-author soundness-auditor, rfc-author
and stele-sumcheck owner / sumcheck-prover-engineer passes; not independent audit.
Scope: accept the prover-only contract after required gates and merge. Production
E3-04 implementation, controls, seeded parity and measured memory remain open.

I tried to break it by truncating one unused original value before the candidate
small prover, and the control ClaimMismatch rejected it in both fields. This uses
the research Python A1 public consumer, asserts exactly one changed final value,
and earns no production NC-0204 credit. The original table and instance stay fixed.

Workflow 03 checklist:
- Public items: A5 defines typed optimization eligibility and the prover strategy
  boundary. A1 statements, proof encodings and verifier API remain unchanged.
- Challenges: Instance precedes the first round; every full A1 Round precedes its
  one Sumcheck challenge; Final includes every original value before continuation.
  The grid folds in full K, never M31. Fixed interpolation nodes are distinct;
  no random-value inversion or retry is introduced.
- Claims/consumers: prefix materialization and tail folding return the original
  tensor MLEs at the ordinary A1 point, including unused inputs. Existing actual
  reduction/PCS consumers remain mandatory; the research public adapter closes all.
- Bindings/controls: original-value binding is unchanged. The specified NC-0204
  will require a real Small-produced artifact and actual public verifier rejection;
  constructor errors alone cannot satisfy it. Catalog status remains todo.
- Ledger: inherited A1 SC m*delta/p^d, d=4/8, with identical challenge/absorb counts.
  No new label or error family. Existing accounting gate remains required; Q12,
  PCS, composition, masks and profile certification remain separate.
- Certificates: signed/unsigned storage implies static magnitude bounds; it is
  not a witness-derived maximum or a proof of range. Internal M31 arithmetic is
  field arithmetic. CQIS integer identities still need their own static certificates.
- Padding/masks: no new padding convention. A1 tables remain exact 2^m shapes;
  K-valued masked data cannot claim eligibility from its unmasked source.
- Determinism: fixed node/term/axis order; parity proof uses distributivity and
  unique interpolation. k selects internal work only, not transcript bytes.
- Parity: 70 both-field algebra cases, two grid builders, full public consumption
  and continuations, plus 500 grid-expansion comparisons. k=0/1 research edges are
  outside the production constructor. Production 1,000 cases per degree/field,
  cross-language decisions and controls are still required; no GPU change.
- Costs: c_sc/T_misc and complete memory are identified symbolically. The simple
  builder handles constants by their exact suffix multiplicity and retains no
  per-term family of grids. No benchmark number or fitted constant is changed.
- Verifier: existing no_std verifier and its length/error handling are unchanged.
  The future constructor must check dimensions, cached instance and allocation
  widths before use; the static type is not an authenticated input claim.
- Glossary: original claims and distinct certificate/range obligations retained;
  no intermediate commitment or unaccounted reduction is introduced.

Formal finding: every monomial's prefix grid lies in M31, its embedding commutes
with arithmetic, and arbitrary K coefficients can be applied after the suffix
sum. Tensor-product interpolation yields exactly the same round polynomial.
Direct prefix MLE evaluation yields the same tail state and final claims. This
is deterministic equivalence, not a new probabilistic soundness theorem.

Sign-off: approve A5's contract for gated merge, with E3-04 ready for implementation
after acceptance. Do not mark E3-04 complete or credit NC-0204 from this study.
