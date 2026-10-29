# Native exact GeLU review (E5-02)

Reviewer: codex-root, also author. Same-author cqis-numerics and soundness-auditor
passes; not independent audit. RFC-0021 §§2.2,3,4,6 / RFC-0004 A4.

Workflow 03 checklist:
- Public items: Table::activation now also generates the distinct gelu_q function.
  Integral, signed-partial and normal-tail helpers remain private. All registered
  component generator kinds are now implemented; E5-02's other criteria remain.
- Challenges: none; existing ordinary identities/framing are unchanged.
- Claims/consumers: deterministic integer rows only. No configured inference,
  membership, original-claim, passport, opening, privacy or profile is admitted.
- Bindings: no new claim-graph edge or NC coverage. Primitive tests reject changed
  entries/field aliases, overflowing tables and cross-variant table identities.
  NC-0412/0413/0414 remain pending their actual consumers.
- Ledger: no challenge/label/loss change. The rounding error remains the proved
  RFC half-output-unit bound, independent of samples or model fidelity.
- Bounds: integral denominators need <=31+512*(60+10+11) bits. With a<8, the
  sum of at most 513 term magnitudes is below 2^3086; thus even signed partial
  numerators, width cross-products and normalizer scaling stay below 100,000
  bits, inside the 2^18 scratch cap. Output magnitude is <=2^29 before int16
  checking. These are resource bounds, not reduction field certificates.
- Padding: 65,536 real rows in signed input order. Other table padding is
  unchanged; actual lookup selectors remain separate obligations.
- Determinism: exact term recurrence and signed partials; apply alternating
  bounds only after n>=a²/2, intersect with (0,a), stop at the specified rational
  width. For a>=8 use the strict Gaussian tail bound. Exact zero is a singleton;
  finite tails cannot become their limits. Normalizer constants are unchanged.
- Parity: one complete table, 10,000 varied valid inputs and 30 boundary cases
  match the independent positive-integral/pi oracle. NumPy int64 gathers match
  at 10,000 inputs. All four precision levels, the integral/tail transition,
  signed-partial cancellation, strict half-limit rounding and overflow are tested.
  Exact and tanh variants differ numerically and reject each other's identity.
- Cost: exact generation/scratch remain T_misc. No measured constant, benchmark,
  additional weight pass or committed intermediate is introduced.
- Verifier: no_std/no unsafe/no floats, fallible owned arithmetic, immutable
  generated tables, no partial result on failure. No new Rust dependency or
  callback granting authority over a table definition.
- Glossary: exact GeLU and tanh-GeLU remain distinct functions and identities.

Tests preceded implementation. I tried to break it by closing finite Gaussian
tails, crossing zero in signed partials, substituting tanh-GeLU data, changing a
row or field-congruent encoding, and overflowing outputs, and the control checks
in the native primitive tests rejected those inputs. They earn no NC credit.
Function/representation/manifest bytes, public MLEs and all actual lookup/private
PCS/ZK/inference deliveries remain required; E5-02 stays in progress.
