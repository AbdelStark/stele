# Native RMSNorm numerical review (E5-02)

Reviewer: codex-root, also author; same-author cqis-numerics and soundness-auditor
passes, not independent audit. RFC-0021 §2.3,§6 / RFC-0004 A4. This supplies
function-level numerical parity; static certificates, full forward inference,
int8 conversion and actual norm proof consumers remain E5-03/E5-04/E7 work.

Workflow 03 checklist:
- Public items: Descriptor::evaluate_rmsnorm, private immutable NormEvaluation
  and explicit NormError. Only an already checked rmsnorm_q descriptor applies;
  caller-supplied table truth or a raw generated-result constructor is absent.
- Challenges: none. The deterministic corpus generator is test-only, not FS.
- Claims/consumers: exact integer outputs and normalization statistics only.
  No source authentication, field identity, membership or certificate admission.
- Bindings/controls: no claim-graph edge or NC credit. NC-0105/0109 and all
  reduction bindings still need actual consumers under Workflow 08.
- Ledger: no challenge, label, loss or profile change; accounting gate retained.
- Bounds: d<=2^14 and signed-int16 inputs imply S<=2^44, N<2^107, P<2^106.
  The initial bit-length exponent gives 2^13<A/D<2^16. When a<0 this implies
  A<2^16*P<2^122; for a>=0, A=N and D<2^124. The one correction multiplies
  A/D by four only below 2^14, retaining the bound. Positive epsilon and input
  ranges give 2^-32<q<2^33, hence a in [-23,9]. Exact u128 suffices; checked
  multiplication by a power of two detects discarded bits, unlike checked_shl
  alone. |T|<=2^44 and shifts [-16,90] fit the checked wide rounding arithmetic.
  These are native arithmetic bounds, not reduction field-faithfulness schemas.
- Padding: exact d is required; normalization M is a real rsqrt row. A=M*D+R
  retains 0<=R<D. No table padding, mask or lookup selector is silently enforced.
- Determinism: ordered integer sum, Euclidean floor for negative exponents,
  certified fixed-table helper, one final signed half-away rounding or exact
  left shift. No double rounding, scalar Requant reuse, floats or backend choice.
- Parity: 11,000 full rows compare with independent rational normalization/root
  arithmetic and NumPy int64 table gathers/rounding. 10,889 succeed and 111
  reject overflow. First 10,000 use scales bounded to succeed; additional cases
  cover unrestricted scales. Maximum d, epsilon extremes, zero rows, remainders,
  signed endpoints, negative shifts and a shift of 89 also have direct tests.
- Cost: O(d) integer work, one O(d) output allocation and bounded scalar state in
  numerical preparation/T_misc; future norm relation/range work remains c_a.
  No fitted constant, performance claim, additional weight pass or commitment.
- Verifier: no_std/no unsafe/no new dependency. Output capacity is reserved
  fallibly before filling; failure drops the prefix and preserves borrowed inputs.
- Glossary: numerical generation is distinct from full inference and proof acceptance.

I tried to break it with wrong descriptor kinds, inconsistent lengths, a late
output overflow and overflowing capacity/shift helpers, and the control checks
in rmsnorm.rs and norm_row.rs rejected it with the specified primitive errors.
No production NC coverage follows. Exact-head CI and all local standard gates
remain mandatory, including the inherited full public-table MLE parity gate.
