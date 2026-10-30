# Consumed RMSNorm canonical product sign (Q26 / Q31)

Research under Draft RFC-0004 A3 for RFC-0022 §2.3's explicit zero predicates
and product-sign requirement. This does not change Accepted semantics.

Question before implementation: can a complete xy consumer supply the same
actual signed X/H sources, with both zero predicates and a canonical product
sign enforced for every row element? Cost terms are c_a/c_lu/c_sc/T_misc for
linear range/view/A3 work. Kill the design if a zero magnitude can acquire a
nonzero predicate, a nonzero magnitude can acquire a zero predicate, a sign
substitution survives, padding is ignored, or output rounding is used to hide
a missing sign obligation.

Retain the complete xy proof, including its two signed-source consumers,
magnitude product, whole ranges and carry boundaries. From each verified pair
of magnitude bytes reconstruct m in [0,32768]. Introduce n in {0,1} and a
predecessor k in [0,32767], and enforce m=k+n and m*(1-n)=0. These force n=0
exactly when m=0, with k=0 there; otherwise n=1 and k=m-1. Range k as a whole
two-byte word. All bounds are static and the largest combined relation side
is at most 65536, strictly below p/2.

The signed-source proof already makes sx=0 when the X magnitude is zero, and
likewise for sy. Therefore the degree-two identity

    s = sx*ny + sy*nx - 2*sx*sy

is the input-sign XOR when both magnitudes are nonzero, and zero otherwise.
Range s as Boolean and retain all five original views. No quotient or rounded
output gates this relation. Its two nonnegative sides are at most 2 and 3.

For N=2^a padded rows, use one range with three N-element planes nx,ny,s,
padded to four planes, and one range with two predecessor planes. Real flag
caps are 1 and predecessor caps 32767; every padded row has cap zero. Both
lookups have dimension a+3 and at most 131072 selected bytes. Reconstruct the
external canonical-u32 sign root from the verified third flag plane, including
its padded zeros. It must match the expected root before parent verification.

Namespace: identity<2^42 and base=2^63+2^20*identity. The xy child identity
is 4*identity+1, occupying the second quarter of the parent span. Flag and
predecessor range identities are 16384*identity+1,+2; their sources are
base+1,+2. Parent A3 ids are 65536*identity+512,+513. Views use base+16..23.
Four distinct external ids stay outside the entire parent span. These choices
separate all inherited range/A3 invocations and internal tensor ids.

Combine the two predicate equations in one degree-two A3 over four N-element
planes using fixed zero views. A separate degree-two A3 over N rows checks
the canonical sign. All nine original claims are consumed at their emitted
points. Expected norm bytes, four external roots, two auxiliary roots and the
three verified child states precede parent weights, rounds and finals.

Before implementation: the inherited xy A3 numerator is 107a+108. New ranges
add 18a+34; parent predicates/sign add 6a+6. Total is 131a+148. Nonlookup
draws total 55a+61 of each label. Six inherited lookup dimensions are a+2;
the two remaining inherited and two new lookups have dimension a+3. For each
retain its separate identity ((2^m+255)/|K|)^r and reduction
r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. At a=14, the A3 numerator is
1982 and each nonlookup label has 831 draws. Runtime receipts must verify this.

Tests precede implementation: 10000 independent NumPy integer sign/predicate
cases, both zero inputs, every source-sign combination, INT16 endpoints, full
static geometry and metadata rejection. Complete proofs must cover both fields
and repetition counts, non-power-of-two rows, exact accounts, actual xy source
composition, fresh false predicates/signs/predecessors, original substitutions
hidden by zeros, and explicit padded values. A complete 16384-element proof
must retain every child and original consumer before publication.

Continue Q26/Q31 with the configured norm output branches and signed output.
Native stacking, physical/model ownership, private PCS/ZK/FS, fidelity and the
original end-to-end acceptance criteria remain required. No new cut, production
NC coverage, fitted cost or benchmark is claimed.

## Current evidence

The tests-first run rejected the missing module. Seed 2716 then passed 10000
independent NumPy int64 cases covering 4242905 padded word slots and full-domain
metadata boundaries. Frozen corpus hash:
`1c00d0c60f7029c8c6ecec8e28e08c19ffb2dcef550f53d884a31220d68a9913`.

All predicate/sign/source controls and padding/cap controls passed. Changing a
nonzero predicate to zero while adjusting k to preserve m=k+n still rejects
the second predicate equation. Fresh false Boolean signs reject even at zero
products; nonboolean signs and padded values reject their actual cap relations.
Composition-preserving finals and originals hidden by zero operands reject.
The first control run stopped at a test-only call to an unavailable field
subtraction helper. Addition and negation repaired that helper; neither the
verifier nor expected rejection reasons changed.

An actual reciprocal-product proof composed on the same xy root. Changing a
raw input sign while preserving xy and canonical product sign rejected the
pinned source. All16 honest proofs passed across both fields, both repetition
counts and row sizes1,5,16,65, including exact accounts and every original
consumer. Frozen matrix state hash:
`4b2053fd44d284cbbc128d7e90c894e38832fe95fe205437f8a566244c5caee9`.
The full16384-element proof is running. Required CI integration and final
maximum evidence remain pending; all required local gates passed below.
Reproduce with `uv run --locked --script research/cqis-bounds/check_norm_sign.py`.
# Repository gates

All required local gates passed: workspace formatting, clippy, tests,
CQIS no_std, dependency and Rust policy, reference digests, production
negative-control catalog, soundness accounting, ledger/schema/docs/glossary
checks and CI-scope tests. Production coverage remains4/21 bindings and
20/81 controls plus one configuration control. The full-row maximum and
hosted CI remain required; these gate results do not grant native admission.
