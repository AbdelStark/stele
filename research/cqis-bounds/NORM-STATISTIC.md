# Consumed RMSNorm statistic — Q26 / Q31

Status: preimplementation research under Draft RFC-0004 A3. RFC-0021 §2.3
defines S=sum_i X_i^2; RFC-0022 §§2.1,2.3,5 supply its static bounds.
Original E5-03 and inference criteria remain blocked/open. This is not a full
norm proof, native/private source consumer, production cut or independent audit.

Question: can one actual signed16 row feed both operand roles of the existing
sum-of-products consumer, binding the exact unsigned statistic without a field
alias or a substituted magnitude? Cost terms: c_a/c_sc/c_lu/T_misc, with all
inherited consumers. Kill criterion: one factor can change unnoticed, including
when the other is zero; S and S+p alias; high output digits or padded sources
escape consumption; or proof receipts are presented as complete RMSNorm.

Expected metadata is the closed norm Spec(d,F,G,E,en,ed), preserving all domains
of RFC-0021 and RFC-0022. The adapter permits d<=2048 because actual signed and
limb-source children have that capacity; original d<=16384 criteria stay intact.
Reject metadata/capacity before input payloads. Derive the statistic role with
count=d, left_max=right_max=32768 and radix8 from that closed schema; no supplied
operator, column cap or observed maximum is authority.

First fully verify a signed16 row source against its independently expected raw
root and auxiliary magnitude root. Its two magnitude byte planes have N=2^a
rows each. Duplicate each plane into left and right operand positions, yielding
the existing limb-source layout of4N slots. Require exact equality with the
sum-of-products child's source and verify the complete child against that
derived root and an independently expected statistic root. Both copies remain
consumed even at zero factors; no supplied source map replaces this derivation.
There is one batched sum-of-products proof, no per-element proof loop or square
tensor. Verification never recomputes the integer sum of squares.

The existing actual whole input ranges, digit/carry ranges, two zero boundary
carries, polynomial identity, row sumcheck and both source/power consumers
remain. Static sides are below p/2 before integer lifting. Since both operands
are the same verified magnitude, accepted integer multiplication yields S.
The S<=d*2^30 bound follows from actual whole inputs; independent digit caps
alone do not establish it. No signed whole-word value is substituted for bytes.

For d1..2048, result columns K are4 for d1..3,5 for d4..1023 and6 otherwise.
The child output is always8 canonical-u32 digit slots, including enforced high
zero padding. This root format is an unsigned scalar byte vector; consumers
must explicitly join any differently sized view. It is not physical packing.

Namespace proposal: identity<2^44 and base=2^63+2^18*identity. Magnitude root
base+1, duplicated operand root base+2; signed child id512*identity+1 and
sum-of-products child id64*identity+1. Its reserved span starts at base+4096;
all descendant spans must remain within the parent span. External raw/statistic
ids are distinct u64>=2 outside the span. Context prefix
stele/research/q26/norm-statistic/v1 plus NUL, followed by version/field/reps,
three u64 identity/source/output ids, and complete RFC-0021 norm function bytes.
Final parent seed binds raw/statistic/magnitude/duplicated-source roots in that
order and the fully verified signed and product states. No parent challenge.

Account derived before implementation: signed source contributes A3 43a+35.
Product input whole range and packing contribute11a+20; its output and carry
capped ranges have dimension3 each, adding74. Full A3 numerator54a+129.
Six separate range lookup dimensions are a+2,a+2,a+2,a+3,6,6; each contributes
[(2^m+255)/|Kfield|]^r and r[F(m)+F(8)+3m]/|Kfield|,
F(m)=3m(m-1)/2+2m. Product identity adds(K-1)/|Kfield| and its three A1s
add(2a+4)/|Kfield|, neither squared. Full ZeroWeight count23a+55; Sumcheck
count24a+58 including product rho and A1 draws, excluding lookup schedules.
The parent draws none. Binding, FS/H and private composition remain additional.

Tests first:10000 exact/NumPy int64 sums and digit layouts, all sign endpoints,
zero/ragged rows and full field/repetition matrix. Compare exact losses/draws
and all original consumers. Independently valid product proofs replacing only
one factor must reject at the source join, including zero times a changed
factor. Two INT_MIN inputs give S=2^31, congruent to1 in M31; a genuine
arithmetic false-output proof must reject its product relation. Mutate each
raw/magnitude/sign source, result/carry, original final, padding and expected
root. Check strict metadata, canonical fields, output high zeros and maximum
namespace/capacity boundaries. No new analytic public-MLE kind is introduced.

Recommendation pending prototype: continue Q26/Q31 with numerator, bounded
normalization exponent, strict remainder, actual rsqrt membership, output
products/branches and model-owned routing. This statistic consumes only the
first RMSNorm arithmetic role and must not claim the remaining obligations.
