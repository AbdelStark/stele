# Canonical signed attention sums (Q26 / Q31)

Draft RFC-0004 A3/A6 and RFC-0009 A2 research. Before code: can actual weighted
offsets O and the scalar offset base H prove canonical M=abs(O-H) and sign b
for every channel, including cancellation? Costs are c_a/c_sc/c_lu/T_misc.
Kill the design if a whole-M31 alias, negative zero, wrong scalar broadcast,
carry boundary or zero-hidden original passes. No production criterion changes.

The expected attention-sum schema fixes configured key capacity C, probability
cap Q and restored-value bound S. Let Hmax=C*Q*S. Consume complete ranges for
O in[0,2*Hmax] over channels, scalar H in[0,Hmax], M in[0,Hmax], Boolean b,
and a predecessor g in[0,2040]. The supported channel width is at most16384.
This is a conditional arithmetic statement: arbitrary ranged O/H can have
abs(O-H)>Hmax and must then reject. Actual O=sum(P*U) and H=S*Z composition
establishes the tighter magnitude bound; no plaintext source claim does so.

External roots use eight byte planes for O and M, eight scalar bytes for H,
and one plane for b. Each compact range root is separately bound and exactly
zero-extended. H broadcasts only to real channels; padded channels retain zero
O/M/b and carries. Keep every real source even when O=H, H=0 or M=0.

Reuse the signed-byte-column construction with actual H bytes. For each of
eight columns enforce O_k+2*b*M_k-M_k-H_k+c_k=256*c_(k+1). Carries lie in[-2,2].
Store B_k=c_k+2 in[0,4] on real channels and zero on padding, giving

    O_k+2*b*M_k+B_k+510 = H_k+M_k+256*B_(k+1).

Initial B_0 and terminal B_8 equal2 on real channels, zero on padding.
Two complete four-plane carry ranges retain all eight outgoing carries.
Each nonnegative side is at most1534<p/2. One degree-two A3 batches8N
column equations; one degree-one A3 consumes the terminal carry. All actual
H broadcasts and public masks/endpoints remain original-point obligations.

Canonical zero uses sum_k M_k=g+b, with the actual eight magnitude bytes.
Their sum is at most2040<p/2 and is zero exactly when M=0; bounded g and b
exclude negative zero without embedding the wide magnitude in M31. A third,
degree-one A3 consumes all three original views. The parent retains12 original
claims in total, including a sign hidden by zero magnitude and H paired with
a compensated offset final. No verifier-side subtraction grants acceptance.

Before implementation reserve identity<2^48 and base=2^63+2^14*identity.
Seven wide ranges in fixed order offset,base,magnitude,sign,predecessor,carry_0,
carry_1 use ids256*identity+1..7 and internal roots base+1..7. Four distinct
external ids stay outside the whole parent span. A3 ids1024*identity+128..130
and views base+16..26 follow all descendant invocations. Full schema and role
bytes, every external/auxiliary root and all verified child states precede
parent ZeroWeight and Instance/Round/Final messages.

For a=log2(padded channels) and compact byte exponents bo,bh,bm, ordered lookup
dimensions are a+bo+1,bh+1,a+bm+1,a+1,a+2,a+3,a+3. Each independently retains
((2^m+255)/|Kfield|)^r and unsquared reduction
r*(F(m)+F(8)+3*m)/|Kfield|, F(m)=3*m*(m-1)/2+2*m.
The full range/A3 numerator is61*a+7*(bo+bh+bm)+52; the parent contributes
7*a+9, already included. Parent draws are3*a+3 per nonlookup label; full totals
are27*a+22+3*(bo+bh+bm) per label. Verify these against actual receipts.
Binding, FS/H, upstream source composition and private claims remain additional.

Write tests first:10000 independent NumPy differences, signs, byte roots and
prefix-derived signed carries; both value policies; all compact widths;
zero H, cancellation and expected magnitude overflow. Both fields/repetitions
must cover dimension zero, ragged channels and static capacity extremes.
Mutate each root/range, substitute valid different H/O sources, forge bounded
M+p, negative zero, carry boundaries and compensating final values. Check
actual scalar broadcast, masks, predecessor bounds and all external high planes.
Compose complete weighted-offset, probability-sum and offset-base proofs on
shared sources; valid different children must reject their pinned joins.
Require a complete16384-channel proof and every repository gate.

Continue Q26/Q31 with signed block rounding,
normalized output and complete source composition. The conditional range cap
does not admit a complete sequence or prove upstream ownership. Native/private
PCS/ZK/FS, fidelity, GPU/scale and all original criteria remain open.

The tests-first run rejected the missing module. Seed 2737 passed all 10000
independent cases: 282594 accepted channel cells and 1429 expected magnitude
overflows. NumPy differences/signs/byte roots and independently derived prefix
carries agreed across both policies, exact/block accumulation and compact byte
widths 1/2/4/8. The frozen corpus SHA-256 is
`6fb9b680c7173c88644474378ab806c1a8afa938e865dcaef4c53bd5afe9169b`.

All primary controls passed: every external root and range, bounded M+p,
negative zero, carry endpoints and compensated O/H source substitutions.
All twelve originals rejected compensated final values, including the actual
scalar H broadcast and a sign hidden by zero magnitude. Whole bounds, Boolean
sign, predecessor overflow, padded carries and external high planes rejected.
Complete weighted-offset, probability-sum and base proofs composed on the same
roots; valid alternate children rejected their pinned joins. The initial
complete account matched. Both-field/repetition matrix and the complete
16384-channel proof are running; required repository gates remain queued.

All 16 matrix proofs passed across QM31/OM31 and both repetition counts.
Every receipt, original count and draw total matched. Frozen SHA-256:
`23a04a1bdd5f29015ef7651056b8edc232735b154f44013e22b1f459b7c980b5`.
The full 16384-channel proof continues in the original runner. Required
repository gates remain queued; this does not complete the review.
