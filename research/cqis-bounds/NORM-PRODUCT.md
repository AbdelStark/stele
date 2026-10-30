# Consumed RMSNorm reciprocal product (Q26 / Q31)

Research under Draft RFC-0004 A3 for RFC-0021 §2.3 and RFC-0022 §2.3.

Question before implementation: can one vectorized byte-column proof bind
t_i=xy_i*J for a full 16384-element norm row, using the actual xy byte root and
the actual scalar J root from the rsqrt consumer? The cost terms are
c_a/c_lu/c_sc/T_misc for linear range, column and view work. Kill the design if
a source, product, carry or padded value can change without rejection, a bound
depends on witness values, or the full row requires a proof loop over elements.

Derive every child from the expected norm parameters and the closed product
role. Its input caps are [255,255,255,64] and [255,64], its result caps are
[255,255,255,255,255,16], and its carry caps are [0,254,318,318,128,16,0].
The maximum column side is 81663, with twice that bound strictly below p.
Whole ranges supply the high-byte caps; endpoint carries are fixed public zero.

The xy child bounds each value by 2^30 and preserves four byte planes. The
output child bounds t by 2^44 and preserves eight planes, including its two
zero high planes. A scalar range bounds J-8192 by 8192 in two byte planes.
After verifying that range, reconstruct J exactly and check its canonical-u32
root against the expected rsqrt output root. This uses the same revealing
source join as the mantissa consumer. It adds no scalar proof or challenge.
The J byte views are the offset's low byte and its high byte plus 32.
Bounding J does not prove table membership: composition must retain the full
rsqrt lookup against that same root.

Let N be the next power of two at least d and a=log2(N). Store the first three
outgoing carry planes in one two-byte range with caps 254,318,318; pad its
fourth plane with cap zero. Store the next two in a one-byte range with caps
128,16. Padded row caps are zero in both ranges. At N=16384, the largest
children have 131072 word-byte cells and lookup dimension 18, within the
capacity continuation's unchanged byte-domain limit.

One degree-two A3 over eight columns and N rows checks the two convolution
terms plus incoming carry against the output byte plus 256 times outgoing
carry. C0 and C6..C8 are fixed zero. Every original view remains consumed,
including views hidden by zero xy values or zero convolution coefficients.

Before implementation, the five range lookups have dimensions
[a+3,2,a+4,a+4,a+2]. For each m retain the separate identity loss
((2^m+255)/|K|)^r and reduction r*(F(m)+F(8)+3m)/|K|, where
F(m)=3m(m-1)/2+2m. Their A3 numerator is 36a+76; the parent adds 3a+9,
giving 39a+85. Each nonlookup challenge label has 17a+36 draws. These formulas
require runtime checks against actual receipts before any success claim.

Tests must precede implementation: independent NumPy int64 products and
convolutions, full static geometry, honest proofs over both fields and
repetitions, exact challenge accounts, one-value source/product/carry attacks,
whole-product aliases separated by p, endpoint and padding controls, and
original-final substitutions hidden by zero operands. Join an actual xy proof
and a complete rsqrt proof on their unchanged expected roots. The full-row
proof and all controls must complete before publication.

Continue Q26/Q31 with configured output branches and canonical product sign.
RFC-0022 requires zero predicates and a Boolean sign that is zero when either
input magnitude is zero; output rounding to zero does not discharge those
requirements. Native stacking, physical model ownership, private PCS/ZK/FS,
fidelity and the original end-to-end acceptance criteria remain open.

## Current evidence

The tests-first run rejected the missing module. After implementation, seed
2715 passed 10000 independent NumPy int64 product/convolution cases covering
6788648 padded column cells and full-domain metadata boundaries. Frozen hash:
`8edffed9ff302d9c132750ec6b5a201e6c8a610ba2063285299648586baa214f`.

Reproduce with `uv run --locked --script research/cqis-bounds/check_norm_product.py`.
The actual xy proof and complete rsqrt lookup composed on their unchanged
source roots. A valid different reciprocal rejected the pinned J root. A
separate offset of 8193 rejected at Offset:CapRelation:RoundSumMismatch under
the expected cap 8192, using a real false-cap proof.

The complete matrix, remaining controls and full-row proof are running.
No completed full-row proof, final review or native/private inference is
claimed. Required CI integration and local gates remain pending.
