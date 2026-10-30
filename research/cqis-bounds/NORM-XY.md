# Consumed RMSNorm magnitude product — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3, for RFC-0021 §2.3 and
RFC-0022 §2.3's closed xy role. No native/profile or production cut admission.

Question before implementation: can one vectorized byte-column relation bind
xy_i=abs(X_i)*abs(H_i) to the same actual signed16 sources, with every whole
range and carry boundary consumed? Cost terms: c_a/c_lu/c_sc/T_misc for O(N)
source/range/view/A3 work; no scalar proof loop over row elements. Kill criterion:
a changed source, magnitude, result, carry, padding or original final survives,
or bounds are derived from supplied values instead of expected norm metadata.

Expected metadata is the complete norm Spec(d,F,G,E,en,ed). This consumer
retains both fractional-bit domains through30, including G>14; gated-product
scale semantics cannot replace it. The existing range adapter limits4N carry
words to4096, so this prototype admits d<=1024. The original d<=16384 remains
required. Neither shared range capacity nor Accepted contracts change here.

Two complete signed16 source consumers supply canonical raw bytes, magnitudes
and signs. One whole unsigned range bounds xy<=2^30 using four byte planes.
The closed xy certificate derives two input bytes, four result bytes and
carry caps(0,254,255,64,0). Enforce the exact outgoing caps per column and
zero caps on padded rows through one complete range consumer. Its final zero
cap already supplies the terminal carry boundary; no redundant terminal A3.
The incoming first carry is public zero. The four columns use two explicit
byte products plus incoming carry, equal to output byte+256*outgoing carry.
All original views are consumed even when multiplication by zero hides a
substitution in the equation. Whole source/result bounds supply high-byte caps;
both sides are at most65535 and2*65535<p. Telescoping gives the integer product.

Namespace: identity<2^44, base=2^63+2^18*identity. Signed children use
512*identity+1,+2; output/carry ranges4096*identity+65,+66. Parent A3 id
16384*identity+512 avoids every child invocation. Internal magnitude/carry
roots base+1,+2,+4 and views base+16..21 avoid child spans. Three external
X/H/xy ids are distinct u64>=2 outside the whole parent span. Full expected
norm function bytes, role order, six roots and four verified child states seed
the parent before weights/rounds/finals. No caller-provided certificate authority.

Account before implementation, a=log2(N): signed children contribute86a+70
to A3, xy range9a+14, carry range9a+18, and parent3(a+2), totaling107a+108.
Six signed-range lookups have dimension a+2; xy/carry each have dimension a+3.
For each dimension m separately retain identity((2^m+255)/|K|)^r and reduction
r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Full nonlookup draws are45a+44
of each A3 label; parent alone draws a+2 each and emits seven actual claims.
Binding/FS and other norm/model/private obligations remain additional.

Tests first:10000 independent NumPy int64 product/convolution cases, static
caps and metadata boundaries. Complete proofs cover both fields/repetitions,
zero/negative/extreme operands and non-power-of-two padding; a maximum-capacity
proof retains every consumer. Exact challenge/account assertions, canonical
source/range/carry substitutions, zero-factor original-final attacks and actual
same-X composition with the statistic consumer must pass. No benchmark claim.

Recommendation: continue Q26/Q31 with xy*J, configured output branches and
canonical product sign. RFC-0022 explicitly requires zero predicates and sign
zero when either input magnitude is zero; final output sign alone cannot erase
that obligation. Native stacking, physical/model ownership, private PCS/ZK/FS,
full capacity and original inference/fidelity criteria remain open.


## Reproduction and evidence

Run `uv run --locked --script research/cqis-bounds/check_norm_xy.py`.
Tests first failed with the missing module. Seed2714 passed10000 independent
NumPy int64 product/convolution cases covering3394324 padded column cells,
strict expected metadata and capacity boundaries. Frozen corpus SHA-256:
`f873271b7a0ecfacad1ccbef6c15966414806db0e4958a99aaa44a2039df17a4`.

Stale raw/magnitude/output/carry roots rejected; fresh bounded false output
and carry proofs failed ProductColumns:RoundSumMismatch. The first loose-cap
attack rejected earlier at Carry:SourceCopy:ClaimMismatch because changing
expected cap metadata changes the range transcript. The focused control was
strengthened to retain original expected metadata while producing actual
false-cap byte/column proofs. Carry overflow and output+p then rejected at
Carry:CapRelation:RoundSumMismatch and Output:CapRelation:RoundSumMismatch.
No verifier change was needed. Composition-preserving output/carry finals
and an original hidden by a zero multiplicand rejected ClaimMismatch.
Actual same-X composition with the statistic proof passed; a valid source
sign substitution preserving magnitudes/statistic/product rejected the pinned
raw root. Separate padding/terminal controls, full field/repetition/capacity
matrices and required repository gates remain pending. No benchmark, native
control credit or independent audit is claimed.
