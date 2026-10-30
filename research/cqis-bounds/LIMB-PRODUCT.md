# Consumed limb sum of products — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8, using
Accepted RFC-0006 A1/A3 and RFC-0021 range_8. E5-03 remains blocked with its
original criteria. Full reveals are not a private PCS/ZK or production cut.

Question: can the unsigned limb sum-of-products relation consume the actual
input/output/carry sources with work linear in their digit payloads, rather than
trusting plaintext multiplication or materializing a quadratic digit-pair table?
The properties are integer faithfulness of every column, row pairing, virtual
evaluation consumption and exact output/carry binding. Symbolic costs are
c_a/c_sc/c_lu/T_misc; no measured constant or inference weight-pass change.

Kill criterion, stated before implementation: stop if a false product, legal-range
wrong carry, wrong source/row pairing or unconsumed virtual value can pass; if
the polynomial degree or complete challenge accounting is unsupported; or if
the prototype needs an N*P^2 replicated grid. No verifier multiplication oracle,
range scan, challenge retry, inverse of a random expression or new production cut.

Candidate: use the existing exact limb input consumer on N=2^a rows per side,
P=2^h original digit planes, and separate actual capped scalar consumers on output
digits and carries. Expected limbs.Spec supplies all bounds. With K result
columns, pad output/carry arrays to S=nextpow2(K+1); force C0=CK=0 and excess
positions to zero through their actual caps. The caller independently supplies
input and output roots. A carry root and all completed range states are fixed
before one fresh transcript challenge rho.

Let A_r(X)=sum_i A[r,i]X^i and B_r similarly. Check
sum_r A_r(rho)B_r(rho)=sum_k(Z_k+radix*C_{k+1}-C_k)rho^k with a degree2 A1
sumcheck over rows. Consume each virtual final at row point t with a degree2
digit sumcheck for sum_i rho^i*FoldRows(A_i,t), and similarly B. Its public power
final is evaluated exactly; its source final at digit point u maps to the actual
original point u+[side]+t. Both sides retain the same row point. These steps
cost O(NP+S) arithmetic, plus all existing ranges, roots and original consumers.

Conditional on actual input/output/carry ranges, every real column has both
sides strictly below p/2 by the static certificate. High source planes vanish;
the residual polynomial has degree at most K-1. A false integer column therefore
survives rho with probability at most (K-1)/|Kfield|. Add three A1 losses
(2a+4h)/|Kfield| separately, retaining every nested range/lookup term. There are
1+a+2h additional Sumcheck draws, no new label. Hash binding, FS/H and joint
private composition remain separate. Even K=1 retains its rho draw and zero loss.

Never fix rho to the radix: an interior carry change contributes
delta*X^(j-1)*(X-radix), so that choice would hide it. The honest producer should
consume supplied result/carry witnesses and perform only the random-point proof
arithmetic, not recompute the original integer multiplication as a verifier check.

## Exact scope, layout and consumers

Spec contains the expected limbs.Spec, identity in [0,2^50), distinct source
and output u64 ids >=2, repetitions 1 or 2, and field degree 4 or 8. Reserve
base=2^63+4096*identity through base+4095; both external source ids must be
outside that span. Derive the existing limb-source schema with identity
16*identity+1. It retains two separate N-row input families and P digit planes.
Recompute its static certificate and capacity before inspecting witness data.

K is exactly the result-cap count, g=ceil(log2(K+1)), S=2^g. Output caps are
the K result caps followed by zeros; carry caps are C0..CK followed by zeros.
Their actual scalar consumers have identities 64*identity+16/17 and source ids
output/base respectively. Both source vectors have S canonical M31 fields.
The carry root is auxiliary and fixed before rho; input/output roots come from
the verifier's independently expected statement. Kind0 width4 Merkle full
openings authenticate these arrays, with the unchanged nested range protocols.

The complete verifier first consumes the input, output and carry range proofs,
in that order. Its core context is domain `stele/research/q26/limb-product/v1\0`,
u8 version=1, u8 degree, u8 repetitions, u64 identity, u64 source, u64 output,
u8 radix_bits, u32 count, 20-byte left_max and 20-byte right_max. Integers are
little-endian. Append the three original roots and three completed range states
in input/output/carry order, each 32 bytes. Only then draw rho using Sumcheck.
This is a composed research transcript, not a registered production format.

A1 invocation ids are 256*identity+128+j for product/left/right, j=0,1,2.
Product inputs are virtual row arrays with ids base+8/9. Each source reduction
has public powers id base+10 and a row-folded view id base+11/12. These are
derived views, not commitments. Every invocation has polynomial input0*input1,
degree2, and dimensions a,h,h. Even zero-dimensional instances keep their
Instance/Final absorbs and zero SC records. Each product final is the claimed
sum of its own source reduction; no supplied point or cached evaluation is used.

The power MLE at MSB-first point u is the product of
(1-u_j)+u_j*rho^(2^(h-1-j)). Repeated squaring evaluates it in O(h), including
rho=0/1/-1, without inverses. The other source final is checked directly against
the authenticated original digit vector at u+[sidebit]+t. The row point t is
the exact product sumcheck point on both sides. Complete equality-table expansion
and a dot product consume each original in linear work. The target functional
on output/carry is evaluated exactly from their authenticated vectors; it is
not an unchecked claimed sum. Conditional core helpers alone do not accept the
whole statement: only verify first authenticates and proves every original range.

## Integer and probability argument

Input ranges imply D_j<=min(radix-1,floor(limit/radix^j)), so all certificate
coordinate bounds and zero high planes hold. Output/carry ranges enforce their
separate coordinate caps, C0=CK=0 and all S-padding zeros. For each k<K,
T_k+C_k and Z_k+radix*C_{k+1} lie strictly below p/2 by the recomputed certificate.
Their integer difference cannot vanish modulo p unless it is zero. All product
coefficients with k>=K vanish because K>=left_width+right_width-1. Thus a false
integer column yields a nonzero residual polynomial of degree at most K-1.

Fresh rho after the roots gives the stated Schwartz-Zippel term. Conditional on
that evaluation, the three A1 protocols have losses 2a,2h,2h over the field size;
actual public/original consumption closes their obligations. Summing every true
integer column with weights radix^k cancels interior carries. The zero endpoints
then give Z=sum_r left_r*right_r as integers, including values far above p.
The exact whole-output bound follows from bounded inputs and this product;
coordinate output caps alone are not presented as a whole-word range proof.

## Evidence, costs and remaining obligations

Run `uv run --locked --script research/cqis-bounds/check_limb_product.py`.
Tests first failed with the missing module. Seed2670 checks 10000 schemas and
301747 columns against independent exact integer multiplication; its checksum is
`4ec874facbb032e3b1ac6b612227ea1350e35d28877acfbb0baeeb6de01b8a4c`.
The first 100 also check polynomial identities at zero, one, minus one and
random extension points in both fields. A separate 10000-case power MLE check
compares the product formula with the independent full-table fold, dimensions
0..6, both fields and zero/one coordinates; checksum
`145f5f68e34642cd41e8b640155b50d7d8327270f34a913e359107b9a8695ff7`.

Full proofs cover byte/nibble inputs, both fields/repetition counts, zero caps,
ragged count3 and a 160-bit operand. Checks compare exact lookup/range/product
losses, core draws, every A1 record and original point mapping. False products
inside valid ranges reach Product rejection. Coherent B-squared arithmetic and
wrong row pairing reach actual SourceClaimMismatch; this also holds when the
other factor is zero. Coordinated power/source finals preserve a child product
but fail its public consumer. A legal-range wrong carry demonstrates the fixed
radix collision yet fails under the actual transcript. Root, shape, canonical
field, identity and capacity controls remain separate. No native NC credit.
Two full false proofs satisfy every core product equation using C0=1 or a
nonzero ignored output padding digit; their actual range endpoints reject them.

The twenty-four complete proof states have frozen checksum
`5b7a12834d5289240440c70ab8d33b5e291f8bc69ec4141c171f880e3f57abd3`.

The core uses O(NP+S) field work: collapse both row polynomials, run the row
sumcheck, fold each original plane at t and run two digit sumchecks. Original
consumption is O(NP) per fixed claim count. Complete range/lookup work, revealed
vectors, metadata, hashing and transcripts are additional; the inherited research
verifiers remain nonsuccinct. No N*P^2 table, performance measurement, fitted
constant, GPU claim or physical weight-pass change is asserted. Production weight
consumers still need their fused one-pass integration and accepted source contract.

Continue Q26/Q31 with signed/model-source relations and native lowering/codec,
private PCS/ZK/FS and fidelity. The separate integer witness generator is an
oracle; it is not called by this prover or verifier to recompute the product.
This proves a bounded unsigned research relation, not end-to-end inference or
an admitted private commitment scheme. All original task criteria remain.
