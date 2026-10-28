# Fused weight layouts and the compression boundary (Q28)

Status: Draft continuation of RFC-0010 A6 / RFC-0007 A1. Question: which
message layouts preserve the original signed B, and what does row splitting
cost? Kill criterion: a compressed layout claimed to recover all original
linear functionals without a decomposition proof, or a one-pass claim hiding
another original source read. No production layout or profile is admitted.
Review: [same-author skill passes](../agents/reviews/fused-layout-study.md).

## 1. A lower bound for direct linear consumption

Let S contain 0 and 1, let a row have T original coordinates, and let any map
P:S^T -> K^C describe its field message. P need not be linear or injective.
Suppose a fixed affine decoder D*y+c recovers every original row x from P(x).
Applying it to 0 and to each unit row e_i gives

`D * [P(e_0)-P(0), ..., P(e_{T-1})-P(0)] = I_T`.

The left side has rank at most C. Hence C>=T. In particular, if every original
coordinate functional can be checked directly as a fixed linear functional of
the committed message (with an allowed fixed offset), collect those functionals
as the rows of D to obtain this bound. It already applies to supported signed
int8/int16 values: their domain contains 0 and every unit row. It holds over
M31, QM31 and OM31, regardless of the integer codec's nonlinear construction.
Extracting base-field limbs from an extension element is not a K-linear decoder;
it does not evade the bound for functionals with general K coefficients.

This is not a lower bound on all proof systems or nonlinear decoding, and does
not forbid one particular functional from factoring through a compressed map.
Packing can save field-message space when an additional authenticated private
decomposition reduction connects the original claims. Such a reduction, its
range/position checks, challenges and costs cannot be replaced by this argument.
The separate collisions in packed-commitments.md establish failure of one
post-fold decoder even without assuming it linear; they are not needed here.

The literal equal-vector contract u=B is stronger still: for a Boolean row
functional selecting one row it requires that message row to equal the original
signed row, in the prescribed order and with prescribed zero padding. Therefore
one signed field element per original value is the minimal direct representation
for that contract. This is an algebraic requirement, not a speed comparison.

## 2. Candidate signed layout with independent axis padding

Let L,I,J be the positive logical layer, inner and output-feature dimensions.
Pad each separately to Lp,Ip,Jp, its least power of two. Let T=Lp*Ip and
t=ell*Ip+k. Do not pad only the product L*I: that gives a different polynomial
when either axis has holes. The full matrix is

`M[j,t] = embed_signed(W[ell,k,j])`, with zero for every padded coordinate.

The signed embedding is x modulo p, with the source independently constrained
to its declared signed width. It is not the unsigned two's-complement integer.
Canonical raw source storage may still use one byte/int8 or two bytes/int16;
registration expands it into field-message symbols. A width tag or honest
decoder alone does not prove a private source's range or its passport binding.

For a_j=eq(j,r_j), the matrix row functional is exactly
`u[t]=sum_j a_j*M[j,t]=B[ell,k]`. The column functional for a point opening is
the separately padded eq over ell and k. Every later arbitrary column functional
is also supported. There is no digit/sign reconstruction of a challenge-dependent
row. The source and padded message shape, axis order, signed width, field and
code identity must be derived from the authenticated plan/passport, not supplied
as authority by the prover. Missing range/source/PCS/ZK consumers remain required.

## 3. Short columns preserve a source visit, but change the row object

Split the output index into j=(j_hi,j_lo), with s low bits, 0<=s<=log2(Jp).
The split matrix has R=Jp/2^s rows and C=2^s*T columns in (j_lo,ell,k) order:

`M_s[j_hi, j_lo*T+t] = M[j_hi*2^s+j_lo,t]`.

Its row functional at the high point is
`u_s[j_lo,t] = sum_j_hi eq(j_hi,r_hi)*M_s[j_hi,j_lo*T+t]`.
The original sumcheck still consumes
`B[t] = sum_j_lo eq(j_lo,r_lo)*u_s[j_lo,t]`.
For any original column functional b, use b_s=eq(r_lo) tensor b to obtain
`dot(u_s,b_s)=dot(B,b)`. General b is not assumed to be another tensor point.

At s=0 the row and B can be the same immutable object. At s>0 they have different
lengths; passing B to an opening expecting u_s is incorrect. The low fold must
be checked in the actual consumer, with the same points/source and a bound to
the B used by the sumcheck. A copied value or prover-declared provenance is not
that binding. Ligerito requires its own full recursive statement and consumer.

All high coefficients are known before the source visit. Traverse the original
logical source in (ell,k,j) order, accumulating each signed value into one u_s
coordinate; padded coordinates remain zero. Then derive B from the retained u_s.
The second operation reads the partial row state, not original weights. It takes
2^s*T K multiply-adds, in addition to the L*I*J base-by-K source multiply-adds.
For s=0 omit this fold and alias the immutable row as B. This schedule establishes
an algebraic possibility only; it does not implement the bucketed kernel, the
phase transcript, authenticated source consumption or a native weight-pass gate.

## 4. Complete count comparison before choosing a layout

All counts below are exact symbolic quantities, not benchmarks. Put Q=L*I*J,
Pp=Jp*T and d=[K:F]. Full/split signed layouts have Pp base-field message
symbols regardless of s; a fixed code rate rho gives Pp/rho encoded symbols.
Actual supported code identities/lengths can add constraints beyond power-of-two
padding. Raw logical input has Q*w/8 bytes, separate from these field buffers.

For a nonrecursive, unblinded opening, sending the full row uses 4*d*2^s*T
bytes. At most q distinct base-field columns use 4*q*Jp/2^s bytes, before their
indices, Merkle paths/descriptors, certificate, scalar/claim messages and other
proof data. With repeated draws substitute the actual distinct count for q;
the security bound still charges all draws. Certificate openings have a separate
lifetime and must be charged even if amortized across model uses.

Retaining the row and B costs 2^s*T+T K symbols when s>0 and T when s=0.
Precomputed high/low coefficient tables add Jp/2^s+2^s symbols, including their
construction and overlap. Include downstream sumcheck folded state, encoder
temporaries, Merkle openings, original source storage and allocator/runtime/GPU
state separately; this expression is not a complete process-memory bound.

The two payload terms alone are minimized over allowed integer s, not by
declaring every column short. Their continuous relaxation has
R=sqrt(d*Pp/q); enumerate actual supported splits and all omitted costs before
selecting one. Query counts/rate/field must first come from the admitted security
policy; a payload choice cannot lower them. No Ligerito or ZK saving is assumed.

For comparison only, packed30 across the T padded original columns uses
ceil(T*w/30) words per row before separate code padding, instead of T. It also
needs the private decomposition path that the signed layout avoids for direct
linear consumption. These message counts do not establish the faster proof:
registration, per-proof ranges/decomposition, queries, memory and native kernels
all contribute. Neither raw-byte storage nor the smaller formula is proof credit.

Recommendation: specify the signed layout for literal u=B fused weights in an
explicit amendment; treat short columns as a separately bound u_s-to-B fold and
retain packed30/private decomposition as unfinished requirements for compressed
sources. This resolves which algebra the contract can demand, not its production
delivery. E4-03/E4-04 and Q28 remain blocked; no existing criterion is removed.
