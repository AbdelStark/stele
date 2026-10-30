# Q26: static signed attention normalization

Question: can positive variable-denominator division with signed nearest rounding
remain field-faithful across exact/block1024 attention units, without deriving
bounds from observed totals or divisors? INV-5 and sum/divisor/unit bindings are
at stake; cost terms are T_misc/c_a/c_x/T_witness. Kill criteria: a rounded-output
or remainder alias, changed source/divisor accepted against expected inputs,
negative zero source, unsafe static column cap, oracle mismatch or implicit
host-only comparison standing in for the variable remainder relation.
Research under Draft RFC-0004 A3/A6 and RFC-0009 A2. Inputs are conditional raw
exact or already rounded block sums; block rounding/summation and actual source,
range, probability/function and output conversion consumers remain required.

## Static domain and expected sources

Spec fixes context length L in 1..2^20, head width W in 1..16384, input/output
fractions fv/fo in 0..30, E in 0..14, dynamic/static V conversion policy and
exact/block1024 accumulation. Dynamic scale metadata is inactive zero; static
scale s is in 1..65535. Drop c is in 0..62 and must be zero in exact mode.
The same policy bounds as the [raw sum study](ATTENTION-SUM.md) give S<=65535
and P0=2^E. Define the following solely from these expected static parameters:

- Raw block cap Hblock=1024*P0*S. For block mode Bmax=R(Hblock/2^c), where R
  is nearest rounding with ties away; reject the configuration unless Bmax<=32767.
- Exact total cap Tmax=L*P0*S. Block total cap Tmax=ceil(L/1024)*Bmax.
  The block bound uses absolute span L; actual sparse keys cannot justify
  replacing it with ceil(actual_count/1024). Even L<1024 retains the full-block
  drop requirement from Draft A6. Exact mode has inactive Bmax/block count zero.
- Zmin=P0, Zmax=L*P0, e=fo-fv+c, A=2^max(e,0), B=2^max(-e,0).
  Nmax=Tmax*A and Dmax=Zmax*B.

Separately expected inputs are z in [Zmin,Zmax] and exactly W signed integer
totals t in [-Tmax,Tmax]. Bool is not an integer. In exact mode these must be the
raw sums; in block mode they must be sums of separately rounded block outputs.
The checker establishes neither provenance. In particular, positivity of z is
a checked precondition, not proof of the unmasked attained maximum and exp sum.
Head/GQA ownership, masks, absolute positions and complete key membership require
their actual consumers. Output conversion occurs after assembling all wide heads.

## Variable division and signed rounding

Witness a source sign b in {0,1}, magnitude a and gap g in [0,Tmax]. Bind
(t+Tmax)+2*b*a=Tmax+a and g+b=a through canonical byte-column results. The latter
excludes negative zero at the source. Then derive U=a*A and shared D=z*B and
enforce, again with canonical byte digits:

- 2*U+D=2*Qp+r and Qp=q*D;
- r+gr+1=2*D, with r and gr nonnegative;
- y=(1-2*b)*q, with q in [0,32768] and signed int16 y.

The strict gap implies 0<=r<2D, so q=floor((2U+D)/(2D))=R(U/D). Neither the
generator's divmod nor a host comparison against the actual D is used as the
checking relation. Both r and gr have the static cap 2Dmax-1. The last small
signed equation alone is checked directly in M31; each side has magnitude at
most 32768. Source sign one with rounded q=0 is valid and returns integer zero.
Positive output 32768 rejects, while negative output -32768 is allowed.

There are two shared roles and eight roles per output column, all with radix 256:

| Scope | Role | (count,left maximum,right maximum) |
|---|---|---|
| shared | denominator | (1,Zmax,B) |
| shared | doubled_denominator | (1,Dmax,2) |
| entry | sign_lhs | (2,2Tmax,2) |
| entry | sign_rhs | (2,Tmax,1) |
| entry | sign_gap | (2,max(Tmax,1),1) |
| entry | numerator | (1,Tmax,A) |
| entry | biased | (2,max(Nmax,Dmax),2) |
| entry | quotient_product | (1,32768,Dmax) |
| entry | division | (2,max(32768Dmax,2Dmax-1),2) |
| entry | remainder_gap | (3,2Dmax-1,1) |

Source offset t+Tmax is derived from the expected source, not a free witness.
Shared D, each U and each Qp are bound to their role's exact result digits.
The doubled-denominator result is consumed by every remainder gap. All source
whole ranges, canonical source digits, digit/carry ranges and initial/final zero
carries remain mandatory. Scalar digit comparisons use a fixed twenty-byte
width and canonical zero extension; no wide scalar is compared only modulo p.

Exact Tmax<2^50; block Tmax<2^25. A<=2^92, B<=2^30 and Dmax<=2^64. These give
Nmax<2^117 and every role result cap<2^119. All source widths are at most twenty
bytes. With count<=3, a raw column coefficient is at most 3*20*255^2=3901500;
carry<=15300, LHS<=3916800 and RHS<=3917055, strictly below p/2. This conservative
bound covers every supported configuration, including zero Tmax at large drops.
The whole-input ranges justify the final zero carry; digit caps alone do not.

## Research bytes and model templates

Accepted RFC-0022 remains unchanged. All fields use unsigned little-endian
integers without padding, under a separate research domain:

1. Literal `stele/research/q26/attention-normalization-bounds/v1\0` (53 bytes).
2. u32 L, u16 W, u8 fv, u8 fo, u8 E, u8 value mode, u16 scale,
   u8 accumulation, u8 drop. Dynamic/exact tags are 0; static/block1024 tags are 1.
3. u32 p, u8 radix bits=8, u8 scalar count=20, then twenty u160 scalars in order:
   probability_max, restored_max, block_raw_max, rounded_block_max,
   block_count_max, total_max, z_min, z_max, left_factor, right_factor,
   numerator_max, denominator_max, double_denominator_max, biased_max,
   quotient_max, scaled_quotient_max, remainder_max, output_max,
   source_offset_max, source_gap_max.
4. Shared then entry groups with u8 role counts 2 and 8. Each role, in the table's
   order, has a u8 id starting at one within its group, u32 count, three u160
   left/right/result maxima, three u8 digit lengths, then left/right/result
   digit-cap bytes and carry/LHS/RHS u32 arrays. Result length K fixes carry
   length K+1 and both side lengths K.

The role-specific left/right/result widths are at most 15/12/15 bytes. Thus a
role needs at most 294 bytes; the fixed portion is 475 bytes and the total is
at most 3415, within capacity 4096. Validation regenerates every byte from the
separately expected Spec, rejecting alterations, truncation and suffixes.
One layer.i.attention_normalization template covers each layer's shared head
parameters. Evidence hashes literal
`stele/research/q26/attention-normalization-bounds-checksum/v1\0`, u32 record count,
then u16 ASCII role-name length/name and u32 record length/bytes. This checksum
does not authenticate a model, source or complete certificate set.

## Evidence and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --attention-normalization`.
Seed 2645 checks 10000 parameter/input sets against independent Fraction nearest
rounding, packed-column cap derivation, NumPy digit convolution and struct bytes.
6935 cases accept and also agree with direct NumPy int64 doubled division; 3065
reject output overflow. Frozen SHA256:
`4058a256af22725c1a630307b54ef2e0f59bd278ab64b01def36b8b83ce1c476`.
A separate exact control exercises D=2^64 beyond NumPy int64. The tests-first
run rejected the absent implementation. Every certificate field and every byte
of representative frames is mutated; truncations and suffixes also reject.

Coherent attacks rebuild all local column witnesses. At t=z=p, a false q=0
with r=p and gr=p-1 satisfies the local field equations while the two division
sides differ by 2p; IntegerRelation rejects it. Other attacks replace source
-p by positive zero, increase the divisor by p while changing output 2 to 1,
or preserve division exactly while making the strict gap sum wrap by p. All
reject through canonical digits. Controls also cover source changes, sign/gap,
quotient/product, biased remainder, zero divisors, output range, carry boundaries,
both tie signs, int16 endpoints and zero totals forced by large block drops.

Seed 2646 checks thirty model configurations with mixed fractions, V policies
and exact/block modes: 28 valid cases compare each head's normalization to
independent full replay, and two reject arithmetic overflow. A sparse three-block
case retains restored block units.
Shared inner numerical primitives are disclosed; this is not native/GPU parity.
The pinned checkpoint adds two records, 3770 bytes and checksum
`c90fad661fdd32d6b689b2f4f8cb75fa78e1f1ffdad208ee2c7f307e8891d4e9`.
It checks normalization for every layer/query/head of the generated sequence
and preserves all earlier fixture fields. Serialized sizes are not performance.

Recommendation: continue Q26 with block rounding/summation, score/max schemas
and the complete certificate set, then amend RFC-0022 before native graduation.
Actual sum/divisor/source/range/function/selection/PCS consumers, native forward,
fidelity and NC-0100/0101/0109/0500..0506 remain required. E5-03/04 and E7-06/07
retain all original criteria. Record derivation is fixed work; witness/checking
uses O(W) work/data, contributing to T_misc/c_a/c_x/T_witness with no measured
constant, new cut, proof weight-pass change or inference-proof admission.
