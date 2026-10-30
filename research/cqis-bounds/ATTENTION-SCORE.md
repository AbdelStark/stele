# Attention score bounds — Q26 research

Status: Draft RFC-0004 A3/A6 and RFC-0009 A2 only. E5-03 remains blocked;
original acceptance and NC-0109 are unchanged. No production proof consumer.

Question: can scaled QK scores have closed static records and integer-faithful
relations across the full signed-int32 score range, including masked scores?
The security property is static field faithfulness. The cost terms at stake are
T_attn/c_x and certificate bytes; no measured constant changes.

Kill criterion, stated before implementation: drop this candidate if any
accepted policy admits distinct scores through an M31 alias, needs data-derived
caps, changes nearest rounding or cannot match independent integer/Fraction
and NumPy references. Keep unsafe static score policies rejected even at zero.
Whole-row conversion, rotary source, head/GQA/absolute-position ownership,
mask/max/function consumers, native parity and fidelity remain separate.

## Static contract

The per-pair Spec contains width W in 1..16384, fq/fk/F in 0..30,
Q/K modes and scale parameters, score multiplier m in 1..65535, and
score exponent e_score in -62..30. Dynamic mode has inactive parameter zero,
code cap 127 and actual scale 0..259. Static mode fixes scale s in 1..65535
and code cap min(127, floor((65536+s)/(2s))). The bounds cover both signs;
source conversion still has to establish the actual code and scale together.
A zero actual scale requires every code in that supplied slice to be zero.

Let Cq/Ck be code caps, Sq/Sk the maximum scales, and define:

```
H = W*Cq*Ck
Uq = H*Sq; Uk = Uq*Sk; M = Uk*m
e = e_score - fq - fk + F
A = 2^max(e,0); D = 2^max(-e,0); B = floor(D/2)
N = M*A; S = floor((N+B)/D)
```

Require S < 2^31 before inspecting inputs. This is the same bound as
`projected_attention.Params`; actual zeros never relax it. There is no
saturation or zero-only policy. Expected code tuples have exact width W;
actual scales must satisfy their configured policies. Masks do not appear in
this per-pair template: masked scores have the same arithmetic and range.

## Relations and field faithfulness

The supplied dot is in [-H,H], with direct equality to sum(q_i*k_i) in M31.
H <= 16384*127^2 = 264257536 < p/2, so the equality is integer-faithful.
For Boolean b and a,g in [0,H], enforce dot=(1-2b)*a and g+b=a.
Both signed sides have magnitude at most H; the gap side is at most H+1.
This gives the canonical source sign, including b=0 at dot=0.

Nine fixed byte-column roles then enforce:

| Role | Expected operands | Integer binding |
|---|---|---|
| query_scale | a, actual Q scale | result = u_q |
| key_scale | u_q, actual K scale | result = u_k |
| score_multiplier | u_k, configured m | result = product |
| left | product, A | result = numerator |
| bias | numerator + B | equals division result |
| quotient_product | quotient, D | result = scaled quotient |
| division | scaled quotient + remainder | equals bias result |
| output_lhs | (output+S) + 2*b*quotient | equals output_rhs result |
| output_rhs | S + quotient | equals output_lhs result |

All intermediate scalars have their statically derived whole ranges, with
quotient <= S, 0 <= remainder < D and output in [-S,S]. The output offset is
derived from that checked signed integer. The last two roles imply
output=(1-2b)*quotient as an integer, even when the signed output interval
spans more than p. A negative dot may round to canonical integer zero.
Nearest ties are away from zero; D=1 has B=0 and remainder zero.

M < 2^62. For e>=0, accepted N < 2^31; otherwise N=M and D<=2^122.
S*D <= N+B; consequently every scalar and role result is below 2^124.
Canonical equality uses 20 bytes, with no truncation. Each actual role operand
and its convolution result uses at most 16 bytes. With at most two terms,
byte coefficients are <= 2*16*255^2; carries <=8160 suffice for a conservative
universal envelope. Thus column sides are <=2089215 < p/2. The generic limb
engine recomputes tighter per-column caps and enforces both zero boundaries.
There is no wide field equality hidden in a returned score or intermediate.

## Encoding and model scope

The domain tag is `stele/research/q26/attention-score-bounds/v1` plus NUL.
Parameters are little-endian u16 W, u8 fq/fk/F/Q-mode, u16 Q-scale,
u8 K-mode, u16 K-scale/m, and signed i8 e_score; modes encode dynamic=0,
static=1. Then come u32 p, u8 radix bits (8), u8 scalar count (20),
and twenty u160 scalars in the implementation's SCALARS order.
The fixed prefix also has u8 role count (9). Each ordered role has local
u8 ID 1..9, u32 count, u160 left/right/result maxima, three u8 digit lengths,
byte digit caps, then u32 carry/lhs/rhs caps. Each role takes at most
65+3+48+4*(17+16+16)=312 bytes. The fixed prefix is 466 bytes, so the
complete record is at most 3274 bytes, within the enforced 4096-byte capacity.
Validation recomputes exact bytes and rejects extra, truncated or altered data.

Model records are `layer.i.attention_score`, one static template per layer,
shared by its heads and positions. The correctness checksum frames record
count, role-name length/name and record length/bytes under
`stele/research/q26/attention-score-bounds-checksum/v1` plus NUL. It is not
a cryptographic commitment or complete certificate-set contract.

The model checker rotates and converts whole Q/K projections before slicing
heads and GQA groups. It validates every key score, including causal-masked
positions, against independent Fraction scaling and NumPy int64 dots. The raw
attention-sum model checker consumes these numerical results and independently
reconstructs scores before deriving weights. Block and normalization checks
therefore compose with score arithmetic in the fixed checkpoint replay.
Source identity, mask validity, attained maximum, exponential function/range
claims and authenticated consumers remain obligations, not host-check proofs.

## Controls and reproducibility

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--attention-score` (corpus/models/controls) or `--attention-score-controls`.
The tests were written first and failed with the missing implementation module.
The oracle independently reconstructs constants, column bounds and framing;
NumPy digit convolution cross-checks each role. It shares the existing generic
limb oracle and numerical model fixtures, which is not an independent audit.

A canonical static example uses Q scale65535/code-1 and K scale32767/code+1,
W=m=1, and e=0. Its correct score is -2147385345. Forging +98302 changes it
by exactly p, stays in range, and passes a direct M31 sign equation. Rebuilding
all byte columns still rejects with IntegerRelation. Other controls rebuild
coherent large-product and division aliases, mutate source codes/scales,
dot/sign/gap/intermediates, certificate fields, byte frames, range/carry
boundaries, and reject unsafe static bounds on zero inputs. Extreme shifts
include e=-122, accepted positive shifts, full width and both signed ties.

The seed2649 corpus contains 10000 configurations: 5499 accepted and 4501
static ScoreBound rejections, including actual zero attempts. Every accepted
case checks full-width signed code rows and independent byte convolutions.
The frozen checksum is
`6ebb42692249177177927c0b55d754ce0d9084cf9e989b5adf01a259cacc330b`.
Thirty seed2650 models give 28 valid replays and two arithmetic-overflow
rejections. A separate GQA control uses whole-row scales across four heads,
two groups and gappy absolute positions 1023/2048.

The pinned baseline adds two records, 3304 bytes, checksum
`c10950e24d7986ef4f10d4bc70003f9141ed3920767a9b07fa22c9dc0b838ae1`.
All prior baseline and separate block-variant fixture fields are preserved.
These are serialized-size/correctness observations, not performance results.

## Recommendation and remaining obligations

Continue Q26 with masked attained maximum/delta records and then complete
certificate-set/source contracts. This is conditional arithmetic evidence for
Draft A3/A6 and RFC-0009 A2, not acceptance or NC-0100/0101/0109/0500..0506
coverage. Native execution/proof parity, fidelity and actual range/source
consumers remain mandatory. Accepted RFC-0022 and every original task criterion
remain unchanged. No challenges, soundness losses, cuts, weight passes or
production constants change. Research checking is O(W) for the source dot
plus fixed byte-column work; there is no allocated position or head tail.
The relevant production term is T_attn/c_x, not a measured improvement.
