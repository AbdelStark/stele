# Q26: complete dense decoder block

Question: do the selected exact operations compose into one Llama-style block,
with identical full causal and incremental outputs, without losing weight,
activation or gated-product units? Cost terms: T_witness/c_a/c_x/T_misc. Kill
criteria: an independent arithmetic mismatch, a full/cache difference, silent
int16 truncation of the int32 gate product, mismatched block/unit cache scope,
or publishing a partial cache after a rejected output. Research only; no proof
admission, native forward, checkpoint fidelity or completion of E5-04.

## Complete numerical path

`decoder_block.py` evaluates both RFC-0021 RMSNorms; Q,K,V,O,up,gate,down
projections; A6 projected attention; SiLU and its exact gated product; and both
one-round residual additions. Expected physical records supply output-channel-
major int4/int8 matrices, mantissas and exponents. Gains are explicit int16 tuples
in each norm's configured units. Every boundary retains its own fractional bits.
This consumes prepared numerical data, not authenticated source-file/role bindings.

Projection inputs contain codes, scale and fractional bits. Compute the exact
dot product and multiply by the channel mantissa and row scale before one signed
nearest rounding. Norm outputs and assembled attention outputs convert over their
whole rows. No head-local or projection-channel-local activation scales are used.
Residuals align both operands exactly and round their sum once. Overflow rejects;
there is no saturation, hidden mode change or observed-data certificate.

The gated product P=U*silu_q(G) stays int32, in units 2^-(fu+E). Its dynamic
scale is ceil(maxabs(P)/127), including scale zero for an all-zero row. The
conservative bound ceil(2^30/127)=8454661 exceeds both the int16 dynamic-row bound
259 and u16. Static mode keeps its explicit u16 scale and rejects code overflow.
The down projection consumes the product's full scale and units. An endpoint
test exercises a combined numerator above 2^63 with an in-range final result.
For inner dimension <=16384, the exact dot is <2^28 in magnitude and the combined
numerator <2^68. These are integer bounds, not yet native field/limb certificates.

## Whole-table admission and field range

RFC-0021 requires every SiLU table entry to fit, not only the entries reached by
a sampled row. Under F<=30,E<=14 the whole int16 table fits iff E<=F. For x>=0,
SiLU is increasing and at most x, so E<=F bounds the maximum by 32767. For x<0,
write u=-x>0: u/(1+exp(u))<1, giving rounded outputs >=-2^E. If E>F then F<=13;
at t=32767, x>1, exp(x)>2, and 2^E*SiLU(x)>2*32767*(2/3)>32767+1/2.
The constructor enforces this complete static criterion before execution.
A tests-first control originally accepted (F,E)=(0,1); it now rejects. Checks
cover all 465 (F,E) pairs against certified endpoint evaluation.

This function range also improves the generic format bound: SiLU magnitude is
at most 32767, so |P|<=32768*32767 and 2*32768*32767<2^31-1. A future reduction
can use this strict centered-field bound only with actual source ranges, SiLU
membership and a bounded product result. The larger down-projection numerator
still needs its own signed limb/carry treatment. Draft RFC-0003 A3 corrects the
old int16-times-int8 assumption without imposing unnecessary limbs on P itself.

## Causal state and evidence

`full` prepares projected keys/values for the supplied absolute positions, then
uses the causal predicate key_position<=query_position. `step` appends one
strictly increasing position. Frozen caches retain the complete block scope,
including every matrix and gain, and are exposed only after the output succeeds.
A rejected down/product/residual operation leaves the caller's old cache intact.
Local scope equality is not authentication of cached values, a token sequence,
or model identity; real source/rotation/scale/position consumers remain required.

Run `uv run --locked --script research/cqis-checkpoint/check_decoder_block.py`.
Seed 2630: 10,000 cases, 8,058 accepted and 1,942 oracle-matched rejections;
all accepted cases match incremental decoding. SHA-256:
`bdce1edd1a5b7e216a53c49276e66d3c82162a71d99e64dc568a7754e46f836a`.
The seeded corpus checks complete intermediate records against NumPy int64 dot
products, exact Fraction scaling/residuals, bisection-based norm roots and the
independent projected-attention oracle. The certified SiLU/exp primitives are
shared; their independent transcendental evidence is in the earlier table work.
Generated A7 rotations feed actual attention. Full versus incremental checks
cover every accepted case, plus two-block compositions across positions 1023/1024
in exact and block1024 modes. Controls cover malformed shapes/types, all seven
weight scopes, changed units, non-total tables, large scales, signed endpoints,
zero rows and failure atomicity. No production NC or native/GPU parity credit.

## Costs and continuation

Seven projections cost O(N*(2*d*h*d_h+2*d*g*d_h+3*d*d_ff)) integer MACs during
witness evaluation, plus O(N*d+N*d_ff) norm/activation work and O(N^2*h*d_h)
attention. No proof weight-pass or cut changes. Retained research records use
O(N*(d+h*d_h+g*d_h+d_ff)) integer payloads; attention uses one score row per head.
Matrices are capped at 2^20 total codes and retained full-call payload admission
at 2^22 conservative cells. Python objects, weights and scratch add memory.
Incremental immutable cache copying/validation scans prior rows: this is not a
competitive serving implementation or a large-model capacity/performance claim.

Continue Q26 under Draft RFC-0004 A8 and its companion field amendment. Canonical
configuration/source-role bytes, complete static schemas, native Rust/NumPy model
parity, embedding/final norm/LM head/decoding, GPT-2 and remaining architecture
coverage, fidelity, proof consumers and joint PCS/ZK remain required. Original
E5-03/04 and E7-05 criteria are unchanged. No benchmark constant is modified.
