# Q26: static rotary-application bounds

Question: can canonical Q14 coefficient pairs keep rotary numerators and signed
rounding field-faithful without limb decomposition, while preserving pairing,
positions and unchanged channels? INV-5 and source/rotation bindings are at stake;
the prospective cost term is c_a, with static derivation in T_misc. Kill criteria:
an invalid coefficient-domain assumption, a modular alias, an accepted source or
pairing substitution, an oracle mismatch, or a bound computed from observed data.
Research under Draft RFC-0004 A3/A6/A7; no proof-consumer or NC-0106/0109 admission.

## Fixed coefficient envelope

For A7 coefficients C=R(16384*cos(theta)) and S=R(16384*sin(theta)), each
signed nearest, ties-away rounding error is at most 1/2. Cauchy–Schwarz gives
|C|+|S| <= 16384*sqrt(2)+1. The left side is an integer, hence at most
isqrt(2*16384^2)+1 = 23171. Each component is also in [-16384,16384].
This holds for every real angle and therefore all A7 base/linear/llama3
frequencies and positions, without sampling coefficient extrema.

23170 is insufficient: A7 width=4, length=2, theta=16213/10000, position=1,
pair=1 gives exactly (11586,11585). The certified coefficient control checks
the full matching source geometry and the resulting sum 23171. Conversely,
component bounds alone admit (16384,16384). The checker rejects that pair
against the fixed envelope even for a zero input row. It never derives a
smaller bound from observed coefficients or input values.

Envelope membership is necessary, not sufficient, for canonical sine/cosine
identity. The existing numerical Params permits arbitrary component-bounded
fixtures; its behavior is unchanged. A record alone does not certify those
fixtures. Actual consumers must authenticate the selected function/table and
absolute position and enforce their source domain. This study takes expected
plaintext coefficients separately from the witness and checks their envelope.

## Shape, units and relations

Spec fixes heads h in 1..128, per-head width w in 1..floor(16384/h), even
rotary width r in 0..w, layout adjacent/split, fraction F in 0..30 and length L
in 1..2^20, with L*max(1,r/2)<=2^20. All parameters are strictly typed;
bool is not an integer. Position is separately expected in [0,L-1]. The source
has h*w signed int16 entries, in units 2^-F; outputs retain those units.
The coefficient row has r/2 pairs, shared by heads. Head-major/pair-major order
uses (2j,2j+1) for adjacent and (j,j+r/2) for split, offset by head*w.
Channels r..w-1 are unchanged; r=0 is a complete passthrough.

For each pair x,y compute N0=x*C-y*S and N1=x*S+y*C. Every scalar entry
has numerator N, Boolean sign b, magnitude a, quotient q and remainder t.
With D=16384 and B=32768*23171, the exact obligations are:

- -B<=N<=B, 0<=a<=B, 0<=q<=32768, 0<=t<D;
- N equals the applicable expression in the separately expected sources;
- N=(1-2*b)*a, and 0<=a-b<=B to exclude negative zero;
- a+D/2=q*D+t;
- output=(1-2*b)*q, with output in [-32768,32767].

The output interval excludes positive 32768 but retains negative -32768.
An overflowing rounded result is rejected, never saturated. A negative nonzero
numerator may round to zero with b=1; canonical zero refers to N, not output.
Every passthrough output equals its source. The checker evaluates these equations
modulo p=2147483647 after checking the stated whole-value ranges.

## Field faithfulness

| Quantity | Absolute or nonnegative maximum |
|---|---:|
| Source/output magnitude | 32768 |
| Coefficient magnitude | 16384 |
| Coefficient absolute sum | 23171 |
| Individual product | 536870912 |
| Either whole signed numerator, B | 759267328 |
| Biased magnitude a+8192 | 759275520 |
| q*D+t | 536887295 |

Every equation side has magnitude strictly below p/2. In particular, the coupled
coefficient envelope bounds each whole signed numerator by B; treating the two
coefficients as independent maxima would lose this property. Both N and signed a
are in [-B,B], so their difference has magnitude at most 2B<p. Rounding sides
are nonnegative and individually below p/2. Signed output and passthrough sides
are bounded by 32768. Boolean sign and the range obligation a-b need no inverse
or extra random challenge. Thus modular equalities imply the stated integer
equalities throughout this fixed source domain. No limb decomposition is needed.
Whole ranges, Booleanity and canonical source identity remain real proof obligations;
the Python comparisons are not replacements for authenticated range consumers.

## Candidate bytes and model roles

Accepted RFC-0022 v1 is unchanged. This separate research frame is exactly 113
bytes, within capacity 128, with unsigned little-endian integers and no padding:

1. Literal `stele/research/q26/rotary-bounds/v1\0` (36 bytes).
2. u16 heads, width, rotary; u8 layout (adjacent=0, split=1); u8 fraction;
   u32 length: twelve parameter bytes.
3. u32 p, u8 scalar count=15; fifteen u32 fields in order: row_width,
   pair_count, passthrough_count, input_max, coefficient_max, coefficient_l1_max,
   product_max, numerator_max, divisor, bias, biased_max, quotient_max,
   remainder_max, division_max, output_max.

The first three scalars are h*w, h*r/2 and h*(w-r); remaining constants follow
the table and relations above. Exact regeneration from separately expected Spec
rejects altered fields, bytes, truncation and suffixes. No proof-supplied field
chooses a bound. Fraction is preserved in the record despite cancelling out of
the integer rotation, so equal arithmetic under different units stays distinct.

The model compiler emits two records per block, ordered layer.i.query then
layer.i.key, including passthrough records for r=0. Query uses heads/fq; key uses
groups/fk. Each takes its own expected layout, width, rotary width and context
length. The row helper selects Params.rotations[position] before checking the
witness; source Q/K ownership and authenticated configuration remain separate.
Record derivation never scans learned tensor values or coefficient extrema.

The fixture checksum hashes `stele/research/q26/rotary-bounds-checksum/v1\0`,
u32 record count, then each u16 ASCII name length/name and u32 record length/bytes.
It is correctness evidence, not the complete certificate-set identity or cqis_id.

## Evidence and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --rotary-bounds`.
Seed 2637 checks 10000 specifications against independent NumPy int64 matrix
rotation and Fraction rounding, hard-coded numeric bound constants and struct
framing. 2940 cases use certified canonical coefficients across all three A7
frequency families; other cases use arbitrary pairs in the fixed envelope or
passthrough. 8318 outputs succeed and 1682 reject overflow. Frozen SHA256:
`9aba52a7fa8ec78f75591f96e21ad7bc634ebf96657c62938c5a9544f40c5a6c`.
The tests-first run rejected the missing implementation.

Controls cover every static field, source/coefficient/pairing substitutions,
positions, signed zero, ties, int16 endpoints, field aliases, invalid coefficient
envelopes on zero rows, passthrough outputs, maximum supported row/context shape,
every truncation and every byte flip of representative records. Seed 2638 checks
thirty model configurations with distinct Q/K fractions and full/zero rotations;
non-overflow cases compare their Q/K rows with the independent numerical model.
The shared certified coefficient generator and model helpers are not independent
native implementations. These checks establish no Rust/GPU parity.

The pinned checkpoint adds four records, 452 bytes, checksum
`d5f2c8dc0890760ac5efdf3c1f4765fe9e05f640f0db21aa5f02ee49f6d7cbd9`.
All previous configuration/artifact/scaled/row/logit/token fields are preserved.
These are serialized byte counts, not measured performance results.

Recommendation: continue Q26/A3 with residual/attention/decoding schemas and
the complete canonical certificate set, then amend RFC-0022 before native
graduation. Source/function/position/range/lookup/PCS consumers, native forward,
fidelity and NC-0106/0109 remain required. E5-03/04 retain all original criteria.
Derivation is fixed work per record; witness/checker work and retained data are
O(h*w). Avoiding limbs prospectively reduces c_a for this operation, with no
measured constant, new cut, challenge or proof weight pass.
