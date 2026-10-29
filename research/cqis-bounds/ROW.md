# Q26: static row conversion and attained maximum

Question: can wide and gated rows derive a closed static schema for absolute
magnitudes, attained maximum, exact ceiling scale and signed nearest conversion,
including the M31 alias at the gated format endpoint? INV-5 and source/scale
bindings are at stake. Derivation contributes to T_misc and the actual range,
selection and arithmetic consumers to c_a/T_witness. Kill criteria: an accepted
modular alias or one-value substitution, an oracle mismatch, a runtime-derived
certificate bound or a missing whole-range/maximum/zero-scale constraint.
Research under Draft RFC-0004 A3/A8; no production proof or NC-0109 admission.

## Parameters and semantics

`row_bounds.Spec` fixes kind (wide/gated), dimension d in 1..2^20, input fraction
F in 0..30 (wide) or 0..44 (gated), mode (dynamic/static), and configured scale.
Parameters are strictly typed; bool is not an integer. Dynamic mode has inactive
configured scale 0. Static mode selects s in 1..65535, without automatic fallback.
Input and converted/restored values retain the same units 2^-F.

Let C=32768 for wide, C=2^30 for gated. Wide inputs satisfy -C<=x<=C-1;
gated inputs satisfy -C<=x<=C. These are format bounds, not observed maxima.
Dynamic mode uses M=max_i |x_i| and s=ceil(M/127), including s=0 for a zero row.
For s>0 the output code is signed nearest x/s, with ties away. Codes must be
in [-127,127]; there is no -128 code, saturation or implicit policy change.
The zero-scale row produces only zero codes. Static zero rows retain their
configured positive scale. Smax=ceil(C/127) for dynamic, configured s otherwise.
Thus dynamic maxima are 259 and 8454661. Original input/source authentication,
gate multiplication and unit associations are not established by this checker.

## Closed relations

The static record derives every range from the Spec, before inspecting a row.
The witness's observed M is never a certificate bound. Shared scalar fields are
scale s, nonzero n, predecessor t, maximum M, selected index j and ceiling slack.
Each entry has sign b, magnitude a, maximum gap, quotient q, scaled_quotient z,
remainder r, remainder_gap k, zero_gap v, code y and fixed limb columns.

n is the scale-nonzero bit, including for static rows. Enforce 0<=t<=Smax-1,
s=n*(t+1) and (1-n)*t=0. Both equations are field-faithful from these bounds.
Dynamic mode adds 0<=M<=C, 0<=j<d, ceiling slack in [0,126], and:

- 127*s=M+slack, which gives the exact ceiling in both directions, including zero;
- a_i+maximum_gap_i=M, with both magnitudes and gaps in [0,C];
- the selected magnitude at j equals M through canonical digits.

Every entry is dominated by M and one attains it. The generator chooses the first
attaining index for deterministic witnesses; the checker permits any attaining
index, including ties. This is not greedy decoding's first-argmax rule. In static
mode M,j,slack and every maximum gap are inactive zeros; their roles are absent.
The softmax maximum over signed scores is outside this absolute-maximum schema.

For each x use its canonical nonnegative offset u=x+C. Enforce Boolean b,
0<=a<=C, b=0 when a=0, and the integer relation u+2*b*a=C+a. Source offset
digits must be tied to the actual integer source, not merely to its residue.
At the gated endpoint, -2^30 and 2^30-1 are equal modulo p=2^31-1. A plain
signed field equality could accept the wrong sign/magnitude. Both offset sides
therefore use byte limbs, even though the original product fits signed int32.

Uniform rounding constraints, including zero scale, are:

- 0<=q,v<=127 and q+v=127*n;
- 0<=r,k<=2*Smax-1 and r+k+n=2*s;
- z=q*(2*s), with 0<=z<=254*Smax;
- 2*a+s=z+r;
- -127<=y<=127 and y=(1-2*b)*q.

For n=1, the second equation gives 0<=r<2*s, so
q=floor((2*a+s)/(2*s)) is nearest with ties away after sign restoration.
For n=0, s=q=r=k=v=0, and the limb relation forces a=0 for every entry.
No zero denominator is evaluated by the checker and no output is unconstrained.
The witness generator uses an explicit zero branch only to construct these values.

## Limb roles and bounds

Every role uses the [byte-column lemma](LIMBS.md), whole source ranges, canonical
source digits, digit/carry caps and both zero boundary carries. Exact result-digit
equality connects the source sides, ceiling sides, maximum, quotient product and
rounding/division. No wide equality modulo p substitutes for these bindings.

| Group / role | Count | Left maximum | Right maximum |
|---|---:|---|---|
| row / scale_product (dynamic) | 1 | Smax | 127 |
| row / scale_ceiling (dynamic) | 2 | C | 1 |
| entry / input_lhs | 2 | C+source_high | 2 |
| entry / input_rhs | 2 | C | 1 |
| entry / max_gap (dynamic) | 2 | C | 1 |
| entry / rounding | 2 | max(C,Smax) | 2 |
| entry / quotient_product | 1 | 127 | 2*Smax |
| entry / division | 2 | 254*Smax | 1 |

The largest role result bound is at most 2^33, needing at most five byte digits
and five convolution columns. Count<=2 bounds a raw column by
2*5*255^2=650250; carry<=2550 follows from floor((650250+2550)/256)=2550.
Both column sides are below 2^20<p/2. Whole source ranges are essential; independent
digit caps alone are insufficient. The implementation derives tighter column caps.

The remaining small equations have explicit bounds: scale/predecessor products
at most Smax; remainder left side at most 4*Smax-1 and right side 2*Smax;
zero-code sides at most 254 and 127; signed output sides magnitude at most 127.
All satisfy the strict centered criterion 2*bound<p. Maximum/source/rounding
values above that domain use digits throughout. No random challenge is added.

## Candidate bytes and operation roles

This has a separate research domain; Accepted RFC-0022 v1 schemas stay unchanged.
All integers are unsigned little endian; framing has no padding:

1. Literal `stele/research/q26/row-bounds/v1\0` (33 bytes).
2. Nine parameter bytes: u8 kind (wide=0,gated=1), u32 d, u8 F,
   u8 mode (dynamic=0,static=1), u16 configured scale.
3. u32 p, u8 radix bits=8, u8 scalar count=19, then u160 scalars in order:
   source_max, source_high, offset_max, scale_min, scale_max, predecessor_max,
   maximum_max, selected_max, slack_max, gap_max, quotient_max,
   scaled_quotient_max, remainder_max, scale_bound, remainder_lhs_bound,
   remainder_rhs_bound, zero_lhs_bound, zero_rhs_bound, output_bound.
4. Row and entry groups, in that order, each with u8 role count, then roles in
   table order. A role has sequential u8 id from 1 within its group, u32 count,
   three u160 maxima (left/right/result), three u8 lengths, then source/source/result
   u8 digit-cap arrays and u32 carry/lhs/rhs arrays of lengths K+1,K,K.

At most eight roles of at most 147 bytes plus 430 fixed bytes give at most 1606
bytes, within the explicit 2048 capacity. Exact regeneration rejects altered,
truncated and suffixed records; supplied fields never choose parameters or bounds.

`model_row_bounds.records` emits 7L+1 roles: each block's first norm output,
rotated query, rotated key, value, assembled attention output, second norm output,
and gated product; then final norm output. Query conversion covers heads*width;
key/value cover groups*width. Attention output covers all heads together, not
independent head scales. Norm rows have d entries and the gated row has FFN width.
Each role retains its own fraction and policy. No learned code/mantissa magnitude
is scanned. Expected metadata and source-role authentication remain separate.

The fixture SHA256 hashes literal `stele/research/q26/row-bounds-checksum/v1\0`,
u32 record count, then each u16 ASCII name length/name and u32 record length/record.
This is test evidence only, not the complete certificate-set identity or cqis_id.

## Reproduction, evidence and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --row-bounds`.
Seed 2635 checks 10000 row specifications with exact Fraction rounding, NumPy
int64 arithmetic, independent packed-column bounds and outer struct framing.
9613 conversions succeed; 387 reject overflow. Frozen SHA256:
`0b67d244cfb85747cffefd78de536a339bd522aa5d228302e58fcb6526b91bcb`.
Accepted witnesses check NumPy digit convolutions and all field/limb relations.
The original tests-first run rejected the absent implementation.

Controls cover every static field and role, coherent rebuilt substitutions,
the gated M31 alias, unattained maximum, under/oversized scale, free zero-scale
output, wrong zero flag/predecessor, invalid remainders, signed zero, symmetric
endpoints, ties, static inactive fields, maximum static dimension, a 16384-entry
zero row, every truncation and every byte flip of representative records.
Seed 2636 exercises thirty complete model configurations with mixed units and
dynamic/static policies; every non-overflow case checks all row roles against
the independent numerical composition. Inner limb/nonlinear primitives are shared.
Native Rust/GPU parity is not established by these Python tests.

The pinned two-layer checkpoint adds 15 records, 20290 bytes and checksum
`048baf66dde63a26ae19a06fd481793d5b838ccdb5886bb073da8d6121dcf86f`.
All previous configuration/artifact/scaled-record/logit/token fields are preserved.
Its full/cache/greedy replay passes. These byte counts are not performance results.

Recommendation: continue Q26/A3 toward rotary, attention, residual and decoding
schemas and complete certificate-set bytes. Native graduation needs an explicit
RFC-0022 amendment. Actual source-offset/digit, range, selection, scale and lookup
consumers remain required, with catalogued negative controls when admitted.
No NC-0109, full inference theorem, fidelity or task-completion credit. Derivation
uses fixed work per record; witness/checker work and retained data are O(d).
This affects T_misc/c_a/T_witness without a measured constant, cut or weight pass.
