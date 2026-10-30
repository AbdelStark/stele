# Q26: static residual alignment and one-round addition

Question: can two signed int16 rows in distinct configured units be aligned,
added and rounded exactly once with a closed static schema, rejecting M31
aliases and separately rounded inputs? INV-5 and residual source bindings are
at stake; the cost terms are T_misc/c_a/T_witness. Kill criteria: an accepted
wide modular alias or source substitution, an oracle mismatch, runtime-derived
bounds, or any missing whole-source/digit/carry/sign/rounding obligation.
Research under Draft RFC-0004 A3/A8; no native schema or proof-consumer admission.

## Semantics and counterexamples

Spec fixes dimension d in 1..2^20 and left, right and output fractions Fl,Fr,Fo
in 0..30. Each source and output is signed int16. Parameters are strictly typed;
bool is not an integer. For each pair x,y, output is signed nearest, ties away,
of (x*2^-Fl+y*2^-Fr)*2^Fo, rejecting results outside [-32768,32767].
There is no saturation, separately rounded source, scale fallback or inferred unit.

For x=1,Fl=1,y=-1,Fr=2,Fo=0, the exact sum is 1/4 and rounds to zero.
Rounding the inputs separately instead produces 1. Unit alignment must precede
the single rounding step. A separate field-faithfulness attack uses
x=1,Fl=0,y=-1,Fr=30,Fo=0. Its aligned numerator is 2^30-1, which rounds to 1.
The integer -2^30 has the same M31 residue but rounds to -1. Bounds permitting
both values cannot justify a direct field equality, even though sources and
outputs are int16. A coherently rebuilt forged witness is rejected by canonical
digit equality, not by an incidental mismatch in stale local columns.

## Closed relations

Let C=32768, f=max(Fl,Fr,Fo), A=2^(f-Fl), B=2^(f-Fr), D=2^(f-Fo),
H=C*(A+B) and U=65535*(A+B). These are static constants. Source offsets
u=x+C and v=y+C are in [0,65535]. Every entry has offset o, Boolean sign b,
magnitude a, sign_gap g, quotient q, scaled_quotient z, remainder t and output.
Their whole-value ranges are o in [0,U], a,g in [0,H], q in [0,32768],
z in [0,32768*D], t in [0,D-1] and signed int16 output.

Enforce exact nonnegative integer relations using the byte-column lemma:

- o=u*A+v*B;
- o+2*b*a=H+a;
- g+b=a;
- z=q*D;
- a+floor(D/2)=z+t.

The second relation gives x*A+y*B=(1-2*b)*a. The third excludes negative
zero without a large field comparison or inverse: if a=0, nonnegative g and
Boolean b must both vanish. A negative nonzero numerator may round to zero.
The last two relations give the exact rounding quotient with 0<=t<D.
D=1 has bias=0 and t=0, so the same relations cover exact integer addition.
Finally enforce output=(1-2*b)*q with a small field equality. Signed int16
output admits -32768 but rejects +32768. The proof obligations include every
whole source range and canonical digit association; plaintext comparisons here
are not authenticated source/range consumers.

## Static roles and field bounds

Each role has count, left maximum and right maximum as follows. Products/sums
use the [byte-column lemma](LIMBS.md), range-checked canonical source/result
digits, bounded carries and both zero boundary carries. Exact result-digit
equalities connect o, the sign sides, a, z and the rounding sides. No wide
integer is connected solely by its M31 residue.

| Role | Count | Left maximum | Right maximum |
|---|---:|---|---|
| aligned | 2 | 65535 | max(A,B) |
| sign_lhs | 2 | U | 2 |
| sign_rhs | 2 | H | 1 |
| sign_gap | 2 | H | 1 |
| bias | 2 | max(H,floor(D/2)) | 1 |
| quotient_product | 1 | 32768 | D |
| division | 2 | max(32768*D,D-1) | 1 |

A,B,D<=2^30; H<=2^46, U<2^47, q*D<=2^45 and each role result is below
2^49. Seven byte columns suffice, including the conservative sign_lhs role
bound 4U. The aligned role has at most two products of a two-digit source with
a four-digit factor; at most four digit products enter any raw column.
Other roles have fewer digit products or a one-digit factor at most 2.
Thus raw columns are at most 4*255^2=260100; carry<=1019 follows from
floor((260100+1019)/256)=1019. Both column sides are at most 261119<p/2.
The implementation derives tighter caps per role. Whole-value ranges remain
essential: independent digit caps alone do not enforce them.

The only direct signed equality has output and signed q bounded by 32768,
so its difference is strictly smaller than p=2147483647. No new challenge,
sumcheck degree, probabilistic loss, intermediate commitment or weight pass
is introduced. The seven-digit helper is justified by the static bounds above,
not by observed witness values. Dimension changes the number of entries, not
their arithmetic caps.

## Candidate bytes and model roles

This separate research frame does not extend Accepted RFC-0022 v1. Unsigned
integers are little endian, with no padding. Framing is:

1. Literal `stele/research/q26/residual-bounds/v1\0` (38 bytes).
2. u32 dimension; u8 Fl, Fr, Fo (seven bytes).
3. u32 p, u8 radix bits=8, u8 scalar count=12, followed by u160 scalars in order:
   source_max, source_high, left_factor, right_factor, divisor, bias,
   numerator_max, offset_max, quotient_max, scaled_quotient_max,
   remainder_max, output_max.
4. u8 role count=7; roles in table order, each with sequential u8 id from 1,
   u32 count, u160 left/right/result maxima, u8 left/right/result digit lengths,
   those three u8 digit-cap arrays, and u32 carry/lhs/rhs arrays of lengths K+1,K,K.

The fixed portion is 292 bytes. Each role has at most 6+4+7 digit caps and
K<=7, hence at most 173 bytes; total<=1503, within explicit capacity 2048.
Exact regeneration from separately expected Spec rejects altered fields,
truncation, every byte flip and suffixes. Supplied bytes never choose their own
unit policy, dimension or bounds.

The model compiler emits two roles per block: layer.i.attention_residual uses
(norm1.F,fo,norm2.F), and layer.i.ffn_residual uses (norm2.F,fd,fout).
Each uses its configured residual dimension. It never scans learned values.
Correct numerical scopes still require authenticated plan/source-role consumers.
The checksum hashes literal `stele/research/q26/residual-bounds-checksum/v1\0`,
u32 record count, then u16 ASCII name length/name and u32 record length/bytes.
This is correctness evidence, not the complete certificate set or cqis_id.

## Evidence and remaining work

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py --residual-bounds`.
Seed 2639 checks 10000 specifications against exact Fraction rounding, NumPy
int64 alignment, independent packed-column bounds, NumPy digit convolutions
and outer struct framing. 3540 rows succeed; 6460 reject output overflow.
Frozen SHA256: `626a52677a666e48ce0ec7b83e0a4a1dc4e5984b6570dbd238e87db0e395e1d1`.
The tests-first control run rejected the absent implementation.

Controls cover every static field and role cap, source and unit substitutions
with rebuilt columns, the M31 alias, separate rounding, negative zero, remainder
bounds, positive/negative ties, int16 endpoints, all equal-fraction choices,
column aliases, zero boundary carries and maximum dimension/extreme-fraction
record encodings. Seed 2640 exercises thirty complete model configurations with
mixed residual units; non-overflow cases compare both residual rows against
the independent numerical composition. Shared inner numerical/limb helpers
are disclosed; these Python checks do not establish native Rust/GPU parity.

The pinned two-layer checkpoint adds four records, 4324 bytes and checksum
`ca81472ef1ec80eff4e9e96658c6c029a5daa100d7416f62ee4d1d448984c759`.
Previous configuration/artifact/scaled/row/rotary/logit/token fields are preserved;
the locked checkpoint command checks full/cache/greedy replay. Serialized sizes
are not performance results.

Recommendation: continue Q26/A3 with attention/decoding schemas and the complete
canonical certificate set, then amend RFC-0022 before native graduation.
Source/unit/range/digit/PCS consumers, native forward, fidelity and NC-0109
remain required. E5-03/04 retain their original criteria. Derivation has fixed
work per record; witness/checker work and retained data are O(d), contributing
to T_misc/c_a/T_witness without a measured constant or changed proof weight pass.
