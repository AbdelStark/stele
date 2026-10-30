# Consumed static row codes — Q26 / Q31

Status: preimplementation research for RFC-0004 §5.5 / Draft A3/A8. E5-03 and
downstream original criteria remain blocked/open; no production cut or private
proof is admitted. Same-author skill review is not independent audit.

Question: can the configured positive static scale prove exact signed row codes
through actual sources and bounded byte division, without a dynamic maximum or
fallback? Cost/security terms are c_a/c_sc/c_lu/T_misc, source association,
strict rounding, symmetric output range and static faithfulness. Kill criterion:
a wrong public scale/source, excessive remainder, -128 output, false carry or
out-of-domain input passes; any final lacks a consumer; or a bound depends on
observed runtime values. Add a required consumer rather than assume a bound.

Use closed row_bounds.Spec with mode static and configured S in[1,65535].
Expected roots are raw input, scale and raw output. The scale root must equal
the canonical-u32 byte-slot root of public S, zero-extended to the input's B
bytes (B=2/4 for wide/gated). Its expected id is independently supplied; no
prover scale source or optional range proof can override the configuration.

Fully consume signed input16/32, signed output8, quotient Q<=127 on the same
output magnitude root, remainder R<=2*S-1 and biased carry T<=258. Nrows=2^a;
input bytes B=2^b; remainder bytes Br=2^br derive from the static cap. Let
P=2^c=max(B,Br); retain every operand byte, with exact zero extension. The
comparison carries track the difference of the two integer expressions, so
an additional result word is unnecessary even if both sides exceed256^P.
Initial/terminal carry closes that difference. Nrows*P<=4096 bounds this research
adapter: at most2048 wide elements when P2, otherwise1024. Original larger-shape
criteria remain unchanged.

Consume three k=0 A3 relations:

1. RoundedDivision: 2*Sbyte*Q+Rbyte+Tin-2*Magbyte-Sbyte-256*Tout+765=0,
   dimension a+c, degree2. Public S bytes are masked on padded rows.
2. TerminalCarry: TP-3=0, dimension a, degree1.
3. SignTransfer: (input_sign-output_sign)*Q=0, dimension a, degree2.

T=C+3 in[0,258], public T0=TP=3 and static byte sides<=66813 prove exact
integer2*S*Q+R=2*Mag+S. S>0 and R<2*S give unique nearest/ties-away magnitude;
the actual signed output fixes canonical zero. Honest C stays in[-3,255].
Padding uses source0, masked S0 and carry3. Static out-of-range codes reject;
there is no automatic dynamic fallback and no scale0 branch.

Static domain lemma to verify before implementation: accepted Q<=127 and
R<=2*S-1 imply Mag<=floor((255*S-1)/2). For every configured S<=65535 this is
at most8355712, strictly below gated H=2^30. Wide signed16 already bounds Mag
by32768. Thus min(signed_type_max,floor((255*S-1)/2))<=H follows from expected
metadata plus the fully consumed integer identities; no extra gated-magnitude
range is necessary. Byte faithfulness uses actual byte bounds independently
of this lemma, preventing circular field-lift reasoning.

Parent A3 adds(8a+3c)/|K| with3a+c draws of each label and10 actual finals.
Full A3 numerator is121a+26b+7br+12c+25; there is no A1. Full draw counts of
each A3 label are51a+10b+3br+5c+11, excluding lookups. Preserve nine lookup
identities/reductions with dimensions a+b+1,a+b+1,a+2; a+1,a+1,a+2; a+1;
a+br+1; a+c+2. No reduction is squared. Seven roots and five verified child
states precede parent challenges. Binding, FS/H and private composition remain
additional; no new label/profile is admitted.

Candidate namespace: identity<2^44 reserves base=2^63+2^18*identity. Expected
raw/scale/output ids are distinct u64>=2 outside that span. Input/output magnitude,
R and T roots use base+1..4. Input/output signed ids are512*identity+1/+2;
Q/R/T wide ids4096*identity+65/+66/+67. Parent invocation ids16384*identity+
512..514; views use base+16..24. Metadata/capacities precede payloads.

Tests first: exhaustive public-scale domain lemma; independent rounding corpus
with explicit Input/OutputRange rejections; complete field/repetition matrix;
S1/S65535, half ties, negative zero and wide asymmetric endpoints; actual
source/final controls and naive A3 parity. At S1, input/output -128 with Q128
and R1 satisfies all parent equations and all other ranges, but actual Qcap127
must reject. At a half tie, R=2*S preserves division with a wrong code but the
actual static remainder range must reject. Include the two-plane overflow
case S257, Mag32767, Q127, R513 where both integer sides exceed65535.

Also test the M31 alias S1, Mag=2^30-1, Q0, R0: its whole-word difference is p.
Fractional field carries can satisfy parent arithmetic; an actual carry range
or original-byte consumer must reject. No native control credit or performance
measurement is claimed. Static/private/model/native completeness remain separate.
