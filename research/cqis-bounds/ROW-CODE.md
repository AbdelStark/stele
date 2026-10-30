# Consumed dynamic row codes — Q26 / Q31

Status: preimplementation research for RFC-0004 §5.5 / Draft A3/A8. E5-03 and
downstream original criteria remain blocked/open. No production cut or private
proof is admitted. Same-author skill review is not independent audit.

Question: can the actual dynamic-scale proof establish an independently expected
signed int8 row under nearest/ties-away division, including scale0, with work
linear in row bytes and no plaintext verifier maximum or division? Cost/security
terms are c_a/c_sc/c_lu/T_misc, shared sources, signed rounding, zero semantics
and static faithfulness. Kill criterion: wrong code/sign/scale, zero-scale free
output, excessive remainder, source substitution, padding or false carry passes;
any final lacks its actual consumer; or whole-word M31 arithmetic hides overflow.

Consume the dynamic-scale proof and signed int8 output with independent expected
raw input, scale and output roots. The output magnitude Q gets an additional
actual cap127 range on the same source root. Further actual wide ranges prove
remainder R, gap G<=2*Smax-1; zero gap Z<=127; nonzero N in{0,1}; predecessor
V<=Smax-1; and biased carries T in[0,258]. Smax is fixed by the closed dynamic
row schema. Every range is mandatory, including at scale0. Full-vector packing
of authenticated bytes is a linear view, not a supplied scalar source.

Use Nrows=2^a padded rows and B=2^b input/scale/remainder bytes. Derive the rounded
power-of-two plane count P=2^c from max(2*H+Smax,256*Smax-1). Both admitted kinds
need four planes (c=2): wide totals can exceed16 bits, while gated totals fit32.
Actual carry ranges require Nrows*P<=4096, so this research adapter supports
at most1024 real elements. This does not weaken the original full-shape criteria.

Consume seven k=0 A3 relations in fixed order:

1. ScaleNonzero: S-N*V-N=0, dimension0, degree2.
2. PredecessorCanonical: (1-N)*V=0, dimension0, degree2.
3. RemainderBound: R_i+G_i+masked_N_i-2*masked_S_i=0, dimension a, degree1.
4. ZeroCode: Q_i+Z_i-127*masked_N_i=0, dimension a, degree1.
5. RoundedDivision: 2*Sbyte*Q+Rbyte+Tin-2*Magbyte-Sbyte-256*Tout+765=0,
   dimension a+c, degree2. Scale is masked on padded rows; all bytes are
   zero-extended to P planes. Q repeats its actual source across those planes.
6. TerminalCarry: TP-3=0, dimension a, degree1.
7. SignTransfer: (input_sign-output_sign)*Q=0, dimension a, degree2.

Signed carries obey Cnext=(2*Sbyte*Q+Rbyte+Cin-2*Magbyte-Sbyte)/256 and
C in[-3,255]. T=C+3 lies in[0,258], with public T0=TP=3. Integer column sides
are <=66813 and2*66813<p. Padded carry words are3, not0; masked columns force
that value with their initial boundary. Remainder/zero/scale scalar identities
have static bounds <=max(4*Smax-1,254,Smax), also satisfying2*bound<p.

Telescoping gives2*S*Q+R=2*Mag+S. Nonzero/predecessor prove N iff S>0.
For N1, the remainder gap proves R<2*S, fixing the nearest magnitude quotient.
For N0, nonnegative R/G and Q/Z force R=Q=0. Actual signed output and the final
sign relation give canonical zero and signed ties-away, including input INT_MIN.
This does not bind a separately committed nonzero flag, index or physical model
format; static row mode and private/native integration remain separate work.

Parent A3 loss is(12a+3c)/|K| with5a+c draws of each label and22 actual finals.
Including all children, total A3 numerator is171a+87b+12c+25; inherited A1 adds a.
Total A3/A1 draws excluding lookup schedules are73a+36b+5c+11 ZeroWeight and
74a+36b+5c+11 Sumcheck. Retain19 independent lookup identities/reductions:
the dynamic-scale nine; output signed dimensions a+1,a+1,a+2; and Q,R,G,Z,N,V,T
dimensions a+1,a+b+1,a+b+1,a+1,1,b+1,a+c+2. No reduction is squared.

Candidate namespace: identity<2^36 reserves base=2^63+2^26*identity. Expected
raw/scale/output ids are distinct u64>=2 outside that span. Output magnitude,
R/G/Z/N/V/T sources use base+1..7. Dynamic child id is16*identity+1; signed output
id is131072*identity+32768; seven wide ids are1048576*identity+524288..524294.
Parent invocation ids are4194304*identity+3145728..3145734. Views use base+32
and above. Ten roots and nine completed verified states precede parent draws.

Tests first: independent integer corpus and byte columns, complete field/repetition
matrix, half ties/negative rounding to zero/zero rows/endpoints, actual source and
all-final controls, valid wrong-output proofs, excessive remainders, S0 free
output, malformed/canonical inputs, maximum namespaces/capacities and naive A3
parity. Preserve all original task criteria and full private/native proof scope.
