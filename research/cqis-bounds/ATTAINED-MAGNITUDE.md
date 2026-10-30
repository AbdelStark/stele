# Consumed attained magnitude — Q26 / Q31

Status: preimplementation research for RFC-0004 §5.5 / Draft A3/A8, using
existing A1/A3 and range consumers. E5-03 and downstream original criteria
remain open/blocked. No private proof or production cut is admitted.

Question: can the actual signed row source prove that a separately expected
maximum magnitude bounds every real element and is attained, with work linear
in row bytes and without a plaintext maximum oracle in verification? The
properties are source ownership, integer comparison, attainment and padding.
Cost terms are c_a/c_sc/c_lu/T_misc; no measured constant or weight-pass change.

Kill criterion: stop if a below/above maximum, padded selection, missing/duplicate
selection, false carry or substituted original passes; if any claim lacks its
actual consumer or static faithfulness; or if the verifier recomputes max(input).

Candidate derives from the existing closed dynamic row_bounds.Spec. Wide rows
use signed16 and H=32768; gated rows use signed32 and H=2^30. The magnitude
maximum and gaps have exact caps H. Source width B=2^b is2/4 bytes. N=2^a is
the padded row size. The actual signed-source consumer limits this research
instance to at most2048 real elements; larger shapes reject before payloads,
without changing the closed row schema's production support requirements.

Authenticate independently expected raw input and maximum roots. An actual
signed consumer binds magnitudes; actual wide ranges prove M<=H, gaps G_i<=H,
and indicator E_i in {0,1}. Original padded magnitudes, gaps and indicators
have cap zero. A rooted carry vector stores C1..CB, with public C0=0.

Consume four A3 identities in fixed order:

1. MagnitudeGap: mag_byte + gap_byte + Cin - masked_M_byte - 256*Cout =0,
   dimension a+b, degree1. masked_M is the actual M byte broadcast on real
   positions and zero on padded positions, not an independently supplied table.
2. CarryBoolean: C(C-1)=0, dimension a+b, degree2.
3. TerminalCarry: CB=0, dimension a, degree1.
4. Attainment: E_broadcast*gap_byte=0, dimension a+b, degree2.

Then degree1 A1 checks sum_i E_i=1 and consumes its actual original final.
Since N<=2048<p and indicators are actual bits, this is exactly one real
selection. Integer byte columns have sides<=511 with 2*511<p; telescoping gives
mag_i+G_i=M for real rows and canonical zero carries on padding. Selection of
a zero gap proves attainment. This also handles all-zero rows and tied maxima.
The honest witness chooses the first attaining element for determinism; the
statement proves existential attainment, not a separately committed index.

The onehot is an explicit revealing research auxiliary (the wrapper option in
RFC-0009 §2 step5), not admission of a new production cut. It does not replace
the Q20 private selection/bit-source work or establish private index security.
Index-format binding, production stacking and joint private PCS/ZK remain open.

Parent A3 adds (10a+8b)/|K|; its A1 adds a/|K| separately. Including signed,
maximum, gap and indicator ranges, total A3 numerator is71a+48b+9. Preserve six
lookup identities with dimensions a+b+1, a+b+1, a+2, b+1, a+b+1, a+1 and all
their separate repetitions/reduction losses. Parent draws are4a+3b ZeroWeight
and5a+3b Sumcheck. All original roots and completed range states precede these
invocations; no challenge retry or new label. Hash/FS and joint ZK are additional.

Critical controls: an above-maximum claim selecting padded zero can satisfy all
arithmetic but must fail the actual padded indicator range. For gated rows,
mag=gap=2^30 and M=1 differ by p; fractional field carries make the column
equations and terminal hold, but actual carry Booleanity must reject. Include
a second genuine magnitude1 selected by E so that every other equation holds.
