# Consumed RMSNorm reciprocal table — Q26 / Q31

Status: revealing research under Draft RFC-0004 A3/A2 and RFC-0008 A2.
RFC-0021 §2.3 defines J=R(2^21/sqrt(M)) for M=16384..65535. This consumes
the actual full canonical tuple lookup; a generation formula is not a verifier
replacement. Upstream normalized-interval and final output composition remain.

Question before implementation: can one actual canonical-field M/J source pair
consume the complete49152-row reciprocal table, excluding canonical padding,
while preserving all original/multiplicity/public denominator consumers? Cost
terms: c_lu/c_sc/T_misc for the complete table, multiplicities and fraction trees.
Kill criterion: an invalid mantissa, padded zero tuple, changed J, partial table,
corrupted valid/padding row or compression-preserving original final survives.

Expected metadata is the complete norm Spec(d,F,G,E,en,ed), with its canonical
function and mode3 representation. Its dependency is exactly rsqrt_q version1
with empty parameters. Generate the complete65536 padded rows from that expected
descriptor; retain all49152 valid tuples and all16384 canonical zero rows for
definition validation. Only the49152 valid distinct tuples enter the lookup
plan. Its fraction-tree padding is neutral(0,1), never an admitted(0,0) tuple.
The verifier never accepts a supplied table, table identity or function override.

External M/J roots each bind one canonical-u32 M31 word, matching the mantissa
consumer's M source representation. The full two-column lookup consumes both
actual original sources; membership itself supplies16384<=M<=65535 and
8192<=J<=16384. No separate range proof or whole-field reinterpretation replaces
membership. All multiplicity commitments precede every beta/alpha, all fraction
and leaf rounds/finals remain, and every actual original/multiplicity/public
denominator claim is consumed. This is one scalar global norm role; native
stacking, private PCS and physical/model ownership remain separate work.

Namespace: identity<2^50, base=2^63+4096*identity; multiplicity roots base+1,+2.
Lookup id64*identity+1 is below2^60 with all derived fraction ids in range.
External M/J ids are distinct u64>=2 outside the full parent span. Prefix
stele/research/q26/norm-rsqrt/v1 plus NUL, version/field/repetitions, three ids,
complete norm function/representation bytes and canonical table identity seed
the final parent with two actual source roots and one verified lookup state.
The parent draws no challenges; the full expected table and both source roots
already bind in the child's statement before multiplicities/challenges.

Account before implementation: scalar m=b=0, tuple arity2 and T=49152 give
identity numerator1+2*T-1=98304, raised only to repetition r. The table tree
dimension16 gives reduction r*F(16)=392r, separate from the identity; no A3
or parent loss. Each repetition draws one beta and alpha,16 fraction gamma,
16 fraction fold and120 Sumcheck challenges; unit challenges are absent.
All3r emitted source/multiplicity claims and every public denominator remain.
Binding/FS and the remaining norm/model/private composition are additional.

Tests first: independently certify every valid J by integer inequalities,
check the entire canonical encoding/zero padding and10000 NumPy gathers with
frozen hashes. Four complete proofs cover both fields/repetitions and mantissa
endpoints/interior. Exact accounts/draws, full multiplicity lengths, original
and composition-preserving final controls remain. Genuine partial/corrupted
table proofs must reject under the full expected plan; padded(0,0) must never
enter the admitted table. Actual same-root M composition with the bounded MD
consumer must pass and reject substitution. Malformed metadata/roots/fields,
supplied tables and changed repetitions must reject. No timing claim is made.

Recommendation: continue Q26/Q31 with actual J and same-a wide signed output
branches, then full native/physical/model/private lowering and fidelity. The
original task status and acceptance criteria remain open.
