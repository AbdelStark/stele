# Consumed scalar Requant — Q26 / Q31

Status: preimplementation research for RFC-0004 A1 and Draft A3. Original
E5-03/E7 criteria remain blocked/open; no native NC credit or private admission.

Question: can the closed scalar Requant semantics consume actual signed input
and output byte sources, multiplication, biased division, remainder and source
relationships without a plaintext integer arithmetic oracle in the verifier?
The properties at stake are source faithfulness, signed ties-away rounding,
zero canonicality, range enforcement and integer division uniqueness. Symbolic
cost terms are c_a/c_sc/c_lu/T_misc; no benchmark or weight-pass change.

Kill criterion: stop if an independently valid wrong-source subproof can splice
in; if a public constant, high byte, sign, remainder bound or output can change
without rejection; if verification recomputes the integer product/division; or
if exact challenge accounting, static bounds or canonical source routing fail.

Candidate uses the existing requant.Spec(M,e,bits) and its closed records:
M in [1,65535], e in [0,62], bits8/16. D=2^e, h=D/2 when e>0 else0.
Actual signed-source consumers bind int32 input and int8/16 output to magnitude
and canonical sign. Four actual limb-product consumers implement product,
bias, quotient_product and division using the existing closed column schemas.
Input_lhs/input_rhs are replaced by the stronger actual signed-source consumer;
no accepted RFC-0022 record format changes. An actual wide range enforces r<D.

Bind product operands to input magnitude and public M. Bind bias operands to
the authenticated product output and public h, both multiplied by public1.
Bind quotient_product to actual output magnitude and public D. Bind division
to its authenticated output and the separately bounded remainder, again times1.
Compare the bias and division results by exact zero-extended byte equality.
This gives |acc|M+h=qD+r, 0<=r<D. A degree2 A3 relation on every quotient byte
checks (input_sign-output_sign)*q_byte=0. This permits a negative input rounding
to canonical output zero; for q>0 it requires the signs to agree.

Every routed byte comes from a verified original or a static public constant.
Derive expected limb input roots in the complete plane-major layout. Never trim
to a cap's nominal digit count: a source with a nonzero higher byte must reach
the actual whole-input range, or reject if it exceeds the source layout. Add
only fixed zero extension, reject nonzero excess tails, and compare all live
result bytes. Full-vector root/equality consumers add no algebraic challenge.

Namespace candidate: parent id<2^42 reserves base=2^63+2^20*id through +2^20-1;
external raw input/output ids are distinct and outside. Signed ids2048id+1/+2
use auxiliary magnitude idsbase+1/+2. Product ids256id+16+j (j0..3) use source
idsbase+16+2j and result idsbase+17+2j. Remainder wide id16384id+32 has source
base+3. Child auxiliary spans are disjoint and statically checked by derivation.

All nested consumers fully verify. The parent binds expected schema, source ids,
all actual roots and completed child states before final sign A3. With output
B=2^b bytes, sign A3 adds 3b/|K| and b draws of each A3 label; zero-dimensional
instances retain their absorbs/records. Sum every signed/range/product receipt's
loss, including all four independent product identities and all lookup terms.
Do not square nonidentity errors or claim hash/FS/private composition for free.

All roots remain revealing canonical-u32 byte-word research roots, not physical
checkpoint/model roots or admitted production cuts. Production stacking, native
plan/codec, source ownership, private PCS/ZK and the full joint security argument
remain required. Continue Q26/Q31 only if the complete controls pass.
