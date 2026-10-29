# RFC-0022 — Closed static arithmetic records

Status: Accepted · Version: 0.1.0 · Depends: RFC-0003, RFC-0004, RFC-0021

Review: [coordinated skill sign-off](../../agents/reviews/cqis-static-records-contract.md).

Evidence: [canonical records](../../research/cqis-bounds/ENCODING.md),
[column lemma](../../research/cqis-bounds/LIMBS.md),
[Requant](../../research/cqis-bounds/REQUANT.md) and
[RMSNorm](../../research/cqis-bounds/NORM.md).

## 1. Statement and authority

This contract defines deterministic static arithmetic records for exactly two
existing integer operations: scalar Requant from RFC-0004 A1, and RMSNorm from
RFC-0021 §2.3. It supplies closed derivation and canonical bytes for their bounds.
There is no prover message, challenge, claim, witness admission or proof receipt.
Native delivery requires §6; acceptance of this RFC alone completes no task.

Expected parameters are separate, checked values owned by the caller. A future
plan/verifier must derive them from authenticated shapes, formats and CQIS
configuration; it cannot read them from a supplied certificate and then treat
that certificate as its own authority. Records do not authenticate a plan or
enforce any source/sign/range/table/branch/claim binding. Full CQIS identity and
certificate-set framing remain RFC-0004 A3 / RFC-0011 work. No alternate hash
identity or opaque configuration blob is introduced here.

## 2. Closed static derivations

All arithmetic is exact integer arithmetic, fixed p=2^31-1 and radix B=256.
No field modulus, observed maximum, arbitrary operator name, input magnitude or
column schema may be supplied as trusted parameters. Unknown schemas reject.

### 2.1 Column derivation

For a role's static count d and magnitude bounds A,C, let
`w(M)=max(1,ceil(bit_length(M)/8))` and `u_i(M)=min(255,floor(M/256^i))`.
Set Z=d*A*C and K=max(w(A)+w(C)-1,w(Z)). Left/right cap arrays have lengths
w(A),w(C); result caps o_k=u_k(Z) have exactly K entries, including high zeros.
Set t_k=d*sum_(i+j=k) u_i(A)u_j(C), C_0=0, and
C_(k+1)=floor((t_k+C_k)/256) for k<K-1. Set C_K=0 as a separate boundary.
The recorded side bounds are L_k=t_k+C_k and R_k=o_k+256*C_(k+1).
Reject unless 2*L_k<p and 2*R_k<p for every k. Both zero carries are recorded.

This is a private derivation helper for the roles below, not an externally
selectable schema. Every source must also satisfy its whole-value bound and
have the stated canonical digits; digit caps alone do not establish that bound.
For example the caps (255,1) for 257 also admit the integer 511.

### 2.2 Schema 1: scalar Requant

Parameters are positive u16 mantissa m, shift e in [0,62], and target bits
b in {8,16}. Source format is fixed signed int32. Let V=2^31, H=2^(b-1),
D=2^e, h=D/2 if e>0 and zero otherwise, Amax=V*m and
Qmax=min(H,floor((Amax+h)/D)). Derive these six roles in this order:

| Id | Role | Count | Left bound | Right bound |
|---|---|---:|---:|---:|
| 1 | input_lhs | 2 | 2^32-1 | 2 |
| 2 | input_rhs | 2 | V | 1 |
| 3 | product | 1 | V | m |
| 4 | bias | 2 | max(Amax,h) | 1 |
| 5 | quotient_product | 1 | Qmax | D |
| 6 | division | 2 | max(Qmax*D,D-1) | 1 |

The ordered scalar fields are divisor=D, bias=h, product_max=Amax,
quotient_max=Qmax, output_max=H, output_lhs_bound=4H-1,
output_rhs_bound=2H. There are no signed-shift fields. All role magnitudes
have at most eight byte digits; every column side is below 2^20. The output
side bounds also satisfy the strict p/2 check. Output overflow still rejects.

Required consuming relations: for input acc, U=acc+V, magnitude v and sign s,
require U+2sv=V+v, s Boolean, 0<=v<=V and s=0 if v=0. The product result
is a=v*m. Require 0<=q<=Qmax, qd=qD, 0<=r<D and a+h=qd+r. Bind the
product/quotient results and equal sums by canonical digits with checked zero
extension, not a single wide field equality. For signed target y in [-H,H),
require (y+H)+2sq=H+q. A negative nonzero input may round to zero with s=1.
The offset digits must bind the original int32 source: distinct valid int32
values can have the same M31 residue. Each reused value is one shared obligation.

### 2.3 Schema 2: RMSNorm

Use exactly (d,F,G,E,en,ed) and their canonical domain from RFC-0021 §2.3.
Let U=d*2^(2F), Smax=d*2^30, Nmax=ed*Smax+en*U, P=ed*U,
Amax=Nmax*2^46, Dmax=P*2^18, MDmax=65535*Dmax. Let
emin=F+G-2-E, emax=F+G+30-E, Bmax=2^max(0,emax),
hmax=2^(emax-1) if emax>0 and zero otherwise, Lmax=2^max(0,-emin).
Derive eleven roles in the following order, using §2.1:

| Id | Role | Count | Left bound | Right bound |
|---|---|---:|---:|---:|
| 1 | statistic | d | 32768 | 32768 |
| 2 | numerator | 2 | max(Smax,U) | max(ed,en) |
| 3 | scaled | 1 | Nmax | 2^46 |
| 4 | normal_product | 1 | 65535 | Dmax |
| 5 | normal_sum | 2 | MDmax | 1 |
| 6 | xy | 1 | 32768 | 32768 |
| 7 | product | 1 | 2^30 | 16384 |
| 8 | bias | 2 | max(2^44,hmax) | 1 |
| 9 | quotient_product | 1 | 32768 | Bmax |
| 10 | division | 2 | 32768*Bmax | 1 |
| 11 | left | 1 | 2^44 | Lmax |

Ordered scalars are unit=U, S_max=Smax, N_max=Nmax, P, A_max=Amax,
D_max=Dmax, MD_max=MDmax, round_divisor_max=Bmax, round_bias_max=hmax,
left_factor_max=Lmax, sign_lhs=131071, sign_rhs=65536. Ordered signed
shifts are shift_min=emin, shift_max=emax. Bounds cover every permitted
normalization exponent a in [-23,9], regardless of the actual input row.
In particular Amax may exceed u128 even though normalized native arithmetic
fits u128. Native derivation must retain the full static value.

Required consumers: bind signed-int16 sources X,H to canonical magnitudes/signs
using (x+32768)+2*s*abs(x)=32768+abs(x), with s in {0,1}, magnitude in
[0,32768] and s=0 for zero magnitude. Enforce each source's whole signed range.
Bind S to the sum of the same X magnitudes squared; N=ed*S+en*U;
A=N*4^-min(a,0); D=P*4^max(a,0); MD=M*D; A=MD+R.
Require a in [-23,9], M in [16384,65535], 0<=R<D and actual membership of
(M,J) in the configured RFC-0021 rsqrt table. P and all factors come from
parameters and bounded a, not independent prover facts. A generation formula
for J cannot replace its actual lookup consumer.

Each output binds xy=abs(X)*abs(H), t=xy*J and product sign s: it is the
input-sign XOR when both magnitudes are nonzero, and zero otherwise. Enforce
the zero predicates and Boolean sign relation. Set e=F+G+21+a-E. For e<0 use the left role
to bind q=t*2^-e and require unused qd,r to be zero. For e>=0 bind qd=q*2^e
and t+h=qd+r, 0<=r<2^e, where h is the exact bias for e. Require 0<=q<=32768
and signed-int16 y with (y+32768)+2*s*q=32768+q. The same digit bindings as
§2.2 apply. These obligations include the selected branch, not just its bounds.

## 3. Derivation algorithm and resources

Derive only from validated expected parameters, in the stated fixed orders.
Compute every scalar, role and column with checked exact arithmetic. None of
the closed schemas requires iteration over the input row or the model weights.
They have at most eleven roles, twenty digits per magnitude and twenty columns.
Derivation costs O(sum w(A)w(C)) integer work plus O(sum K) encoding, in T_misc.
Actual arithmetic/range/lookup reductions remain c_a/c_lu; no fitted constant,
extra weight pass or committed intermediate is introduced.

All recorded unsigned values fit 160 bits; all role products Z also do so.
For norm, Nmax<2^107, P<2^106, Amax<2^153, Dmax<2^124 and MDmax<2^140.
The numerator role is below 2^107; other role products follow the displayed
bounds and are below 2^153. Requant products are below 2^64. These bounds imply
K<=20, including w(A)+w(C)-1; they do not authorize generic u160 multiplication
to discard high bits. Counts are at most 16384. Compute raw columns/carries
in checked wide integers before narrowing after the strict field checks.

Use no_std, no floats or unsafe code. Private immutable types hold checked
expected parameters and derived records. There is no untrusted raw-record
constructor, arbitrary schema callback, field-limit parameter or check bypass.
Bounded stack storage is permitted; any owned allocation reserves fallibly.
Capacity/overflow failure returns no partial object and preserves borrowed data.

## 4. Canonical bytes and validation

Every integer is little-endian with exactly its stated width; u160 means twenty
bytes, not a field element. Prefix ASCII `stele/v0.1/cqis/bounds` is followed by
u32 version 1, u8 schema, u16 parameter length, and parameter bytes. Schema 1
parameters are u16 m, u8 e, u8 b (four bytes). Schema 2 uses the thirteen
RFC-0021 RMSNorm parameter bytes. Next: u32 p, u8 radix bits 8, u8 scalar count,
ordered u160 scalars, u8 signed-shift count, ordered two's-complement i16 shifts,
u8 role count, then ordered role records. Exact counts are 7/0/6 for schema 1
and 12/2/11 for schema 2. There are no reserved extension tags in version 1.

A role is u8 id, u32 count, u160 A,C,Z, u8 w(A), u8 w(C), u8 K; then left,
right and result caps as u8 arrays of those respective lengths; then K+1
carry caps, K left-side bounds and K right-side bounds, each a u32 array.
Id/order is the schema table above. A role has at most 372 bytes; the complete
envelope has at most 4386 bytes. The implementation capacity is 8192 bytes.
No alignment, terminator, omitted high zero byte, alternate signed integer,
field-congruent alias, unknown record or trailing bytes is canonical.

The validator receives expected parameters separately, rederives the complete
record and compares its exact length and every byte with the supplied record.
Unknown versions/schemas and every field/count/ordering difference reject.
It never adopts fields from the supplied record as expected authority. Validation
can compare a previously generated immutable expected record without allocation;
no unbounded parser or memory allocation may depend on supplied lengths.
Derivation errors are Parameters, Arithmetic, FieldBound or Capacity as
applicable; a supplied record mismatch is Encoding. Exact error names may be
qualified by the native API but cannot become successful partial validation.

## 5. Conditional integer soundness and profiles

The column argument is deterministic and proven: assuming all source whole-value,
digit and carry bounds and both zero boundary carries are enforced, each modular
column equality has both nonnegative sides strictly below p/2. Its difference
is in (-p,p), hence residue equality implies integer equality. Multiplying column
k by 256^k and summing cancels interior carries and gives the exact source sum
of products. Honest final carry zero follows from the whole result bound Z<256^K.
Independent digit caps cannot justify this last step on their own.

For Requant, algebraic substitution in §2.2 and 0<=r<D give the unique biased
quotient and signed half-away output. For norm, the mantissa/exponent intervals
tile the positive axis; the retained remainder gives the unique normalization.
The configured table, exact product, branch, remainder and signed target checks
then give precisely RFC-0021 §2.3. These implications require every named consumer.
Static derivation by itself enforces none of them.

At maximum norm dimension, statistic has largest side 1073709311<p/2. Every
other norm role has count<=2 and at most twenty operand digits: raw column
<=2601000, interior carry<=10200, either side<=2611455<p/2. Requant's analogous
bounds are raw<=1040400, carry<=4080, side<=1044735<p/2. Small signed-source/output
relations use the recorded bounds and must also pass the strict inequality.

| Profile | Effect |
|---|---|
| standard | Same deterministic M31 prerequisite; no proof or profile admission. |
| treaty | Same prerequisite, no conjectural bound; full FS/privacy/lookup/PCS accounting remains required. |

No challenge, transcript label, commitment hash, SC/RLC/LU/PCS/MASK instance or
probabilistic error term is introduced here. Actual consumers must account for
their own complete reductions, range checks and source obligations under RFC-0012.

## 6. Mutation checks, controls and native delivery

Native delivery must compare full bytes with the independent reference for at
least 10000 varied supported parameter sets per schema and all boundary vectors.
It must independently check static column bounds, all declared resource limits,
strict field endpoints, and every parameter/scalar/role/cap/carry/side field.
Mutations cover changed version/schema/modulus/radix/order/count, every one-byte
change and truncated prefix of representative records, trailing bytes, integer
aliases, mismatched valid expected parameters, capacity and arithmetic overflow.
Require no_std, dependency bans, fmt/clippy/workspace, digest, negative-control,
soundness-accounting and ordinary repository gates; GPU changes require parity.

Unused deterministic record derivation creates no claim-graph edge. Primitive
byte tests earn no catalog credit and grant no new Workflow 08 exception.
NC-0109 remains required under the actual consuming certificate validator;
NC-0100/0101/0105 and every source/range/table/branch binding require their real
prover/verifier consumers and honest baseline. None is satisfied by a plaintext
witness checker, independent byte oracle or this conditional integer argument.

## 7. Open questions and preserved work

Q26 retains the full quantiser, other operation schemas, authenticated plan and
source derivation, complete cqis_id/certificate-set encoding, chunking policies,
native delivery and every actual range/claim/lookup consumer. Larger norm shapes
and wider Requant shifts remain unsupported; no automatic DPA path is introduced.
E5-03 and its property/control criteria remain open, as do E5-04/E5-05, E6/E7,
E9/E10 and E12-05. Q12 and the full private PCS/ZK/inference goal are unchanged.

## 8. Amendment log

Initial Draft at ebdba34; adopted with the coordinated same-author skill review
and RFC-0004 A5. Native §6 delivery and the full E5-03 requirements remain open.
Acceptance is not independent audit, completed native validation or proof admission.
