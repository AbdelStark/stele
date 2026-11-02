# RFC-0024 — Centered signed-int8 matmul and Requant

Status: Accepted · Version: 0.1.0 · Depends: RFC-0005 A3, RFC-0007 A2/A4,
RFC-0008 A5, RFC-0010 A9/A10, RFC-0012 A14, RFC-0020 A9, RFC-0022, RFC-0023 A1

## 1. Statement

This contract joins one stacked signed-int8 matrix product to scalar Requant.
It fixes the original byte interpretation, both accumulator bounds and their
actual equality consumer. Existing field matmul and standalone full-int32
Requant keep their APIs, schemas, bytes and semantics. Native delivery is
E7-01f; this operation supplies no generic source view, model plan or profile.

The independently expected statement fixes K=QM31/OM31; stage j in [1,2^20);
full power-of-two dimensions L=2^h, n=2^a, d=2^b, o=2^c; scalar parameters
(mantissa,shift,bits) in the complete RFC-0023 domain; repetitions r in {1,2};
advice blowup in {1,2}; two actual byte-range-verified sources X,W; and an
incoming output MLE claim (z,y_z) with m=h+a+c coordinates. Require m<=63,
all actual A9/A5 geometry limits and checked capacities. Ragged axes, implicit
padding, int4, wider formats, per-position/channel parameters and virtual
activation source ownership are outside this operation.

Physical source matrices retain RFC-0007 A2's layout:
M_X[i,l*d+k]=x[l,i,k]+128 and M_W[j,l*d+k]=w[l,k,j]+128.
Each message is a canonical M31 word. Actual whole-source byte membership gives
x,w in [-128,127]. This explicit full-int8 interpretation does not settle the
Draft quantiser's use of “symmetric”. The source contexts, roots, certificate
identities, physical axes and range obligations belong to the caller; a proof
cannot select them. An external X source grants no new cut for a model's virtual
activation. X and W source ids are distinct, at least two and outside this
operation's reserved source/tensor interval.

At each Boolean output position (l,i,j), define the integer
C[l,i,j]=sum_k x[l,i,k]*w[l,k,j]. Derive B=d*128^2 with checked integers and
require 2B<p, p=2^31-1. Thus b<=15; b=16 rejects before proof work. This is a
static bound, never a bound inferred from observed values. The operation proves
the incoming claim on Q=Requant(C,mantissa,shift,bits), including rejection of
output overflow. It is an output MLE claim, not by itself a commitment to an
entire supplied output vector or a complete inference statement.

### 1.1 Actual byte-range registration

A byte-range verifier derives a complete A5 statement for the actual original
A9 certificate: canonical range_8 Table, all-one selector over every physical
message entry, b_lookup=min(total_bits,30), expected lookup id, r repetitions,
and r expected distinct mu ids with ell=0 and blowup=1. Initialize a separate
actual Transcript with the fixed ASCII public input
`stele/v0.1/integer-linear/byte-range/v1`, then run the unchanged complete A5
schedule. No mu root, mu certificate identity or proof bytes enter that initial
public input. Count the actual constructor payload/Usage in this range attempt,
separately from A9 certificate imports. All existing A5 id,
geometry, authentication and failure rules apply. It executes the entire A5
verifier and retains the actual original/mu certificate owners and conditional
record. Importing those certificates remains real A9 verification with separate
Usage. The range proof has ordinary A5 bytes; its fixed descriptor is derived,
not read as authority from the packet.

Only that private verifier constructor may create the opaque byte-range handle.
An arbitrary LookupRecord cannot be promoted: a valid lookup with an all-zero
selector proves no range. No bool, format tag, digest or unchecked deserialization
constructs this handle. Retain the exact original context/certificate identity,
range policy and every actual A5/A9 obligation. No additional range-proof hash
is required for membership. The handle references its actual registration event;
it does not authenticate an adversarial query cap or a global profile budget.

Both handles are completed before the enclosing operation begins; their r and
K must match it. The outer record borrows them, and they borrow all original/mu
owners. Reuse for the same immutable source retains the original event/lifetime
obligations; a repeated verification or failed attempt is a new charged event.
A coordinator may not deduplicate independent attempts by a source or packet
digest. Weight-range production is genuinely registration-scoped and reusable,
not a proof-local scan renamed preparation. Its complete cost remains visible.

The result exposes read-only access to its actual LookupRecord, original
certificate, ordered mu owners, range parameters and Usage. The completed
object itself identifies the evidence instance; an external registration-event
key may refer to that object for accounting only. No new cryptographic event
identifier or persistence format is introduced. Reuse borrows the same object;
separate objects created by verification are separate attempts. Across storage
or process boundaries, rerun the expected complete verification. Temporary
Table/selector/descriptor/proof buffers do not own the returned record; all
original/mu certificate owners remain caller-owned and borrowed. Any retained
proof bytes or copied records are separately charged actual buffers.

Range-attempt public admission is the fixed prefix length plus the actual A5
descriptor.public_bytes; A5's own limit excludes that preceding constructor.
The producer additionally counts twice its actual mu registration payload sum
for production/import. Failure returns no range handle and preserves the real
constructor-plus-A5 Usage. Failed imports separately retain their actual ordered
Option<Usage> prefix, including the failed attempt, without a partial roster.

## 2. Protocol and canonical representation

### 2.1 One embedded-input advice cut

Let N=L*n*o=2^m, V=2^31, and derive the existing RFC-0023 semantic schema from
the expected scalar parameters and unchanged RFC-0022 record. Let L_old be its
allocated semantic row count, excluding its old reserved zero rows R_old-L_old.
The new physical advice source has these exact rows:

| Rows | Meaning |
|---|---|
| 0..3 | Little-endian bytes U_t of U=C_witness+V |
| 4..L_old+3 | Original semantic advice row j at physical row 4+j |
| L_old+4..L_old+7 | Four slack bytes for the new cap v<=B |
| L_old+8..L_old+10 | Three Boolean carries for that cap |
| L_old+11..R-1 | Reserved zeros, R=next_power_of_two(L_old+11) |

Here C_witness is untrusted captured accumulator data, not a new committed
source. Positions are full (l,i,j), in that MSB-first order. There is one named
Requant advice root, no separate C, U or Q root and no fake four-row certificate.
This is an explicit extension of the named cut; it still discloses information
determining the accumulator and result and supplies no privacy claim.

Retain every original semantic equation, with U ordinals 1..4 and semantic
advice ordinals 5+j. The common A3 inputs are sigma at ordinal0, then physical
rows in order, ordinal1+row; sigma is the actual A7 full-domain selector, equal
to one. Append four cap columns
v_k+slack_k+carry_k=B_k+256*carry_(k+1), k=0..3,
with zero endpoint carries and three Boolean-carry equations. The existing v
has four bytes: never truncate it to the width of B. All seven cap planes are
covered by the same whole-cut range_8 lookup.

Each cap column has five terms in order: v_k, slack_k, carry_k, -B_k,
-256*carry_(k+1). Endpoint carries are retained zero constant terms. Each
Boolean equation has terms carry^2,-carry. Prefix every factor list with sigma
ordinal0, including constants; rows use ordinal1+physical_row. Keep zero
coefficients and repeated factors. This gives the existing conservative degree
three and exact term order even though sigma is identically one here.

J_old means the complete original count, including all old input padding and
reserved-row equations. Constraint order is the original semantic order through the target identity;
then the four new cap columns and their three Boolean equations; then
(1-sigma)*row for physical rows 0..L_old+10 inclusive, in order; then row=0
for reserved rows L_old+11..R-1 in order. Regenerate these last two groups for the new layout;
do not retain the old reserved-row constraints or slice a compiled list by
guessed counts. Conservative degrees and term ordering follow RFC-0023.
The common input count is 1+R and J=J_old-R_old+R+3. Keep all zero terms and
require J<2^20. The original semantic L_old<2048 implies R<=4096; all actual
row/code/lookup/byte capacities are nevertheless checked before work.

### 2.2 Source claims and signed matmul

Run one complete A5 range_8 lookup on all R*N advice words, with an all-one
selector and the fixed grouping/layout rules of RFC-0023. There is no separate
U lookup. Then use the actual independent constraint weights and skip=0 A3.
Its complete finals contain every physical advice row at its actual position
point q. Independently consume three claim groups through ordinary A9 openings:

| Group | Actual claims, in order |
|---|---|
| 0 | A3 rows0..3, the four U finals at q |
| 1 | A3 rows4..R-1 at q, including cap and reserved rows |
| 2 | Actual output A1 sign and q-magnitude byte finals, mapped to physical rows |

Each group binds its phase, exact source/certificate identity, point and complete
ordered row/id/value list before fresh independent weights. Rows are unique
within a group; reuse across different groups is intentional. Construct full
R-entry row coefficients with zero elsewhere and actual column eq weights.
Do not merge the three openings or their losses because the source is shared.
Use the unchanged output A1 relation of RFC-0023 on the mapped semantic planes.

Derive the accumulator claim from consumed group0, never from proof metadata:
v_C=sum_(t=0..3) 256^t*U_t_tilde(q)-V.
Restore precisely q=(r_l,r_i,r_j), without reorder or truncation, as the incoming
claim for the signed matmul. Multiplying separate s_tilde(q) and v_tilde(q)
does not compute the MLE of their Boolean pointwise product and is forbidden.

For each original byte source, construct the existing immutable RetainedRow
with exact row weights a_X=eq(r_i), a_W=eq(r_j). Keep raw u_byte unchanged.
The A4 Dense folding scratch is u_byte-128*sum(a) at each column. Actual A4/A1/A7
uses the existing layer coefficient and geometry, with incoming v_C. At its
restored terminal column weights b_col=eq(s_l||r_k), consume the raw source
through the existing retained-row A9 opening with expected scalar
v_raw=v_signed+128*sum(a)*sum(b_col).
These are the exact weights used by the owner and opening. Full eq tables sum
to one, including scalar axes; the identity is stated with actual sums to make
source/weight substitution visible. Both originals remain mandatory under zero
factors. No signed PCS source, new opening wire or second original-message scan
is introduced. The online weight pass forms one retained raw row; its affine
scratch is derived from that row, not from another source vector.

### 2.3 Ids, bytes and schedule

Let S=j*2^40. Reserve the same interval discipline as RFC-0023. Advice id is
S+2; whole-advice lookup id S/16+9; its mu ids S+18+k, k=0..r-1. A5's derived
tree/leaf ids remain scoped by its actual statement. Constraint ids are
S+4096+ordinal; aggregate A3 id S+1024; output A1 id S+2048; group opening ids
S+3072+group. Physical plane ids are S+2^24+row; sigma/output-eq ids are
S+2^28 and S+2^28+1. The virtual C id is S+2^21, signed matmul stage S+2^22,
and its public coefficient id S+2^28+2. Check every id and count before replay.
Range registrations have independently expected A5 ids/layouts outside this
operation; their actual nested invocation scopes and original identities remain.

Unsigned integers are little endian; K encodings and source contexts follow
the existing canonical codecs. A range handle's binding bytes are u8 version=1,
u64 lookup_id,u8 r, then r actual mu contexts (105bytes) and certificate ids
(32bytes), in repetition order. The actual original context/id accompanies it
in the outer statement. Bind completed registration data only; this does not
move the original A5 all-units/all-multiplicities/all-pairs schedule.

The new absorb-only LinearStatement payload is u8 version=1,u8 field degree,
u32 j,u8 h,a,b,c,u16 mantissa,u8 shift,bits,r,advice_blowup,u16 bound_length,
the complete rederived RFC-0022 bytes,u64 B; then X context/certificate id/range
binding, W context/certificate id/range binding, advice context/certificate id;
then z's m K values and y_z. Its length is
457+274*r+bound_length+(m+1)*sizeof(K). All fields come from expected objects
and actual verified handles; no supplied alternate bound or source is adopted.

Reuse RequantConstraints and RequantClaims payload definitions with the new
exact input roster, rows and physical source. Their stage/group meanings stay
fixed. The signed matmul uses MatmulStatement payload version2; its remaining
payload and byte length are exactly native-matmul.md §3, with this contract's
derived C claim, stage/coefficient ids and byte source contexts. Version2 fixes
the offset128 interpretation; existing version1 field matmul is unchanged.
The new outer label is `stele/v0.1/integer-linear/statement`; no new challenge
label is introduced. Registry implementation waits for native delivery.

The outer proof is u8 version=1,u8 field degree; advice root32 and complete A9
certificate; one complete advice A5 packet; aggregate A3 arithmetic packet;
group0 and group1 advice openings; output A1 packet; group2 advice opening;
then the complete signed matmul packet. The last packet retains A2's independent
wire version=1 and shape, with signed finals and restored
raw A9 scalars as defined above. No C value, q, dimensions, ids, counts, records
or alternate source roster are supplied in the wire. The version2 statement,
fixed by this outer operation, selects signed semantics; a wire version byte
cannot select or downgrade that expected statement. If w=sizeof(K), C_A is the
advice certificate size, L_A the advice A5 size, and O_X/O_W/O_A the ordinary
opening sizes, the exact length is
2+32+C_A+L_A+w*(8m+R+3+q_bytes)+3O_A
 + [1+w*(4*(h+b)+3)+O_X+O_W],
where q_bytes is the original rounded-magnitude byte width, not sizeof(K).

Caller-owned X/W byte-range handles, advice certificate and r advice-mu handles
outlive the closed record. Import advice and mu certificates by their real A9/A5
helpers; retain standalone registration Usage separately. Before outer mutation,
derive all geometry, schema, proof partitions and resource budgets; check exact
version/length/field, canonical arithmetic and original/range/advice identities.
Preserve authentication-before-column-decoding. An arbitrary existing Requant
descriptor or record cannot alias both old sources to this one handle.

The final matmul point/value are unavailable until A3 completes. Nevertheless,
derive its entire suffix size and preflight its versions, canonical A1 finals/
rounds and A9 row encodings from expected geometry before LinearStatement.
No provisional point becomes transcript authority. The later real matmul
descriptor uses only the actual consumed q and v_C. Retain that exact pair
through output A1/group2 until the matmul consumer finishes.

Replay exactly: LinearStatement; complete advice A5; RequantConstraints and J
weights; actual A3; groups0,1 with actual A9; output A1 and group2 with A9;
signed MatmulStatement, actual A4/A1/A7, original X then W retained-row openings.
Four distinct RLC records remain: constraints and the three claim groups.
The exact new RequantWeight count is J+R+1+q_bytes. Any error aborts the whole
attempt with its real cause and consumed-prefix Usage, no partial accepting
record, retry, rollback or source replacement.

### 2.4 Complete payload and allocation admission

Let w=sizeof(K), q_bytes be the rounded-magnitude byte width, P_in=R+1,
t=h+b and T=sum_terms(w+1+4*factor_count) over the full unsampled constraint
list, preserving zero terms and repeated factors. The cumulative absorb-payload
cap excludes transcript framing/challenge internals and standalone imports.
It is the checked sum of these quantities:

| Payload | Bytes |
|---|---|
| LinearStatement | 457+274*r+bound_length+(m+1)*w |
| Advice A5 | actual derived A5 public_bytes, complete child inventory |
| RequantConstraints | 13+8*P_in+13*J+T |
| Zero descriptor and final | 24+8*P_in+T + 16+w*P_in |
| Output A1 Instance and Final | 39+w+q_bytes*(30+2*w) + 12+w*(q_bytes+2) |
| Both arithmetic round streams | 2*m*(12+4*w) |
| Three RequantClaims | sum G(c), c=4,R-4,q_bytes+1; G(c)=147+m*w+c*(12+w) |
| Three advice openings | 3*U_A |
| Signed matmul and both openings | 486+12*t+w*(2*m+h+4*t+8)+U_X+U_W |

Here U_s is the actual A9 opening_frame_size(s)+opening_proof_size(s)-1.
The matmul entry counts its actual Statement/Stack/A1 frames, not StackSources.
Proof admission uses the exact wire sum in §2.3. The operation positions cap
counts R*N+L*d*(n+o) physical message cells; earlier complete range registration
has its own actual A5 caps. All shifts, sums, products and typed allocation
sizes must be checked for usize/isize addressability before replay. Bound
schema/term/id arrays, selectors R*N, arithmetic tables (R+1)*N and
(q_bytes+2)*N, group coefficients R+N and actual child decode/query buffers.
They are separate requested payloads, not claims about peak allocator capacity.

Use the existing A4 limits for signed matmul, including its conservative
descriptor/proof allowances and prepared/partial/A7 entry caps from
native-matmul.md §6. For S_col=L*d, separately reserve 5*S_col+n+o K entries:
two raw retained rows, two signed input copies, shared column eq and both row
weight vectors. A4's own folding copies remain in prepared_entries. Include
the retained joining point/value (m+1 entries) separately. This conservative
allowance permits the existing copying strategy; copies are neither hidden
source visits nor free memory. Fixed affine filling may avoid the temporary
signed copies without changing the cap or original-row identity.

Producer public admission adds each actual advice-mu certificate producer's
constructor/row/response payloads and every complete local import, just as A5
producer_public_bytes does. Advice and original registration performed before
this call retain separate budgets and Usage. Check the total local-H bound in
§4 and every child limit before mutation. Any later fallible allocation returns
Capacity with the actual prefix. Native evidence must report simultaneous
actual capacities and process RSS separately from these static admission caps.

Typed preflight failures are Statement for invalid expected ids/axes, the actual
CQIS Parameters cause for invalid scalar parameters,
Bounds(FieldBound) for 2B>=p, SourceRoster for source/range-policy disagreement,
ResourceLimit for the outer caller cap, and Capacity for overflow/addressability
or allocation failure. Preserve existing child causes, including child cap
errors. Wrong complete version/length/field returns ProofShape; noncanonical
arithmetic returns NoncanonicalField. Genuine advice context mismatch returns
CertificateContext; a different packet identity returns CertificateIdentity
after its real identity hash. Preserve ArithmeticRoster/CoefficientMismatch and
actual wrapped A3/A1/A4/A5/A9 causes. No invented JoinMismatch replaces a child.

## 3. Prover algorithm and cost

Register each original and its actual range proof separately. W registration
may be reused only for that immutable source. Capture C/advice during a separately
measured forward computation, or accept untrusted already-captured accumulators
as witness. The online proof producer receives fixed captured advice; it must
not recompute X*W before its later retained-row pass and hide that read in
preparation. Advice generation from captured C, advice encoding/registration,
range multiplicities and all other proof work are charged separately. A fixture
generator's forward computation is not proof of a whole-process one-pass claim.

Use shared actual A5/A3/A1/A4/A7/A9 engines, not copied transcripts or verifier
callbacks. Charge all R*N advice cells and their range/arithmetic work in
c_c/c_lu/c_a/c_sc/T_misc. Original/range registration retains complete c_c/c_lu
and hash costs. Online original visits are |X|+|W|; affine row preparation adds
O(L*d) K operations per source and no original reread. Retained rows, folding
copies, encoded-column query reads and all proof/witness buffers remain visible.
No measured constant or complete inference performance result is supplied here.

## 4. Verifier algorithm and cost

Derive the complete expected descriptor and actual child descriptors. Verify the
one whole-cut lookup, all arithmetic/groups, the joined claim and both original
openings; retain every child and registration obligation. Restore physical
coordinates and affine scalars internally. A metadata digest or successful
schema parse never grants an accepting operation record.

Charge complete public coefficient/schema construction, group arrays of R and N
elements, payload absorption, packet identities and actual child query/path work.
The closed verifier's local non-transcript H maximum is one advice packet-id hash plus the actual advice A5
max_local_hashes plus 3*H_advice+H_X+H_W; standalone imports/range attempts are
separate. The producer charges its actual advice packet identity, Table encoding
and mu Merkle construction; the verifier maximum is not observed producer work.
Derive cumulative transcript and allocation caps as in §2.4 with checked
arithmetic. Limits may reject a shape,
never select a weaker relation. Report both verification paths, complete live
capacities and independent process RSS in native resource evidence.

## 5. Soundness and retained boundaries

Outside the original A9/A5 failure events, fixed near messages are canonical
byte arrays. Hence signed originals lie in [-128,127], so |C|<=B. Outside the
advice lookup/arithmetic/RLC/opening failures, all original Requant equations
hold and the new full-width cap gives |U-V|=v<=B. Since 2B<p, equality in M31
of these two bounded integers implies their integer equality. No extension
field or repeated lookup repairs a missing bound.

Let D=C_tilde-(sum_t 256^t*U_t_tilde-V), where C_tilde is the MLE of the
Boolean-position integer matmul results. Both fixed output tables are determined before the A3
tail draws. D has individual degree at most one and total degree at most m;
it is not a product of globally interpolated X/W at a shared layer coordinate.
A false integer join makes D nonzero under the preceding deterministic facts.

Skip=0 A3 returns its actual m fresh tail coordinates. In the interactive model,
pre-sample that complete independent uniform vector Q. Adaptive round messages
and rejection only remove executions; do not condition on reaching or accepting
the complete A3 when asserting uniformity. Thus the accepted false-join event
is contained in the union of the actual source/range, arithmetic/RLC/A9 and
matmul failure events and {D nonzero, D(Q)=0}. The latter has probability at
most m/|K| by Schwartz-Zippel. At m=0 a nonzero constant cannot vanish, so this
contribution is exactly zero. No independence between failure events is assumed
and no future PCS/hash success is conditioned away.

Add an explicit SZ family and PointEqualityRecord with stage, m, field degree,
numerator=m and point_origin=(aggregate A3 id,tail). Keep the zero record for
scalars. This is neither an executed extra sumcheck nor independent-weight RLC.
Retain A3's three original records, including its separate phase0 m/|K| term;
all four RLC losses; output A1; advice A5; signed matmul A1; every actual A9
opening and original registration/range lifetime. Reusing one source does not
erase events or square child losses. The affine restoration is deterministic
and adds no random term. The same actual tail point must be tied to both records.

The accounting amendment must add SZ to the total explicitly. This conditional
interactive argument admits neither standard nor treaty and supplies no
Fiat-Shamir, Q12, extraction or joint-view privacy result. Full configured source
authority, model lowering, virtual activations, packing/wider dots, scale grids,
W8 and original E3/E4/E5/E6/E7 requirements remain mandatory.

## 6. Negative controls and native delivery

All four new reservations remain todo until native E7-01f executes them in both
fields through the unchanged complete consumers. Preserve real wrapped causes.

| Id | One declared changed value | Actual rejecting consumer |
|---|---|---|
| NC-0315 | One original byte becomes256; opposite signed factor stays zero | Private all-one range A5, RootMismatch |
| NC-0316 | One new high-cap slack A3 final becomes one instead of zero, scalar baseline | Aggregate A3, FinalEvaluationMismatch |
| NC-0317 | One scalar signed-matmul original A1 final changes under a nonzero opposite factor | Matmul Stacked(Sumcheck(FinalEvaluationMismatch)) |
| NC-0318 | One scalar raw A9 opening-row cell is replaced by its signed value | Matmul Pcs(ValueMismatch), before column queries |

The short RootMismatch in NC-0315 means the actual
lookup::Error::Fraction(fraction::Error::RootMismatch), not a Merkle rejection.

NC-0315 has the narrow false-statement procedure of RFC-0008 A5 §7: keep a
separate accepted byte7 baseline, then fix the negative source256 certificate
before every range draw, declare that one source deviation via ProverHook and
regenerate genuine dependent registrations/trees/openings. The negative source
stays unchanged through actual verification; it has no accepted honest proof.
Exercise X and W separately. Do not reuse byte7 authority for source256.
This explicit exception adds no bypass or general relaxation of Workflow08.

NC-0316 mutates a new cap-only slack final, not the shared v: otherwise an old
Requant equation could reject and conceal a missing new bound. Use the high
byte beyond B's short width. NC-0317 retains all accepted advice work and its
U-derived incoming value; the changed matmul final must meet a nonzero opposite
factor so the actual scalar product check rejects. NC-0318 retains honest
signed finals and changes one raw row; the unchanged consumer expects the
affine-restored raw scalar. Each of these three proof-artifact cases requires
an accepted complete baseline and exactly one encoded K-value difference.

Native regression cases must also isolate two distinct in-range accumulator
values (true C=0, valid advice1), plus C=0/advice p, B+1 and full-width high
tails. The former reaches actual matmul; the latter reach the new cap arithmetic.
Neither static schema rejection nor producer witness rejection counts as a
verifier control. API compile-fail guards reject arbitrary/all-zero-selector
LookupRecord promotion and escaped owners. Static tests reject b=16 and wrong
range policy/context, with exact zero-work preflight where applicable; they
earn no proof-control count. Extend actual 0306/0307/0606/0610/0611/0802 variants
for point/row/weight/source/continuation consumers in the new mode. A wrong-point
producer variant changes one declared coordinate then rebuilds dependent work;
there is no encoded q to claim was directly mutated. Independently omit
LinearStatement, constraints, each group and final original OpeningColumns in
following-A1 controls. Reservations and reference evidence earn no native credit.

E7-01f must deliver genuine nonconstant stacked composition in both fields and
repetition counts, scalar/zero-axis and signed/tie/zero boundaries, exact
malformed/lifetime/failure Usage, independent full-byte/record/continuation
parity and complete same-execution resource ledgers. Preserve existing matmul
and standalone Requant corpora. Registration, capture, online proving, import,
both verifiers, bytes, simultaneous allocations and RSS stay separate. One
online weight visit requires actual counters and source-owner evidence.

## 7. Open questions

Q26/Q28: this contract resolves only the explicitly centered fixed-parameter
operation. Full plan/cqis_id/passport authority, quantiser semantics, scale grids,
wider/chunked/packed dots, virtual source adapters and every model architecture
criterion remain. Q12/Q29 retain complete adversarial/lifetime composition and
privacy. No original parent task is completed by accepting this specification.

The [bounded evidence](../../research/integer-linear/REPORT.md) checks integer/
affine identities, aliases and non-Boolean point restoration, with four scalar
reference A3/A1 rejections. It does not replace the native successor's actual
whole-source composition, independent wire checks or complete resource ledgers.

## 8. Amendment log

Initial acceptance for E7-01e, with the five companion amendments and
NC-0315..0318 reservations. The [coordinated review](../security/integer-linear-contract-review.md)
qualifies the bounded evidence and exact source. ADR-048 adopts this contract;
E7-01f owns native consumers, independent parity and complete resource evidence.
