# RFC-0023 — Integer Requant with a fixed advice cut

Status: Draft · Version: 0.1.0 · Depends: RFC-0004 A1, RFC-0006 A1/A3/A7,
RFC-0008 A5, RFC-0010 A9, RFC-0012 A11, RFC-0022

## 1. Statement

This contract supplies the missing integer/source consumer for scalar Requant,
applied independently to a vector. It preserves every Accepted RFC-0004 A1
parameter: signed int32 input, positive u16 mantissa, shift 0..62 and signed
int8/int16 target, rejecting output overflow. It uses the actual A5 grouped
lookup, A3 zerocheck and A9 source consumers. It does not authorize an HF plan,
passport, arbitrary Table-producing operation, matmul splice or either profile.
Acceptance of this contract completes no native implementation criterion.

An independently expected operation statement fixes K=QM31/OM31, stage id,
real length n>=1, m=ceil(log2 n), N=2^m, parameters (mantissa,shift,bits),
repetitions r in {1,2}, an actual input registration certificate, advice-code
blowup in {1,2}, and an incoming output claim (point z in K^m, value y_z).
The caller must own that statement; copying parameters/root/claim from the proof
does not authorize it. The complete model-derived authority remains E6 work.
The full field/source/code restrictions of A9 and lookup restrictions of A5
apply; checked resource caps may reject, never choose a different relation.

The input source is exactly four rows and N columns of canonical M31 words.
At real position i, its rows are the little-endian bytes U_0..U_3 of
U=acc+2^31. The four-byte interpretation is injective on signed int32.
All four words at padded positions are zero. The expected 105-byte A9 context,
root and verified certificate identity are distinct from untrusted packets.
One complete A5 range_8 lookup over all 4N words proves byte membership.
No single M31 residue is an integer-input representation.

This RFC explicitly names **Requant advice** as an additional auxiliary cut
under RFC-0007 §3 and RFC-0005 §1. It is one A9 M31 matrix with a deterministic
row for each byte plane in §2 and N columns. Its source root and registration
certificate are fixed before every dependent lookup or arithmetic challenge.
This is a substantive commitment decision: the advice contains information
determining the accumulator and result. There are no separate accumulator or
output roots, but their information is not claimed to remain uncommitted.
The root grants no confidentiality; Q29 and all original private-mode costs
remain. The fixed cut resolves the otherwise circular attempt to authenticate
uncommitted sign/digit/remainder tables through the lookup proving their meaning.

## 2. Protocol and canonical relation

### 2.1 Deterministic advice schema

Write B=256, V=2^31, H=2^(bits-1), D=2^shift and h=D/2 for shift>0,
otherwise h=0. Set A=V*mantissa, Q=min(H,floor((A+h)/D)). Recompute the actual
RFC-0022 schema-1 bound record from the expected parameters. No supplied bound,
observed input magnitude or arbitrary polynomial description is authority.
Let w(M)=max(1,ceil(bit_length(M)/8)); zero bounds still allocate one byte.

First allocate one byte plane for sign s, then the following integer values in
this exact order, each as w(M) least-significant-byte-first planes:

| Value | Meaning | Whole-value cap M |
|---|---|---:|
| v | input magnitude | V |
| a | v*mantissa | A |
| q | rounded magnitude | Q |
| qd | q*D | Q*D |
| r0 | biased remainder | D-1 |
| t | common biased/division result | A+h |
| w0 | common input-sign result | 2V |
| u | v-s | V |
| z0 | H-1+s-q | H |

After all nine value byte blocks, allocate their nine cap blocks below in table
order; do not interleave a value's bytes with its cap block. No result or operand
copy with an independent meaning is introduced.

For an integer x of allocated width w and cap M fitting that width, allocate w
slack-byte planes and w-1 carry-byte planes. Require, for k=0..w-1,

`x_k + slack_k + carry_k = M_k + B*carry_(k+1)`,

with carry_0=carry_w=0 and each interior carry Boolean. For the nine initial
values w=w(M). Reapplying a tighter cap preserves the existing full width;
it never truncates high bytes. All digits, including
slack and carry bytes, belong to the same whole-cut range_8 lookup. The integer
identity x+slack=M proves the whole cap, even when individual byte caps alone
would permit a larger number. A zero cap never trims its allocated field.

Next process the six RFC-0022 schema-1 roles in role-id order. If a role's shared
result has declared cap M_result greater than that role's Z, first allocate an
additional cap block for that SAME result with bound Z and its full allocated
width. This establishes the result's recorded byte caps and all excess high
zeros; a shorter role must never silently ignore the shared result's high bytes.
Then allocate that role's interior carries in ascending column. Carry c_k has width w(C_k), where
C_k is the verifier-rederived cap in that role's record. Allocate all its byte
planes and its cap construction immediately after them. Boundary carries are
the literal zero, not witness fields. The role results and actual input pairs
are fixed as follows:

| Role | Ordered input pairs | Shared result |
|---|---|---|
| input_lhs | (U,1), (v,2s) | w0 |
| input_rhs | (V,1), (v,1) | w0 |
| product | (v,mantissa) | a |
| bias | (a,1), (h,1) | t |
| quotient_product | (q,D) | qd |
| division | (qd,1), (r0,1) | t |

For every role column k, enforce its actual radix identity
`sum_(pairs,i+j=k) left_i*right_j + c_k = result_k + B*c_(k+1)`.
Constants use their complete canonical bytes. The byte of 2s at index zero is
2s, and its other bytes are literal zero; Boolean s bounds it by two. Referenced
values use their one allocated representation, zero-extended to the role's
checked widths. Verify statically that each actual operand's known cap is no
greater than the record's common left/right bound. Missing high result digits
are literal zero; excess allocated result digits are bound by the tighter cap
above, not discarded. Check every column
through K-1 and both zero endpoints. Never replace these equations by one wide
field equality, drop a high zero column, or accept separate left/right results.

Finally allocate three Boolean carry-byte planes for the four-column identity
`u+s=v`, using s only in column zero and zero boundary carries. Enforce s Boolean
and the small identity `q+z0=H-1+s`, reconstructing q,z0 from their byte planes.
The first equality makes s=0 when v=0. The second supplies the asymmetric signed
target range; it allows negative nonzero inputs to round to zero. Both sides of
the small identity are at most 2H; its strict field bound is checked statically.

Let L be the resulting number of byte planes, a0=ceil(log2 L), R=2^a0.
Append R-L zero planes. The physical cut is exactly R rows by N columns, row
bits first, then position bits. All values at positions i>=n are zero, including
slack/carry planes: semantic equations apply only at real positions. No prover
chooses plane order, aliases, widths, padding or omitted roles. The fixed nine
values and six RFC-0022 roles imply L<2048: value/cap planes contribute at most
9*(8+8+7), tighter result caps at most 6*(8+7), role carries at most
6*19*(4+4+3), with four sign/addition planes.
This conservative bound uses RFC-0022's K<=20 and u32 carry caps; it does not
claim all shapes have the same L. Reject unsupported code geometry/capacity.

Honest advice generation uses exact integer arithmetic, the unique quotient
and remainder, exact differences for slacks and the ordinary column carries.
It rejects negative slacks, overflow or nonintegral/out-of-cap carries. Padding
is written as zero. Same input/parameters produce the same advice and root.

### 2.2 Actual constraints and source consumers

Let sigma(i)=1[i<n] on the m-dimensional cube. The verifier constructs it with
RFC-0006 A7 Eq, one Axis(bits=m,real=n), no selector. It is not a literal mask
chosen by the proof. For every real-position equation C=0 above, include sigma*C
in the constraint list. Boolean equations are x*x-x=0. Also include
`(1-sigma)*x=0` for each of the four input planes and every allocated
advice plane, and `x=0` for every appended zero plane at every position.
All equations have degree at most three. Padding and reserved planes are real
proof obligations; a range_8 lookup does not prove they are zero. Their complete
ordered list is combined below; no individual equation may be omitted.

Constraint order is: s Boolean; nine value caps (column equations, then interior
carry Boolean equations, each in ascending order); six main roles (tighter result
cap when required, carry caps in ascending order, then main column equations);
u+s=v columns then its three
carry Boolean equations; the target identity; input padding planes; allocated
advice padding planes; appended zero planes. A main carry's cap has exactly the
same internal order as a value cap. No batching coefficient or omitted equation
is implicit. Constants are verifier-owned.

Each polynomial is the displayed left side minus right side; enumerate products
in pair order, then ascending (i,j), followed by incoming carry, negative result,
negative outgoing carry. Cap/addition and Boolean equations use their displayed
order. Expand reconstructed integers in ascending byte order. Expand each
product in that order, without combining or dropping zero-coefficient terms.
For sigma*C, prepend sigma to every term; for (1-sigma)*x use x then -sigma*x.
The single aggregate input list is sigma, four input byte planes, then all R
advice planes, each in physical row order. Constants have no input id. Factor
ordinals follow the written factor order. Every constituent uses this same list,
including inputs it does not use. The closed compiler, never proof data, supplies
all Instances, degrees, m and zero claimed sums.

Absorb the complete ordered constraint descriptor (§2.3), then draw J independent
RequantWeight challenges gamma_j, one per constraint. Form P=sum_j gamma_j*C_j
by concatenating their term lists and multiplying coefficients by their gamma,
without dropping any term/input or reducing the conservative degree on sampled
zeros. Run ONE actual A3 zerocheck with skip=0 on P. Check its sigma final with
A7, then close its four input-plane finals as one group and its R advice-plane
finals as one group, through the actual functional procedure below.

For a group on one genuine certificate and one actual position point r, absorb
its full ordered plane ids/values and point under RequantClaims before drawing
one independent RequantWeight eta_t per claim. Derive a[row_t]=eta_t, other rows
zero, b=eq(r), v=sum_t eta_t*value_t. Rows in a group are distinct and fixed by
the schema. Invoke ONE actual A9 functional opening for (a,b,v) on that exact
certificate. This uses the exact identity
`sum_t eta_t*plane_tilde_t(r)=a^T matrix b`; false claim aggregation has its own
RLC term in §5. No synthetic slice certificate, guessed point, trusted row value
or post-challenge selection is allowed. All claims, including zero-valued ones
or sampled zero coefficients, remain in the frame and retained group record.
The actual opening still runs when a or v is zero. A group is not closed merely
by its aggregate scalar; retain its actual A9 opening and certificate lifetime.

After all constraints, consume the incoming output claim with one actual A1
instance for `sum_i eq(z,i)*(1-2s_i)*sum_k B^k*q_(k,i)=y_z`.
Input order is eq, s, then q's byte planes. Term order is each positive
eq*q_k term followed by its negative 2*eq*s*q_k term, ascending k. Its degree is
three even for m=0 and zero sampled coefficients. Check the eq final with A7
using Axis(bits=m,real=N), selector z, then consume every s/q final as one
RequantClaims group through the same advice A9 certificate at the actual point.
No output table is committed.
The derived output is zero at padding, so no output mask is omitted here.

### 2.3 Ids, expected bytes and proof framing

Stage id j is in [1,2^20). Let S=j*2^40; the enclosing expected statement reserves
that interval for this operation's new source/tensor/descriptor ids. Advice
source id is S+2. The lookup ids are S/16+8 and S/16+9 (input, advice). A5 keeps
its actual derived ids: tree=4*lookup_id+2*repetition+side and
leaf=8*lookup_id+4*repetition+2*side. They are scoped by the bound A5 statement;
they are not asserted to lie in the new source/tensor interval.
Their multiplicity source ids are S+16+2*b+k for lookup b=0,1 and repetition
k=0..r-1. Constituent descriptor ids are S+4096+ordinal; the aggregate A3 id is
S+1024 and output A1 id S+2048. The verifier rejects J>=2^20.
The three A9 Functional ids are S+3072+group, for group 0,1,2 in §2.3.
Byte-plane tensor ids are S+2^24+t: input planes t=0..3, advice t=4..4+R-1.
Public sigma/eq ids are S+2^28 and S+2^28+1. The expected input source id is
at least two and outside this reserved interval. The verifier checks all
arithmetic and distinct ids before replay. No claim is routed by a proof id.

Construct input/advice A5 descriptors with the actual definition-generated
range_8 Table, all-one selectors on their complete physical message cubes,
group exponent min(total_bits,30), r repetitions and mu layouts (id,ell=0,
blowup=1). These fixed layouts do not select a profile. Every A5 root/leaf/source
and multiplicity consumer runs unchanged, including all structural zero terms.

All unsigned integers are little-endian, K encodings canonical RFC-0003.
The RequantStatement absorb payload is exactly: u8 version=1, u8 field degree,
u32 j, u64 n, u8 m, u16 mantissa, u8 shift, u8 bits, u8 r,
u8 advice blowup, u16 bound-record length followed by the complete rederived
RFC-0022 bytes; input 105-byte context and 32-byte certificate id; advice
105-byte context and 32-byte certificate id; z's m K values then y_z.
Its length is 297+bound_bytes+(m+1)*sizeof(K). Nothing is inferred from a hash
supplied alongside changed data. No cqis_id, passport or generic plan format is
created by these operation bytes.

RequantConstraints bytes are u32 j,u8 m,u32 input_count, the common input ids as
u64 in their exact order, u32 J, then for each ordered constraint u64 id,
u8 conservative degree,u32 term_count and its ordered terms. Each term is its
canonical K coefficient,u8 factor_count, then u32 factor ordinals as in A1.
Zero claimed sums are implicit; there is no duplicate input roster per constraint.
These bytes contain no gamma. After the J draws, the actual A3 Zero frame binds
the complete aggregate descriptor with its sampled coefficients before any
ZeroWeight or round draw.

RequantClaims bytes are u32 j,u8 group (0=input A3,1=advice A3,2=output advice),
the full 105-byte source context and 32-byte certificate id, u32 claim count,
u8 m, the actual m-coordinate position point, then each ordered u32 physical
row,u64 tensor id,K claimed value. Rows/ids/counts come from the exact returned
input list and schema, never a supplied roster. Group order and all values are
fixed before its independent weights. The existing A9 Opening frame subsequently
binds the actual functional, including all coefficients and expected scalar.

The proof is u8 version=1,u8 field degree; 32-byte advice root and its complete
A9 certificate packet; the input A5 proof; the advice A5 proof; the aggregate
zerocheck packet; its input and advice A9 openings; the output A1 packet and its
advice A9 opening. An arithmetic packet contains
exactly m*(delta+1) canonical K round values, ordered round-major, then one final
per actual ordered input. Skip=0 has no skip values. Public inputs have no
opening packet. There are no supplied counts, points, ids, callbacks,
length prefixes, records or alternate schedules inside arithmetic packets.

If C_A is the advice certificate size, L_U/L_A the two full A5 sizes and O_f
the A9 opening size for a referenced source, exact total length is
`2+32+C_A+L_U+L_A+sizeof(K)*(8m+7+R+w(Q))+O_input+2*O_advice`.
Both arithmetic instances have conservative degree three; their input counts
are 5+R and 2+w(Q). No weights or aggregate scalars are proof-supplied.
Derive the complete schema and all sizes before parsing/replay; reject extra,
missing, noncanonical or overflowing data and allocation/resource failures.
A9 column payloads are authenticated before field decoding, as in A9; preflight
must not change its error precedence. Source/code policy is derived, never a
proof-selected weaker certificate or retry budget.

### 2.4 Transcript and ownership

Import the expected input certificate through actual A9 verification. A helper
derives the advice Source from the fixed layout/id and supplied root, preflights
its packet, invokes actual A9 certificate verification and returns the genuine
handle plus separate registration Usage. No registration helper grants Requant
acceptance. Caller-owned input/advice and all 2r multiplicity handles outlive the
closed borrowed record. Import multiplicities with each actual A5 registration
helper against its derived context; retain their ordered handles and separate
registration Usage. Do not return a self-referential owner-plus-borrowed-record
object. The closed verifier compares complete contexts and exact packet certificate
identities through the real A5/A9 consumers; a metadata cache cannot replace them.

Before outer transcript mutation, derive all dimensions, J/term counts, lengths,
resource limits and the complete wire partition; check version/field/length and
canonical arithmetic values. Check outer input/advice source/packet identities
before RequantStatement. Each unchanged A5 checks its own mu contexts/packet ids
before its own LookupStatement; do not duplicate those hashes in the outer
prelude. Preserve each A9 authentication-before-column-decoding rule.
The local non-transcript H maximum is one advice packet-id hash plus both actual
A5 max_local_hashes values plus H_input+2*H_advice, where
H_source=q_o*(1+path_height). Check additions/multiplications before work. Keep
standalone certificate imports disjoint. Bound total absorb payloads from the
exact outer frames and existing child formulas; checked Limits cover padded
positions, proof bytes and cumulative public payload, never only one allocation.
Parameter/bound/source/shape/resource failures return typed causes before replay;
executed child failures preserve their actual cause and consumed-prefix Usage.

Absorb RequantStatement once, then run the complete input A5 invocation, the
complete advice A5 invocation, RequantConstraints and its J independent weights,
aggregate A3, its input/advice RequantClaims groups and genuine A9 consumers,
then output A1 and its RequantClaims/A9 consumer, in that order. Add the registry
absorb strings `stele/v0.1/requant/statement`, `stele/v0.1/requant/constraints`
and `stele/v0.1/requant/claims`, and challenge string
`stele/v0.1/requant/weight`. Draw independently through the actual Transcript,
never powers of a single draw or externally generated coefficients. The exact
weight count is J+4+R+1+w(Q). Four distinct RLC records account for these groups.
Each A5 retains its all-units -> all-multiplicities -> all-pairs order. Its mu
roots/certificate identities and full proof hash never enter the earlier outer
prefix. Standalone certificate import does not move their outer absorption.

Any error aborts the entire enclosing attempt. Return no partial accepting record
or permission to continue; retain failed-prefix transcript/hash Usage and every
attempted standalone registration separately. No challenge resampling, transcript
rollback or source replacement is permitted. Successful records borrow actual
source handles and retain every A3/A1/A5/A9 obligation, not only a digest or bool.

## 3. Prover algorithm and cost

Read input bytes, generate the exact advice and register its one source. Generate
the two A5 proofs, then actual A3/A1 proofs and three genuine functional openings in the
specified order. No plaintext checker, independently reinterpreted source or
host receipt substitutes for a consumer. The dense CPU reference may retain the
full input/advice matrices; it does not claim streaming or private memory.

For P=4+R planes, N padded positions and E total constituent terms, source
generation and combined constraints cost O((P+E)*N) in T_witness/c_a/T_misc.
Charge c_c for the new R*N-symbol advice registration, all A5 mu registrations,
and all complete A9 encodings/trees/openings; c_lu uses 4N and RN positions,
not only n real rows. Charge actual A3/A1 work and the unchanged Table consumers.
Source preparation is separate from input registration lifetime. Retain all
proof bytes, source/certificate buffers and actual simultaneously live states.
There is no measured constant, fitted speed claim or privacy-overhead result.

This operation reads no weights. It does not establish that adding it to an
inference preserves one weight pass: an accepted integration must collect all
emitted weight functionals in its actual single visit. The complete original
E7-01/E7-02/E4-04 costs and pass criteria remain required.

## 4. Verifier algorithm and cost

Derive the closed schema, static record, ids, masks, expected proof shape and
resource maxima from the expected statement; compare the actual bound record
before any proof replay. Import real certificates, bind their full identities,
then execute §2.4. Actual A5 successes supply byte ranges on the same near messages
used by every arithmetic consumer. Actual A3 successes establish all real rows,
padding, carries and whole bounds. Actual A1 closes the incoming output claim.
Only their conjunction creates the conditional integer record.

Use no_std+alloc, checked arithmetic, fallible reservation and typed errors;
no panic paths, public all-success constructors or unverified callbacks.
The implementation stays in stele-reductions with its existing CQIS/GKR/PCS
dependencies. Arithmetic and certificate engines remain their existing owners.
This delivery adds no top-level verifier dependency edge or full artifact codec.
Verifier work is the sum of actual child verifiers, O(N+m+E+P+J) public coefficient
work, complete table/selector costs and every opening's row/column/hash work.
Resource maxima charge all failure prefixes; actual successful Usage is not an
adversarial/lifetime cap or a profile certificate.
Count live a/b coefficient buffers. The two A3 groups may reuse b only if the
implementation actually retains that same vector; output uses its own point.

## 5. Soundness and retained boundaries

Use an unconditional union of child failure events. The deterministic implication
below holds when the actual A9/A5/arithmetic predicates are true; probability
arguments condition only on a prefix before a fresh draw, never on future PCS
or hash success. Unique near messages at source fixation supply fixed M31 input
and advice tables. A5 byte membership and all retained zero constraints give canonical
input bytes and byte/carry representations. Cap columns have sides below 512;
Boolean checks are field-faithful on byte inputs. The six role columns use the
actual RFC-0022 strict p/2 bounds. The u+s=v columns have sides below 512; the
target relation has sides <=2H<p/2. These are static derivations, not observations.

Thus input_lhs=input_rhs gives U-V=(1-2s)v; product gives a=v*mantissa;
bias=division with 0<=r0<D gives the unique q=floor((a+h)/D).
The target and sign equations give exactly the Accepted signed result, including
both ties, e=0, -H, forbidden +H and negative-to-zero. The actual output A1
therefore proves the MLE claim of this fixed output vector.

For a false fixed constraint list, select any false Boolean position. At least
one constraint value there is nonzero. Conditional on all other independent
gammas, its coefficient makes the aggregate value uniform, so the probability
the aggregate polynomial is identically zero on the cube is at most 1/|K|.
After gamma fixation, actual A3 contributes 4m/|K| at skip=0; retain all three
SC records, including zero numerators. After its complete finals, a false fixed
lane-claim vector likewise has at most 1/|K| probability of a true random linear
combination. Charge that term separately for each of the two A3 source groups
and the output advice group. Source/claim fixation before independent sampling
is essential; neither argument is about a vector chosen after its weights.
These are direct finite-field linear identities, consistent with the fingerprint
argument in [Thaler §§2.2,3.4](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf).

Retain four RLC records (stage, phase 0..3, actual draw count, field degree,
numerator=1), totaling 4/|K|, and output A1's 3m/|K|. The phases are constraint,
A3 input, A3 advice, output advice. This new batching is independent-weight RLC,
not RFC-0006 A2's powers of one gamma; its records cannot use A2's formula or
claim A2 execution. Each whole-source A5 contributes its joint LU identity and
all individual A3/SC/RLC/PCS terms exactly as A11; there is no shared LU draw or
squaring of child failures. Retain every individual A9 opening, original
certificate lifetime, standalone registration and A8 classical-hash obligation.
Deterministic byte restriction and radix reconstruction add no random term.
The new frames/weights add actual transcript work and the four explicit RLC
losses, not a Fiat-Shamir theorem. All failed-attempt draws remain chargeable.

| Claim | Status |
|---|---|
| Integer equivalence and byte/cap reconstruction | Exact, under the checked source/range/arithmetic predicates |
| Interactive reduction soundness | Conditional union of the existing proven A1/A3/A5/A9 terms |
| Fiat-Shamir/hash profile total | Unadmitted; Q12 and deterministic adversarial/lifetime caps remain |
| Standard or treaty admission | Neither; r and an unmasked cut do not select a profile |
| Joint privacy | Unadmitted; the cut may disclose accumulator/output information; Q29 remains |

**Matmul boundary:** a claim on C modulo p cannot authenticate arbitrary int32
bytes. C=0 and acc=p with (mantissa,shift,bits)=(1,31,8) demonstrate the alias:
their field values agree and their valid Requant outputs are 0 and 1. A centered
bridge requires actual source range consumers establishing the true dot bound
|C|<=B, an actual bound on the advice accumulator |U-V|<=B, 2B<p, and an actual
row equality connecting the same C producer to the same U byte planes. A format
tag, a bound only on C, or relabeling an advice final is insufficient. Current
signed-residue matmul sources also need actual signed-range consumers or an
accepted offset-byte/signed-view adaptation. This RFC admits none of those
missing adapters; it retains wider dots/chunking/packing and all parent criteria.

## 6. Negative controls and native delivery

Reserve the following controls on acceptance. Native delivery must execute the
specified actual consumer and record its precise wrapped cause, not credit an
unrelated earlier failure.

| Id | Changed value / binding | Required rejecting consumer |
|---|---|---|
| NC-0308 | one int32 input replaced by a field-congruent value in advice/arithmetic | genuine input group A9, ValueMismatch |
| NC-0309 | one separately verified advice handle substituted under unchanged packet | outer CertificateContext / CertificateIdentity |
| NC-0310 | shared t=65537 for (1,0,8), q=1 with valid low division columns | full-width result cap, actual A3 FinalEvaluationMismatch at m=0 |
| NC-0311 | one interior carry above its static cap or one altered column carry | actual A3 FinalEvaluationMismatch at m=0 |
| NC-0312 | one group row index used by the producer for the wrong plane | actual A9 ValueMismatch on its unchanged expected functional |
| NC-0313 | s=1 at v=0, or positive q=H | actual sign/target A3 FinalEvaluationMismatch at m=0 |
| NC-0314 | one padded position or reserved-plane byte is one instead of zero | actual A3 padding/zero relation, RoundSumMismatch or FinalEvaluationMismatch |

Use actual honest baselines and change one value;
rebuild dependent messages only as the applicable control workflow permits.
Existing NC-0100/0101 must reach real rounding/remainder consumers, NC-0109 the
real expected static validator, and composed NC-0606/0610/0802 the actual source
and following-instance checks. NC-0802 must independently cover RequantStatement,
RequantConstraints, each RequantClaims group and the final A9 response. Independent
weight ordering/omission tests must reach their actual arithmetic/source consumer.
Reservations/reference evidence are not native
catalog completion. No verifier bypass or fake certificate is permitted.

Native delivery requires both fields/repetition counts, the full supported
Requant parameter domain, boundary/overflow decisions, n=1 and non-power-of-two
lengths, zero caps, zero-valued factors, all source/plane/padding substitutions,
malformed/preflight/failure/lifetime checks and independent Python/native full
wire/decision/claim/record/Usage/continuation parity. Preserve full existing
corpora; use bounded fixtures for added protocol cases, not another unrelated
exhaustive numerical campaign. Record complete registration/prove/import/verify,
proof-byte and peak-memory evidence with every binding enabled. Required native,
repository and accounting gates remain; GPU work requires parity.

## 7. Open questions and task boundaries

Q26 retains canonical full model/quantiser/plan/bound-set identities, all other
operation schemas, configured source authority, native model parity and fidelity.
Q28 retains signed/packed matmul mapping, the actual centered/wider integer bridge
and complete one-pass integration. Q12/Q29 retain full profile/privacy contracts.
These are recorded questions, not permissions to substitute an unchecked adapter.
E7-01c reviews this contract; native Requant is a distinct sequential delivery.
E3-07/E5-03/E6/E7-01/E7-02, W8 GPT-2-small and all scale/architecture criteria
remain incomplete. The operation statement is not a replacement plan format.

## 8. Amendment log

Initial Draft: explicit cut/fixation and complete integer/source consumers for
the already Accepted Requant semantics. Review, exact control reservations,
companion amendment/index/ledger/task updates and execution evidence are pending.
