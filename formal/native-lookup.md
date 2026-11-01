# Conditional grouped lookup with certified original sources

Status: Draft for RFC-0008 A5, RFC-0012 A11 and RFC-0020 A6. No production
behavior is authorized until coordinated acceptance. This specifies field
membership against the unique near messages of actual RFC-0010 A9 sources.
It does not establish CQIS ownership, range dominance, privacy, either profile
or Fiat–Shamir soundness. Full E3-07 requirements and Q12/Q29 remain open.
Here A3 denotes RFC-0008 A3; A8/A9 denote RFC-0010 A8/A9. Sumcheck A1 is
RFC-0006 A1, and transcript A1 is RFC-0012 A1.

## 1. Statement and expected data

Only canonical K=QM31/OM31, degree d=4/8, is supported. The verifier supplies
an immutable descriptor with u64 lookup id <2^60, 0<=m<=59, 0<=b<=min(m,30),
repetitions r in {1,2}, a complete validated RFC-0021 Table, N=2^m Boolean
selector bytes, c original verified certificates, and r multiplicity layouts.
The Table determines ordered real tuples T, t in [1,65536], padded length
n=2^k and c in {1,2}. Use the actual generated/definition-checked Table object;
a TableId, arbitrary rows or truth callback alone cannot replace it. Its
canonical integer encodings lift by RFC-0021 §4; its real tuples are distinct.
Bind complete descriptor and table-data bytes, not just shape or name.
Table data retains its canonical signed-i32 encoding. Membership/histogram
arithmetic embeds those integers with M31/K::from_i64; it must not compare a
negative signed entry directly with an unsigned canonical source residue.

Each original certificate identifies an A9 canonical M31 matrix with exactly
N message entries. Its physical row and column bits may differ among sources;
their sum is m. All c+r original/multiplicity ids are distinct and >=2.
Original contexts, roots, certificate identities, tuple-column order, Table,
selectors and dimensions are fixed before unit challenges. Selected positions
assert membership of the corresponding original field tuple in T; unselected
positions assert no membership. A literal selector does not certify a plan's
padding, attention mask, source ranges or CQIS semantics. No lookup value or
tree intermediate is newly committed.

Set B=2^b<p, G=N/B and h=m-b. Position i has MSB-first bits; its group is
floor(i/B). For repetition j, theta_j has h independently drawn K coordinates
and U_j(g)=eq(bits(g),theta_j). Honest multiplicities are
mu_j[tau]=sum_(i:selected and x_i=T_tau) U_j(floor(i/B)). These K values need
not be integer counts. Their physical limbs, roots and certificates may depend
jointly on all theta vectors, but must be fixed before every beta/alpha.
There is one mode, grouped equality units; m=b is its ordinary bounded case.
Neither extension degree nor repetitions permits b>30.

A multiplicity layout is (u64 id,u8 ell,u8 blowup), with 0<=ell<=k and blowup
in {1,2}. It fixes R=2^ell, S=2^(k-ell), C=S*d and the existing Circle code
whose message exponent is k-ell+log2(d). Its only prover-chosen context field
is the 32-byte root. Derive the complete A9 Source from these expected values;
field, policy=1, layout=0 and canonical code identity are not proof choices.
The physical message has n*d canonical M31 limbs in record-major order
L[i*d+a]. The limb axis stays entirely in columns. Define the logical tensor
mu[i]=sum_a e_a L[i*d+a] for i<t and mu[i]=0 for t<=i<n, where e_a is the
RFC-0003 A1 ordered basis. Physical tail limbs are ignored by this definition;
no claim that a certificate proves their zero value is made. Honest producers
write zero tail limbs for deterministic bytes. This view is lookup-specific;
it grants no general source-view, integer-packing or stacked A4 permission.

## 2. Actual multiplicity functional

At the actual table-tree point x in K^k, write i=u*S+v, t=q*S+s with
0<=s<S. Let A[u]=eq(x_prefix,bits(u)), E[v]=eq(x_suffix,bits(v)).
The exact logical MLE is the sum of these disjoint rank-one functionals:

| Piece | Row coefficient a[u] | Column coefficient b[v*d+a] | Exists when |
|---|---|---|---|
| 0 | A[u] * 1[u<q] | E[v] * e_a | q>0 |
| 1 | A[u] * 1[u=q] | E[v] * 1[v<s] * e_a | s>0 |

The identity follows from 1[u*S+v<t]=1[u<q]+1[u=q]1[v<s]. At t=n, q=R,s=0
and only piece 0 remains. At q=0 only piece 1 remains. Omit only structurally
empty pieces according to these public integers, never a piece whose sampled
weights or claimed value are zero. One or two ordinary A9 openings consume
the complete functionals in increasing piece order. Their claimed values sum
exactly to the actual emitted table numerator; there is no random batching.
Use the actual shared MSB equality-table builder and canonical field basis.
Do not pretend this is a point opening on an unsupported K-valued A9 source.

A8/A9 fix an M31 oracle. Outside their charged certificate failures it has a
unique near message L*. The base-field argument adopted in tensor-opening.md
§3 shows L* is M31-valued: any nonbase encoded component has weight <=e<D,
so distance and injectivity force it to zero. Basis reconstruction and the
prefix projection above therefore define one fixed logical K tensor.
If the claimed MLE differs, at least one consumed piece value is false.
Apply that actual individual opening's existing bound; reconstruction adds
no challenge, Schwartz–Zippel term, code assumption or range proof.

## 3. Canonical statement, wire and ownership

All integers below are little endian. K values use RFC-0003 A1 serialization;
reject noncanonical limbs, never reduce wire values. No implicit alignment,
terminator, omitted-zero field or proof-selected dimension is admitted.

Statement bytes are, in order:

1. u8 version=1, u8 d, u64 lookup id, u8 m,b,r,c, u32 t, u8 k;
2. u32 length and complete canonical Table descriptor bytes; u32 length and
   complete Table data bytes from the actual RFC-0021 encoding;
3. u64 N and exactly N selector bytes, each 0 or 1;
4. c ordered 105-byte original A9 contexts, each followed by its 32-byte
   verified certificate identity;
5. r multiplicity layouts (u64 id,u8 ell,u8 blowup), in repetition order.

Lengths/values are rederived from expected objects, not adopted from proof
metadata. Source roots/certificate ids in this statement are verifier-owned.
The selected r=1/2 does not imply standard/treaty admission.
If Dbytes and Tbytes are the two encoded table lengths, statement length is
exactly 35+Dbytes+Tbytes+N+137*c+10*r bytes.

The unverified lookup proof is u8 version=1,u8 d, followed by r registration
packets, then r repetition packets. Registration j is a 32-byte mu root then
the complete A9 certificate bytes, whose length follows from layout j.
Repetition j is, in this exact order: A3 lookup-tree proof, A3 table-tree
proof, A3 selected-product proof, c original A9 opening proofs, all p_j
multiplicity piece values, then p_j A9 opening proofs. p_j is the number of
structurally present pieces. No counts, ids, points or length prefixes occur
inside these packets. Existing A3/A9 codecs supply every inner byte contract.

For w=4d, tree length Fbytes(v)=w*(2+2v^2+3v), leaf length
Lbytes(m,c)=w*(4m+c+2). Let C_j and O_j be the A9 certificate/opening lengths
for mu layout j and O_a the original opening lengths. Exact total bytes are

`2 + sum_j [32+C_j+Fbytes(m)+Fbytes(k)+Lbytes(m,c)
            +sum_a O_a+p_j*(w+O_j)]`.

Decode against the expected statement. The verifier validates all wire lengths,
versions, canonical K rows/A3 proof values, source rosters and checked size
arithmetic before outer transcript mutation. A3 shape checks use m,b,k and fixed lengths; no
provisional theta value becomes transcript authority. Authentication and
column equations still run at their real A9 consumer, preserving its errors:
authenticate each response before decoding its M31 column limbs. Preflight
must not decode unauthenticated columns or change that precedence.
Reject truncation, trailing bytes, unsupported source geometry, overflow and
caller resource-limit violations; no partially accepted object is returned.

The caller owns the original and mu VerifiedCertificate handles. A registration
helper may derive each expected mu context from its layout and packet root,
preflight every registration packet, invoke actual verify_certificate in order,
and return the handles plus each independent registration Usage. Its result
certifies no lookup. Any failure returns no partial handle roster. These
standalone certificates may be verified before replaying the outer transcript;
their own public inputs and draws do not depend on outer execution order.

The closed lookup verifier borrows those actual handles. For every mu packet,
compare full expected source bytes, parse the complete certificate, and recompute
the actual A9 certificate_id over expected source bytes and that exact payload.
Require equality to the opaque handle's identity. This is A9's collision-accounted
digest identity, not literal storage of verified bytes or a fresh verification.
Charge the real ID hashes. No digest constructs a handle; no proof-supplied
receipt, bool, arbitrary authentication callback or unverified record is accepted.

The producer can own its temporary mu limbs, preparation, certificates and
verified handles throughout one complete call, then return only unverified
proof bytes and descriptive usage. It must call actual preparation/certification
and opening producers. Do not return self-referential records, replay an A3
transcript to recover a point, or invent certificate records from metadata.
The closed verifier's successful record borrows all certificate handles and
retains the actual A3 results and actual A9 OpeningRecords. Its fields are
private, readable without public construction or deserialization. It cannot
outlive any original or mu certificate. Parsing and registration alone cannot
construct it. Every failure aborts the entire enclosing attempt.

## 4. Complete transcript and consumers

Use the existing Transcript object and A1 capped sampler. New labels have
prefix stele/v0.1/lookup/ and the following exact typed suffixes:

| Typed choice | Suffix | Kind |
|---|---|---|
| LookupStatement | statement | absorb |
| LookupUnits | units | absorb |
| LookupMultiplicities | multiplicities | absorb |
| LookupRepetition | repetition | absorb |
| LookupMultiplicityClaims | multiplicity-claims | absorb |
| LookupUnit | unit | challenge / joint LU identity |
| LookupBeta | beta | challenge / joint LU identity |
| LookupAlpha | alpha | challenge / joint LU identity |

1. After complete preflight and mu-handle identity checks, absorb Statement with
   the exact expected statement bytes. Mu packets/roots/identities do not occur
   in that payload or in caller-supplied pre-unit public data. Original sources,
   Table and selector do. A caller must not seed this transcript from the full
   proof or its digest; that would alter the theorem's fixation order.
2. For j=0..r-1 absorb Units(u64 id,u8 j), then draw h Unit values in MSB group
   coordinate order. Complete every vector before binding any mu context.
3. Absorb Multiplicities(u64 id,u8 r, then for each j: u8 j,105-byte expected mu
   context,32-byte verified certificate id). All r contexts bind before any
   denominator draw. No root can change afterward.
4. For j=0..r-1 absorb Repetition(u64 id,u8 j,u8 phase=0), then draw Beta followed
   by Alpha. Finish all r pairs before any tree proof. Independent draws may
   coincide by chance: never enforce inequality, resample a pole or share units.
5. For each j in order absorb Repetition(id,j,u8 phase=1), then execute the
   following complete sequence. Derived tree ids are 4*id+2*j+side, side=0/1;
   their leaf ids are 8*id+4*j+2*side and that value+1. These ids are scoped
   tree identities, not aliases for original source or multiplicity ids.
   The lookup descriptor has depth m, group depth b and theta_j; the table
   descriptor has depth k, b=k and no theta.
   - Execute actual A3 lookup-tree reduction on leaves
     (sigma_i,1-sigma_i+sigma_i*(alpha-sum_a beta^a*x_i,a)).
     Execute actual A3 ordinary table-tree reduction on real leaves
     (mu_j[i],alpha-sum_a beta^a*T_i,a) and padded leaves (0,1).
   - Consume both bound roots with actual check_roots: both denominators must
     be nonzero and cross multiplication must agree. No supplied nonzero value
     substitutes for either reduced root. Any pole rejects this attempt.
   - Evaluate the actual validated Table at the actual table-tree point.
     Its denominator must equal `1+(alpha-1)*valid_rows-sum_a beta^a*columns[a]`.
     The separately returned valid_rows MLE is essential for non-real rows.
   - Pass the actual lookup Reduction, fixed selector and this pair to the
     actual A3 SelectedProduct. It consumes both incoming values, Eq and sigma,
     and returns every original column at its actual returned point.
   - Consume all c returned original claims, in source order, with actual A9
     verify_point and the matching certificate. Opening id is the original
     source id within this already-bound repetition. Zero beta powers, zero
     selectors and unused/zero finals exempt no source.
   - Read all expected piece values; require their exact sum to equal the
     actual table numerator. Absorb MultiplicityClaims(u64 id,u8 j,u8 p_j,
     k actual point coordinates,actual numerator, then each u8 piece index
     and its K value). All piece values bind before any piece opening query.
   - Construct each expected functional from §2 at that same actual point and
     invoke the actual A9 verifier in piece order, with local opening id equal
     to piece index 0/1. It verifies the full row/equations/responses. The
     preceding source opening ids are >=2, and all operations retain context.
6. Return a complete conditional record only after every check/consumer. A9
   response absorption and A3 final absorption precede any next repetition or
   external continuation. No remaining original claim is silently discarded.

Producer preflight checks expected statement, originals/layouts, static byte
sizes, addressability and limits, without requiring mu packets/handles that do
not exist yet. After all Unit draws and before Multiplicities it constructs
the actual mu sources/certificates and verifies them to obtain handles. The
verifier instead preflights the already supplied complete proof/handles. These
different preparation schedules share the identical outer transcript sequence;
standalone registration transcripts remain separate. The producer uses actual
returned A3 points. Failure,
inner sampling exhaustion, allocation failure or pole discards the entire
attempt and permits no rollback, alternate layout, hidden retry or fallback.

## 5. Conditional soundness and accounting

The grouped identity proof in weighted-logup.md §§1-3 applies to the fixed
unique original near messages and exact public selectors/Table. Each group
contains at most B<p selected positions. For a bad selected tuple, compression
collision contributes (c-1)t/|K|, its bad-fiber unit polynomial at most h/|K|,
and a fresh nonpole alpha root at most (N+t-1)/|K|. Thus

`e_LU=min(1,(h+N+c*t-1)/|K|)`, and the r identity events cost at most e_LU^r
under this exact all-units/all-mu/all-pairs schedule. Mu may depend jointly on
unit vectors; it is fixed before every beta/alpha. No GKR/PCS/binding error is
squared. Do not condition away aborts or replace char(K) by |K|.

For F(v)=3v(v-1)/2+2v, each repetition adds [F(m)+F(k)+3m]/|K| from actual A3
trees/selected product. Every scoped A1 record, Gamma and Fold count remains
separate and checkable. Lookup draws are r*h Unit,r Beta,r Alpha; tree draws
are r*(m+k) Gamma and Fold each; A1 rounds total
r*[m(m-1)/2+k(k-1)/2+m], all individual degree 3. Zero-depth trees have no
tree draw, but the prescribed scalar leaf finals and all source consumers stay.

Keep every original/mu registration's actual certificate tensor/query term,
each of r*c original openings and sum_j p_j mu openings, and A8's complete
bounded-lifetime collision/late-preimage obligations. An adaptive first-false
piece/source value is handled by the existing individual A9 argument; earlier
true checks do not justify removing later opening terms. Existence/uniqueness
and M31 membership of near messages are conditional on the adopted A9 theorem;
they do not identify an external checkpoint, input or packed integer tensor.

The immutable result retains lookup id, d,N,t,c,b,h,r and identity numerator
h+N+c*t-1 with exponent r; actual scoped tree/leaf records; and ordered actual
OpeningRecords referencing original certificate losses. No probability float,
proven flag, synthetic success record or profile total is produced. The outer
Usage has one cumulative outer transcript snapshot plus disjoint local hashes.
Standalone registration usages are a separate ordered list, never falsely
reported as an outer cumulative snapshot or double-counted when reused. Failed
registration/outer calls retain observable actual usage but no acceptance record.
External composition owns lifetime/attempt/adversarial query caps fixed before
execution; local successful-work counters cannot supply them.

Failure observations include every executed local hash even when the outer
transcript is unchanged. Registration failure preserves the ordered usages of
all earlier certificates plus the failing call, while returning no handles.
Outer failure preserves its cumulative transcript snapshot and disjoint local
hashes (including certificate-ID comparison and table encoding); it does not
claim that externally performed registration work occurred inside the call.
All counter additions are checked before unrecorded work. No unused capacity
or assumed adversarial cap is substituted for the actual observed prefix.
The closed verifier preflights the checked local-H maximum
`1+r+r*sum_a[q_o,a*(1+path_height_a)]
 +sum_j[p_j*q_o,j*(1+path_height_j)]` before subcalls: one Table encode, r
certificate replay-ID hashes and the actual individual Merkle paths. This is
an execution bound, not an adversarial cap. Count the executed prefix on failure;
standalone registration remains separate, with its own checked A9 work.

Normative outer errors and their precedence are:

| Condition | Error |
|---|---|
| Unsupported expected field/id/m/r/table width/layout | Statement |
| b>min(m,30) | GroupBound |
| Selector length or Boolean encoding | Selector |
| Original ordered certificate count/id/dimensions, duplicate ids | SourceRoster |
| Mu handle count or full derived source context differs | CertificateContext |
| Same-source handle id differs from recomputed exact packet id | CertificateIdentity |
| Outer version/length, trailing data or packet roster | ProofShape |
| Public point denominator differs from actual table-tree Q | TableDenominatorMismatch |
| Sum of all declared piece values differs from actual table P | PieceSumMismatch |
| Caller limit exceeded / checked arithmetic or allocation fails | ResourceLimit / Capacity |

Check expected structure/limits first, complete wire shape/canonical K values
second, and certificate context then digest identity third, before Statement.
During execution preserve actual wrapped A3 errors (including Pole, RootMismatch
and SelectorMismatch), PCS errors, Table errors and Transcript errors. Do not
flatten an actual earlier failure into a later generic membership error.

| Claim | Status |
|---|---|
| Grouped rational identity and rank-two reconstruction | Conditional interactive algebra with the stated fixed-data hypotheses |
| A3 and A9 consumer errors | Existing individually accounted conditional bounds |
| Concrete Fiat–Shamir/QROM composition | Q12 unresolved |
| Private sources, joint ZK, standard/treaty, inference | Unadmitted |

## 6. Complete costs and resource admission

All sizes, shifts, sums and products are checked, including isize addressability
of K selectors, frames, coefficients and Dense buffers whenever their lengths
are known. m<=59 is a symbolic cap, not a claim that every such dense shape can
execute. Caller-owned limits cap
positions, serialized public bytes, complete proof bytes and dense producer
elements before corresponding work/allocation; they are admission policy,
not proof-selected metadata or measured soundness bounds. Allocate fallibly.
The verifier never allocates a message-sized matrix merely from a proof root.
Literal selectors and canonical public Table are expected inputs; their scan,
framing and evaluation costs are charged even when reused in one invocation.
Table::encode executes one ordinary descriptor-identity BLAKE3 hash. Its actual
call and every repeated identity/validation hash must be included in disjoint
local H, including failures after hashing. Reuse canonical encoded bytes within
the invocation; do not silently repeat generation/encoding or label that work
as a transcript evaluation. The implementation must preserve exact hash counts
on pre-hash and post-hash failures, not infer them from successful output alone.
Concretely, preflight the actual immutable descriptor's encode(),
entries.len()==padded*c, and the checked canonical data header plus 4*padded*c
length. Reserve one checked local H immediately before Table::encode. For that
same immutable object its repeated size/descriptor checks now cannot fail;
the identity hash precedes the remaining fallible allocation. Retain count one
on that allocation failure; counter overflow aborts before invoking encode.
Reuse the bytes and make no extra identity/validate_encoding call. The first
descriptor encoding is still charged runtime work, although it performs no H.

Preparation charges source/table validation and indexing, all c*N source
entries and selectors, grouped histograms and r weighted accumulators, complete
limb conversion/storage and real A9 mu preparation/encoding/Merkle construction,
certificate production and verification. Using public row order and integer
input keys, table indexing must have an explicit implementation cost; do not
claim an unspecified dictionary has worst-case constant work.

Reuse the existing A3 engines. Charge retained levels (2N-1 pairs per lookup
tree and 2n-1 per table tree), A1 copies, selectors, original K conversions,
mu limbs/values, proofs, coefficients and their actual overlapping lifetimes.
Discard each tree's temporary levels before subsequent phases when its real
producer permits it. Do not add a transcript replay or a second tree to acquire
points. Public denominator evaluation uses Table::evaluate, O(n*c) work.

For mu geometry R,C, each actual opening charges O(R*C) row preparation,
complete Circle encoding, O(C) scalar work, q_o authenticated R-limb columns
and all paths/responses; both pieces pay separately. Equality/mask coefficient
construction costs O(R+C) per piece with the shared linear equality builder.
An R=1 layout can reveal the full limb row; no choice here is a ZK claim.
Original point openings and every certificate retain their complete A9 costs.
Report c_lu/c_sc/c_c/T_misc, full preparation/producer/verifier times and proof
bytes, actual scoped allocations and fresh-worker RSS with explicit boundaries.
No fitted constant, benchmark number or one-weight-pass result is supplied by
this contract. E3-07a's arithmetic ledgers cannot replace a complete lookup run.

## 7. Controls, parity and delivery

Preserve original NC-0400..0403. Their conditional variants use the unchanged
expected statement and actual closed verifier:

| ID | One logical tamper, with genuine dependent proof work | Exact rejection |
|---|---|---|
| NC-0400 | Increment one mu entry and rebuild its real registration/trees | A3 RootMismatch |
| NC-0401 | One fixed selected source tuple outside T; truthful trees and no fabricated matching table row | A3 RootMismatch |
| NC-0402 | Build leaves/mu with one inactive position selected, retaining the verifier's original selector; use an in-table value so root equality passes | A3 SelectorMismatch |
| NC-0403 | Use pair 0 only for repetition 1 leaf arithmetic, retaining the actual independent outer draws and genuine trees | TableDenominatorMismatch |

NC-0402 establishes proof/selector consistency, not a CQIS padding authority.
Rebuilding a proof under a different verifier-owned literal selector is a new
statement, not this attack; original full-plan padding obligations remain.
A producer's refusal or codec failure is insufficient for these controls.
Use the separate control harness/ProverHook, never a verifier bypass. Honest
challenge coincidences remain valid; deterministic attack fixtures establish
that their selected challenge values differ without altering runtime sampling.

Reserve these additional controls as todo, without coverage credit:

| ID | One-value attack / boundary | Expected consumer |
|---|---|---|
| NC-0415 | b=31, exceeding the static characteristic-safe group bound | descriptor GroupBound before transcript |
| NC-0416 | one bound root denominator equals zero | actual A3 Pole check |
| NC-0417 | Change only one declared mu piece value, keeping actual table P and the other piece fixed | PieceSumMismatch before mu opening queries |
| NC-0418 | Substitute one independently verified different-root mu handle, retaining the packet/opening | CertificateContext before Statement |
| NC-0419 | For range_8, r=1,m=b=0 and one selected scalar source 256, set only mu[0]=alpha_early/(alpha_early-256) using alpha before Multiplicities; keep other mu entries zero and build actual trees under canonical later draws | A3 RootMismatch |

The NC-0419 fixture checks both early and canonical alpha are outside the
embedded set {0,...,256}, and that they differ; thus no source/table pole masks
RootMismatch. The NC-0403 fixture can use full range_8 (c=1), where unequal
alpha0/alpha1 forces TableDenominatorMismatch; different beta values alone do
not establish this when beta is unused. The runtime performs no such resampling.
Also reject a same-source/different-certificate packet identity with
CertificateIdentity. Extend NC-0610 through the complete lookup mu consumer:
change exactly one K value in a structurally present mu opening's row at a
column with nonzero expected b, leaving its registration, trees, piece claims
and all earlier proof bytes fixed. Actual A9 scalar checking must reject
ValueMismatch before column queries. This mandatory composed variant has no
coverage until native delivery. It exercises the terminal edge rather than
stopping at roots, context or piece-sum preflight. Basis/limb order and logical
tail projection require independent functional-parity cases; the piece-sum
control alone does not establish that mapping. Nonzero physical tails must be
accepted when their logical projection and every actual proof are valid.

Extend actual NC-0802 continuation controls to the new statement/multiplicity/
piece-value frames. Existing A3/A9 controls remain mandatory and cannot stand in for
these composed edges. Record opacity/lifetime compile-fail tests cover mu as
well as original certificates; invalid shape/caps fail before outer mutation.

Deliver both fields, both repetition counts, m=0, b=0/b=m, partial/full table
tails and all structurally present mask pieces, zero weights/values, poles,
unused columns, complete registration/import failures, maximum verifier shapes
and allocation bounds. Compare native and independent Python complete bytes,
actual claims/records/usage/continuation, including malformed proofs and seeded
inputs. A focused basis/mask identity corpus checks every table-tail boundary
class without claiming native PCS coverage. Complete measured lookup campaigns
must run every binding, include registration and all consumers, and preserve
clean source/raw receipts. GPU parity is required when a GPU backend is added.

## 8. Open questions and amendment history

Q31 retains full private lookup integration, plan/source ownership and complete
c_lu evidence; Q29 retains joint privacy and Q12 retains FS/profile composition.
This contract's conditional native task cannot mark those questions or E3-07
done. Existing Q20/Q26/Q28 coefficient, integer and packing obligations remain.

Draft history: specify the grouped identity with actual A3/A9 consumers,
canonical lookup-owned K-limb projection, at most two prefix-mask functionals,
caller-owned registration handles and complete wire/accounting/resource scope.
Acceptance requires Workflow02 soundness, RFC and affected-owner sign-offs.
