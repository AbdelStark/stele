# Conditional stacked runtime (RFC-0006 A4)

Status: Accepted under RFC-0006 A4, RFC-0012 A6 and RFC-0020 A2.
Native implementation and its delivery gates remain required.

## 1. Statement and source authority

For K=QM31 or OM31, prove the field relation
`v = sum_{x in {0,1}^m} A(x) P(f_0(x),...,f_(a-1)(x))`.
The expected statement fixes the consumed claim, common original layout, ordered
original identities, P, public coefficient A and elimination order. The output
claim supplies v; its point and identity remain bound even when an operation
does not use every coordinate. A producing operation must derive this relation
from that claim under its own Accepted RFC. This runtime does not prove that
derivation, authenticate a plan or admit an inference proof.

A is exactly the single selected Boolean-table MLE in
[A7](public-coefficient.md), with the same six kinds and padding rules. Extend A
and each original separately. The complete degree is delta=0 for an empty P,
otherwise `1+max(term.factor_count)`, including zero coefficients. Each P term
has at most three factors. A is uncommitted; its final is independently checked.

There are two closed source adapters: expected public originals, and A9 certified
field originals. Both take the expected statement as verifier input, never from
the proof. Coefficient source values are immutable, explicitly public inputs of
that statement, fixed before replay. A public onehot index is a u64, not an M31
residue of an integer. A source borrowed from a private witness is not a public
input merely because its digest or identity was supplied by the prover.

| Source | Authority and consumer | Disclosure and remaining obligation |
|---|---|---|
| Public coefficient indices or exact table | Actual expected public values, kind, source identity and layout in Stack; independent A7 final evaluation | Values are public by the stated relation. No commitment, CQIS or passport ownership claim follows. |
| Public original | Expected immutable K table, full bytes fixed by StackSources; direct original-MLE evaluation | All values are public. Validate zero padding before replay. |
| Certified field original | Expected opaque A9 verified certificate; StackSources fixes its complete context and certificate ID; actual A9 point opening consumes the restored claim | Unmasked A9 messages disclose linear functionals/columns. Retain every conditional certificate/opening loss. No integer or privacy admission. |
| CQIS/passport table | Its operation's actual Accepted registry/manifest consumer must derive the expected public table and identity | Passing values to RopeTables proves only the stated exact-table relation. It cannot establish CQIS provenance. |
| Committed selection coefficient, private coefficient, or virtual view | No closed adapter in this version | Reject such a request as UnsupportedSource; no fallback to public values, fresh commitment or caller authentication callback. |

The first three rows are complete conditional field interfaces. The last two
rows locate inference integration obligations without granting them authority.
Their source owner must enforce the actual public-input policy; neither an enum
tag, a successful arithmetic receipt nor this field API changes that policy.
The API accepts no profile or privacy-disable option. Full inference admission
must reject this unmasked path wherever secrecy is required.

This separates the runtime from private coefficient format and joint masking
admission. Requiring completed E12-01 before E3-06 would close the existing path
E12-01 -> E8-02 -> E8-01 -> E7-09 -> E7-06 -> E3-06 into a cycle. Q20's private
bit/paired-source studies remain candidates, with source conversion, packing,
range, complete opening costs and joint privacy unresolved. Q29 and E4-05/E12-01
retain their original requirements. No private format is adopted by A4.

## 2. Exact expected statement bytes

Integers below are unsigned little-endian. K is d canonical M31 u32 limbs in
the RFC-0003 basis, d in {4,8}; limbs >=p reject. No alignment, implicit sorting,
term normalization, terminator or suffix is permitted. Lists retain plan order.
`Layout = u8(axis_count) || each(u8(bits) || u64(real))`.
Each axis has bits<=63, `1<=real<=2^bits`; total bits<=63, axis_count<=64.
The input has at least one axis; its first axis is the layer axis, of width ell.
An output scalar may have no axes. Point length equals the layout's total bits.

Stack is exactly:

1. `u8(1) || u8(d) || u64(stage_id) || input Layout || u8(order)`, with order
   0=layer-first and 1=layer-last as in [ownership](stacked-ownership.md).
2. `u64(output_id) || output Layout || output_point K elements || K(v)`.
3. `u64(coefficient_id) || u32(a) || a ordered u64 original_ids`.
4. `u32(term_count)`; each term is `K(coefficient) || u8(factor_count)` followed
   by that many u32 original-input ordinals, all <a; factor_count<=3.
5. `u8(kind)`: 0 Eq, 1 CausalMask, 2 WindowMask, 3 OnehotSparse,
   4 GqaBroadcast, 5 RopeTables.
6. For every input axis: `u8(selected)` in {0,1}, followed when selected by
   exactly axis.bits K selector coordinates. A selected zero-bit axis is legal.
7. The kind payload from this table; end of payload follows exactly.

| Kind | Payload |
|---|---|
| Eq | empty |
| CausalMask | u8(row_axis), u8(column_axis) |
| WindowMask | the two axes, u64(positive_width) |
| OnehotSparse | the two axes, u64(source_id), u64(count), count u64 indices |
| GqaBroadcast | u8(head_axis), u8(group_axis) |
| RopeTables | u8(source_axis_count), those u8 axis ordinals, u64(source_id), u64(count), count canonical M31 u32 values |

A7 specifies every kind's axis/range/count condition. The onehot source layout
is the single row axis; the exact-table source layout is the ordered selected
source axes. Source values omit padding, with A7 supplying its zero semantics.
Original ids are distinct. The coefficient id differs from every original and
output id. An output id may alias an original only with the identical layout.
A coefficient source id differs from every original/output/coefficient id in
this version: shared-source aliases need a separately Accepted identity/view
consumer, not an unchecked assertion that two representations agree.

The proof contains only A1's round/final values and the selected adapter's
opening bytes. It never selects Stack, source mode, capacities, IDs, degree or
permutation. The descriptor's canonical encoder is also checked independently
against Python bytes; no proof-supplied descriptor parser is required for this
primitive. Parsing a persisted expected statement, when added by the full plan
consumer, must reject unknown flags/versions, noncanonical fields, truncation
and suffix bytes before constructing it.

## 3. Source fixation and replay

The closed adapters preflight the entire statement, A1 proof, source roster,
opening wires and checked capacities before any absorb. A9 certificate handles
must already exist from actual complete certificate verification. The closed
certified adapter requires every original to have the same total dimension m,
the expected tensor ID, field and complete expected context. It supports only
layouts with `real=2^bits` on every axis: A9 provides no proof of zero padding.
Padded originals use the public adapter's explicit zero check or a separately
Accepted padding consumer. A9's message row/column split is unrelated to ell;
only its total bit count matches m. No source subview is inferred from a shape.

Absorb StackSources with the following bytes:

`u8(1) || u8(mode) || u64(stage_id) || u32(a) || ordered source entries`.

Mode 0 is public: each entry is `u64(original_id)` then exactly 2^m canonical
K values in original tensor order. Mode 1 is certified: each entry is the exact
105 A9 source bytes followed by its 32-byte certificate ID. Every entry matches
the corresponding expected original. All-public and all-certified rosters are
the two complete modes; a mixed roster is not silently coerced. Both modes bind
the empty roster too. Coefficient source values occur in Stack, never this roster.

Then absorb Stack, derive the ordinary A1 Instance and run the actual A1 engine:
id=stage_id, num_vars=m, inputs=`original_ids || coefficient_id`, claimed_sum=v;
append factor ordinal a to every P term. Reuse its Instance, Round, Sumcheck and
Final bytes and ordering unchanged. No new random challenge or standalone
coefficient commitment is introduced. Public originals and every original
certificate are fixed before the first A1 challenge.

Nested A1 input i is `g_i(y)=f_i(restore_pi(y))`. Keep its raw receipt internal:
it is not an original claim at the draw-order point. After A1 verification,
restore `canonical[pi_j]=r_j`. Independently evaluate A7 at that point and require
equality with A1's coefficient final, even for empty P or m=0. Export every
original at that same canonical point, in original order, including unused and
zero-coefficient inputs. Retain the actual A1 SC record unchanged.

The public adapter directly evaluates and checks every original table. The
certified adapter, in stele-reductions, calls actual A9 verify_point on every
original using this restored point, returned value, expected certificate and
one opening wire per original, in order. Its opening id is the original tensor
ID within the already-bound stage segment. It never accepts replacement points,
synthetic opening records or authentication callbacks. The nested public A final
is already consumed by GKR and is not sent to PCS. Existing A9 FieldSources
and verify_field_sources retain their exact all-A1-input meanings unchanged.

The certified producer binds the same source roster and runs the actual stacked
A1 prover. Its Summand strategy retains the m actual challenges delivered to
fold(), restores them by pi, and prepares every A9 opening from that point and
the corresponding original final. This adds O(m) retained K elements, checked
before replay; it changes neither A1's API nor proof bytes. The verifier derives
its point independently. No guessed, caller-replaced or separately sampled point
is accepted.

Return only a complete conditional record containing the actual SC record and
every ordered opening record borrowing its verified certificate. A public record
has the actual SC record after all public checks. Kernel-only verification returns
unconsumed claims, never a closed record. Every post-absorb error invalidates the
entire attempt; discard the transcript. No partial record, rollback or retry.
Kernel callers must fix originals through their real consuming protocol before
the first A1 challenge; Stack alone cannot certify that precondition. Every
failure, including preflight, A1 and coefficient errors, exposes one actual
cumulative transcript Usage snapshot plus local work already performed. It
returns no closed record; usage is observation, not authority to continue.

## 4. Round ownership, algorithm and capacities

Use [stacked ownership §§1-4](stacked-ownership.md) with complete summand A*P,
and a+1 input tables, including A. Its representative map partitions each
current Boolean suffix exactly once. Coalesce both actual restricted endpoint
vectors at their destination before evaluating nonlinear P. Expose delta+1
partials for each of the 2^ell original padded logical blocks, including zero
slots; their sum is the transmitted A1 round at every interpolation node.
Fold every input only after the round absorb/challenge. CPU ownership is logical;
it neither implements a distributed transport nor proves a GPU weight-pass bound.

A dense reference strategy uses A1's existing Summand round/fold/final interface.
It constructs A's Boolean table independently of the verifier's A7 evaluator,
reorders original tables once and retains the same canonical originals for
public consumers. Both elimination orders and m=0 have defined behavior.
Dense copies are charged; this contract introduces no streaming claim.

All APIs use fallible allocations and checked shifts, products and conversions.
Caller-owned resource limits cap descriptor bytes, proof bytes, prepared field
entries, exposed partial entries and A7 axis-vector entries. These limits are
verifier policy, not proof metadata or a way to suppress checks. Accept only
when the computed requirement fits every applicable limit; an error creates no
record. The full plan fixes deployment limits before parsing its artifacts.
At minimum preflight `(a+1)*2^m` prepared entries, `2^ell*(delta+1)` partial
entries, `m*(delta+1)+(a+1)` A1 proof elements, StackSources/Stack lengths and
all opening lengths. Check each simultaneously retained allocation, not only
individual factors. m<=63 does not imply a table is addressable. Retained original
tables, fold overlap, proof bytes and source certificates count separately in
measured peak memory. Actual strategy capacity must be reported, not inferred
from the lower bound `(a+1)*2^m`.

Malformed statement/kind/layout/identity/degree is InvalidStacked. Wrong public
shape or nonzero original padding is PublicShape. Wrong source count/order,
certificate ID/dimension, mixed mode or unsupported padded certified layout is
SourceRoster. Unsupported source category is UnsupportedSource. A wrong A final
is CoefficientMismatch; a wrong public original final is ClaimMismatch. Capacity
errors remain Capacity. Preserve actual A1, transcript, Merkle and A9 causes,
including PCS ValueMismatch. A preflight structural error precedes replay; later
mathematical rejection may advance the transcript and still aborts the attempt.

## 5. Conditional soundness and accounting

Fix the complete expected statement, originals and public coefficient before
interactive challenges. The coordinate permutation is bijective; the restricted
state invariant proves each nested A1 final is the original MLE at the restored
point. The disjoint ownership partition proves each summed partial equals the
same complete polynomial round. A7 independently supplies its final, and all
original consumers supply theirs. A1's theorem therefore bounds false initial
relation acceptance by `m*delta/|K|`, conditional on true original evaluations.
There is no additional algebraic error for reindexing, partitioning or a fixed
public coefficient. This proof uses no inverse of a challenge or selector.

Public consumption is exact. Certified consumption adds A9's certificate tensor
and proximity terms, one ordinary opening term per original, and the existing
global hash/late-preimage and lifetime terms. Retain reused certificate losses;
never multiply a cumulative transcript snapshot by the number of openings.
For a failed opening include its actual non-transcript hash work as well as all
preceding work. Check the sum of maximum opening work before replay, preserving
the real cumulative transcript Usage and disjoint local Merkle counts.
There are exactly m Sumcheck draws, followed by each A9 opening's actual
attempted column draws. Stack and StackSources add absorbs only. The ordinary
A1 SC record includes zero-degree/zero-round records. No RLC or masked line is
inferred. The implementation must update the closed registry, inventory and
actual accounting gates together.

| Scope | Result |
|---|---|
| Conditional interactive field relation | Proven by A1, A7 and ownership, with actual original consumers and A9's stated conditions |
| standard or treaty inference admission | Neither; Q12, integer ownership/plan derivation, composition and applicable privacy obligations remain |
| Private coefficient source or zero knowledge | Not admitted; Q20/Q29 and the original private-source/format requirements remain open |

## 6. Complete costs and delivery

Let N=2^m, B=2^ell, E be P's per-row evaluation work, and s=delta+1.
Dense preparation/reordering and direct public consumption cost O((a+1)*m*N)
in the straightforward reference, with the scalar case charged separately.
Rounds/folds cost O(s*(a+E+1)*N); exposed dense partial clearing/aggregation adds
O(m*B*s). The ownership rule moves exactly `(a+1)*2^(m-j-1)` logical field values
at a layer-axis round j, zero at an inner-axis round. Physical movement depends
on placement and is not claimed by this formula. A7's selected-source evaluator,
all descriptor/source-byte scans, A1 transcript/interpolation and retained proof
work are additional. Verifier A1 work is O(m*(delta^2+1)+a+E).

For each certified original, add all actual A9 source preparation, registration,
row preparation/encoding, coefficient vectors, proof responses and terminal
opening verification, with caller/source/proof overlap and whole-process RSS
identified separately. The opening verifier prepares 2^r+2^c point weights for
that source's A9 split r+c=m; no new row/column split is chosen by the stage.
No full inference benchmark, c_sc fit, fused opening or weight-pass result follows.
Measure complete producer/consumer time, bytes and memory with every binding on.
Reuse a certificate only with its existing lifetime record, not as free setup.

Implementation acceptance retains all three original E3-06 criteria. Keep A7's
10,000 points per kind per field; add native both-field partial-round agreement
for both orders, empty axes/terms, padding and unused inputs. Independent Python
must agree on canonical descriptor/source frames, actual A1 proof bytes, restored
claims, records, closed decisions and continuation. Fuzz malformed shapes and
lengths; reserve checked capacities before replay. Source substitution and a
wrong restored point must reach real consumers, not a fixture self-comparison.

| Control | One changed value / actual rejecting consumer |
|---|---|
| NC-0203 | Replace A's final by its evaluation at a wrong layer coordinate in an empty-P proof; actual A1 still passes, independent A7 check rejects CoefficientMismatch. |
| NC-0211 | Change the first, unused original final to its value at the raw layer-last point; actual stacked reduction passes, public consumption rejects ClaimMismatch and the first certified opening rejects PCS ValueMismatch before queries. |
| NC-0212 | Change one public onehot index or exact-table value in a prover's coefficient source; retain the expected source, use m=0/empty P where applicable, change only A's final; actual coefficient consumer rejects CoefficientMismatch. |
| NC-0213 | Substitute one separately verified certificate with the same ID/dimensions and a different root for an unchanged original opening; an empty-P/full-layout-Eq fixture keeps A1 and the coefficient check valid, and actual A9 rejects RootMismatch. |
| NC-0802 extension | Omit Stack or StackSources only in an adversarial transcript and change one successor A1 final produced from it; actual continuation rejects FinalEvaluationMismatch. |

Fixtures must make old/new evaluations distinct and retain both-field checks.
NC-0212 requires separate actual onehot and exact-table variants.
For NC-0213 retain an opening row for an all-zero original, so its scalar check
passes before the old authenticated path encounters the substituted root. The
substituted certificate must pass its actual independent registration verification.
Controls remain todo until actual
native consumers exist. RFC review earns no control, parity or runtime credit.
