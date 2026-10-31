# Head assembly and complete attention output conversion (Q26 / Q31)

Draft RFC-0004 A3/A6/A8 and RFC-0009 A2 research. Before code: can complete
per-head normalization proofs bind one configured output-row conversion,
with all heads in order and no independent head scales? Costs are
c_a/c_sc/c_lu/T_misc. Kill the design if a missing/reordered/replaced head,
wrong byte layout, padded-channel insertion, alternate conversion source or
head-local scale can produce acceptance under the original expected roots.

Expected metadata contains one full attention normalization schema with head
width w, head count h, KV group count g, output policy and static scale,
identity, every head's thirteen normalization role ids, scale/output ids and
repetition count. Require 1<=g<=h<=128, g|h and h*w<=16384. All heads use
the same expected schema, preserving units, accumulation mode and value
policy. Block mode has a canonical zero base-role sentinel per head. All
other external ids are distinct and outside the parent namespace. Group
metadata binds the context; it does not establish actual GQA source ownership.

Verify all h complete normalization proofs against their expected root lists.
Each verified Y source has two planes of Nh=next_power_of_two(w) bytes.
Take only the w real bytes of each head, in head order, for each plane;
append zero padding to N=next_power_of_two(h*w). Hash those actual assembled
bytes under a fixed internal source id. Route that root to the complete
dynamic row-code or static row-code verifier for row.Spec(wide,h*w,Fo,...).
Its scale and output roots are external expected roots. Do not accept a
producer root, receipt, whole-input division or unverified output view.

The proof has exactly h complete head proofs and one complete conversion
proof. Dynamic maximum selection, scale ceiling, signed input/output, rounded
division and all ranges remain complete over the assembled row. Static
conversion retains the configured constant and rejects overflow. A valid
conversion of another row must fail the actual assembled-source binding,
even if its final int8 codes happen to match. Missing or extra heads and
ignored branch payloads reject. The producer assembler also checks its join;
verifier admission never relies on that producer check.

Reserve identity<2^24 and base=2^63+2^38*identity. Normalization head j uses
identity 256*identity+j, occupying disjoint lower-half spans of size 2^30.
The dynamic conversion uses identity 4096*identity+2048, or static conversion
1048576*identity+524288; both start at base+2^37. The internal assembled
source is base+2^37+2^26, outside every child span. Check all nested namespace
limits at maximum parent identity, h=128 and full output width before code.

No wrapper challenge, projection or reduction is added. Sum all complete head
accounts and the complete row account unchanged. Retain four separate product
identity losses per exact head or three per block head. Dynamic conversion
adds its existing selection numerator log2(N); static selection is zero.
All independent lookup identities and unsquared reductions remain separate.
Bind full expected metadata/roles, ordered external roots, the assembled root
and every verified child state into the final context. Equivalent arithmetic
under changed metadata may remain valid, but cannot return the same context.

Tests first: 10000 independent integer normalizations, head assemblies and
whole-row conversions, including overflow rejection, signs, ties and zeros.
Check ragged heads/rows, full head count and width, GQA metadata and both
output policies. Both fields/repetitions must match every child receipt and
the aggregate, with no wrapper draw. Attack every expected root, missing or
extra head, head order, padding and byte layout. Supply valid replacement
normalization/conversion proofs, including altered sources hidden by zero
codes and genuine head-local dynamic scales. Context tests cover each child
state and expected schema/role/policy/group fields. Require complete
128-head, 128-channel proofs for exact/dynamic and block/static output,
queued once after normalization and row-capacity prerequisites.

This binds conditional normalized outputs to the complete row consumed by
O projection. Actual global offset/probability/key/mask/value ownership,
GQA association, model/checkpoint/cache/decode ownership and O-projection
weights remain separate requirements. No native/private PCS/ZK/FS, GPU,
fidelity, benchmark, production coverage, cut or extra weight pass is claimed.
All original task criteria stay blocked; Draft semantics remain unaccepted.

All 16 maximum-parent namespace derivations passed before implementation:
both fields, accumulation modes and output policies at h=128,w=128 and
h=1,w=16384. Every complete child derives; their reserved spans are disjoint
and contained, with the assembled source outside them. Tests first then
rejected the missing output-conversion module. No proof admission follows
from those namespace checks; complete controls and proof suites remain required.

The complete consumer is implemented. The verifier checks all head proofs,
gathers their actual int16 bytes with complete-row padding and verifies the
configured row conversion on that derived root. Producer joins and child
states do not substitute for verification. Corpus, boundary/context controls
and complete proof suites are running; full-size proofs and repository gates
must wait for their existing prerequisites. No completion claim is made yet.

Boundary/shape checks passed. A separate context check then covered every
head root, child state and assembled root across both fields, repetitions,
accumulation modes and output policies; each change altered the final state.
Changed source-role, group, output-role and unit metadata also changed it.
Future boundary runs include that broader context check. Linear list
flattening preserves independent witness roots and context byte order without
repeatedly copying earlier heads. Complete admission suites remain running;
context-only checks do not establish proof acceptance.

The first control run rejected a reordered exact-mode head at its nested
product source commitment, before the external probability-root check. The
test expected the later diagnostic. Only that assertion was corrected;
verifier behavior is unchanged. The failed log remains recorded, the original
corpus continues, and a corrected proof run is required.
