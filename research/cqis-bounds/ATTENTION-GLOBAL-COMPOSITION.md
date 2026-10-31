# Global attention sources through configured output (Q26 / Q31)

Draft RFC-0004 A3/A6/A8 and RFC-0009 A2 research. Before code: can complete
global offset/probability proofs feed every complete normalized head and
one configured output-row conversion, without a missing block or changed
source crossing a join? Costs are c_a/c_sc/c_lu/T_misc and retained proof
storage. Kill the design if a valid replacement aggregate/normalization,
omitted head/block, reordered stream or alternate output source is accepted
under the original expected roots, or if supported dimensions are narrowed.

The expected specification embeds the complete output-conversion Spec,
parent identity and two ordered source-id arrays of shape (heads,B), where
B=ceil(L/1024). Preserve L<=1048576, heads<=128 and heads*width<=16384.
Every block 0..B-1 occurs, including blocks whose actual masked sum is zero.
Expected roots contain both block families plus the complete existing
output-conversion root structure. All external ids across those families
and normalization/output roles are distinct and outside the parent span;
block mode retains only its existing canonical zero base-role sentinel.

For each head verify one complete global probability-sum proof against all
B four-byte block roots and the eight-byte Z root used by normalization.
Verify one complete streamed global-offset proof against all B eight-plane
block roots and the exact O root used by normalization. Both children derive
from the full expected metadata. The probability child includes the full ordered block roster.
Its existing block-bound adapter needs a legal
rounding shift even when only its probability arithmetic is used. In exact
mode choose the smallest shift in 0..62 for which round(1024*Q*S/2^shift)
is at most 32767; in block mode use the configured drop. This auxiliary
exact-mode parameter does not round the exact inference sum. L/Q still fix
all probability caps, and the original full schema binds the wrapper.

Finally verify the complete output-conversion proof against the same
expected root structure. It retains canonical sign, exact H=S*Z where used,
positive denominator, scaled magnitude, strict division and signed output
for every head, followed by actual head-byte assembly and the whole-row
conversion. Route O/Z roots independently to both complete sides of each
join. Neither producer joins, child receipts nor plaintext sums authorize
acceptance. Per-head dynamic output scales remain forbidden by that consumer.

Use a flat canonical stream. For each head in order, one strict header holds
its integer head index and complete global probability proof. The next B+1
records are exactly the global-offset child's B block records and tail.
Pass a bounded iterator of those records to its complete verifier, which
still requires its own EOF. After all heads, one strict final record holds
the complete output-conversion proof; require outer EOF. An extra child
record becomes an invalid next header/tail, never ignored payload. Reject
missing/extra/reordered records and Boolean indices. Temporary spool
ownership and reauthentication stay with the complete offset child.

The producer may accumulate each head's integer O and Z while streaming its
inputs, deriving T=O-S*Z in exact mode or T=O-B*Rmax in block mode to construct
the normalization witness. The verifier never uses that producer arithmetic.
It retains upstream context states/accounts and one complete output proof;
that proof's memory and child peaks remain additional. No blanket process
memory or speed claim follows from streaming only the upstream records.

Reserve identity I<2^23 and base=2^63+2^39*I. The output child has identity
2I and occupies the lower half. Head j's global-offset identity is
2^19*I+2^18+2j; its span starts at base+2^38+2^21*j and has size 2^20.
The global probability identity is 2^21*I+2^20+8j+4, starting immediately
after that offset span with size 2^18. All 128 head pairs fit the upper
half. Check every nested namespace at maximum parent identity, h=128,w=128
and h=1,w=16384, in both fields, modes and output policies before code.

The wrapper draws no challenge and adds no identity or reduction loss.
Sum every verified child's range and unsquared lookup reductions, retaining
all independent lookup identities. Keep each global-offset projection
identity separately and sum its A1 reductions. Retain each global-Z product
identity alongside the existing four exact or three block product identities
per normalized head. Existing product A1 and row-selection losses remain.
Full expected metadata, ordered roots and every verified child state bind
the final context. A supplied child state cannot replace verification.

Tests first: independent integer O/Z aggregation, normalization and complete
row conversion across both modes/policies, zeros, signs and overflow. Check
all namespace/shape boundaries and expected metadata contexts. Complete
proofs cover both fields/repetitions and every root family. Attack missing
or extra records, head/block order, malformed indices, ignored tails and
canonical exact-mode adapter metadata. Replace complete global children
while preserving global totals, and replace complete output proofs while
preserving final codes; require rejection at the actual shared source.
All child/aggregate accounts and empty wrapper draws must match. Require
complete L=1048576 proofs for h=128,w=128 and h=1,w=16384, with exact/dynamic
and block/static conversion, after the existing full child prerequisites.

This closes conditional aggregate-to-output joins. It does not establish
actual per-block weighted sums or rounded offsets, key/mask/cache/GQA/model
ownership, O-projection, native linear views/PCS/ZK/FS, GPU parity, fidelity
or independent audit. No new production cut, coverage credit, benchmark or
weight pass is claimed. Original tasks remain blocked; Accepted semantics
are unchanged.

All sixteen pre-implementation namespace checks passed at maximum parent
identity, both fields/modes/policies and both full head/channel layouts.
Every complete output child and global pair derives within disjoint spans;
the exact-mode probability adapter preserves the expected Z bound. The
global-offset child matrix and zero-bound edge evidence are now frozen.
Tests first and complete composition implementation remain required.

Tests first rejected the missing implementation module. The complete
consumer is now implemented: it verifies all global children on the O/Z
roots used by each complete normalized head, followed by whole-row output
conversion. Full source-roster, namespace and context checks passed. The
original corpus and complete proof suites are running; full-size proofs,
repository gates and independent review remain required.

All 120 exact-mode probability adapter configurations passed: both fields,
fifteen probability exponents and four value quantizers. Each uses the
canonical minimum auxiliary shift while preserving its original L/Q caps.
Future boundary runs include these checks. Complete zero-offset and
zero-probability substitution proofs are also running separately.
