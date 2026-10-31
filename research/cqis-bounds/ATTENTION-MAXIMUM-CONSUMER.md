# Consumed masked attention maximum (Q26 / Q31)

Can actual signed32 score bytes prove an attained allowed maximum, exact
exponential-domain differences and the first allowed tie without M31 aliases?
This is revealing Draft RFC-0004 A3/A6 research, retaining RFC-0009 A1 and the
[static maximum schema](ATTENTION-MAX.md). Costs are c_x/c_sc/c_lu/T_misc.
Kill the design if a modular alias, masked selection, later tie, out-of-domain
difference, altered source or free mask is accepted. Bounds must remain static.

Expected metadata fixes the static score/domain/unit schema, absolute query
position, sorted unique key positions, sequence block [start,stop), and window.
The query lies in its block. A key is allowed exactly when it lies in that
block, is no later than the query, and window=0 or query-key<window. At least
one key is allowed. The verifier derives this predicate; there is no supplied
mask. Key-set completeness and model ownership still belong to the caller.
The prototype supports at most16384 actual keys and absolute span2^20.

Let S be the static score magnitude cap and H=2S, D=min(H,2^B). Eight complete
wide-range children consume raw source bytes, raw maximum bytes, offsets O,
differences delta, gaps g and three Boolean carry arrays. Raw sources use
four byte planes; the scalar maximum uses four bytes. Offsets are bounded by
H and differences/gaps by D, with zero caps at masked entries. All source
scores, including masked scores, retain their bound. Offset/difference/gap
widths are static powers of two in1,2,4, expanded with public zeros to four
planes for arithmetic. Carry arrays have four planes, including zero padding.

Four external roots bind source, maximum, selected absolute ID and differences.
The selected ID is one canonical-u32 leaf opened in full and checked against
its expected root and allowed key positions. Five auxiliary roots bind O, g
and the carry arrays. These are revealing research roots, not new model cuts
or physical packed roots. Actual raw bytes at the selected key must equal the
maximum bytes through an A3 over four byte positions.

Three other A3s consume four byte-column relations: raw+S=O modulo2^32,
mask*O+delta=mask*O_selected, and g+prefix=delta. The first relation starts
with carry zero; its final Boolean carry is allowed and encodes the signed
wrap. Since S<2^31 and O<=2S, it proves precisely score in[-S,S] and O=score+S.
The latter two start with carry zero and require final carries zero in a
separate A3. Each column side is at most511<p/2. Prefix is one exactly for
an allowed key preceding the selected absolute ID and lives only in byte0.
This proves the Draft first-tie rule. Masked deltas/gaps and all padded rows
are canonical zero. The first-tie rule is stronger than A1's attainment alone.

The five A3s run SourceOffset, Difference, FirstMaximum, Terminal, Attainment,
with dimensions a+2,a+2,a+2,a,2 and degrees1,2,1,1,1. All20 original views
have actual-point consumers, including masked originals. Full child states,
expected metadata and all nine roots precede parent challenges; the opened
selected ID is bound by its checked expected root. No whole signed32 equation
is compared in M31. Repetition counts do not square reduction errors.

Namespace before code: identity<2^48, base=2^63+2^14*identity. Wide children
256*identity+1..8 occupy64..576. Auxiliary ids use base+1..5, parent views
base+16..35, and parent A3 ids1024*identity+128..132 follow the child ids.
All four distinct external ids stay outside the parent span.

For N=2^a and offset/difference byte widths2^bo/2^bd, retain eight separate
lookup identities with dimensions a+3,3,a+bo+1,a+bd+1,a+bd+1 and three a+3.
Each identity is ((2^m+255)/|K|)^rpt; each unsquared reduction is
rpt*(F(m)+F(8)+3m)/|K| with F(m)=3m(m-1)/2+2m. Total range/A3 numerator is
72a+100+7bo+14bd, including parent9a+18. Parent draws are4a+8 of each
ZeroWeight/Sumcheck label; complete nonlookup totals are32a+44+3bo+6bd each.
Source binding, FS/H, private and model ownership losses remain additional.

Tests first:10000 independent integer/NumPy rows, causal/window/block masks,
sparse absolute positions, zero/maximum S, inclusive domain endpoints, ties,
masked larger scores, padding and namespace/capacity. Attack all roots, all20
originals, coherent source/maximum/delta M31 aliases, later ties, masked
selection, source bounds, terminal carries, domain and metadata replays.
Require both fields/repetition counts and a full16384-key proof, then the
required local gates. No evidence is claimed before those runs finish.

Continue Q26/Q31. Native lowering/parity, private selection, physical/model
source ownership, exponential membership, full attention composition, fidelity
and original task/control criteria remain open. This changes no benchmark,
weight pass, cut, Accepted schema or production binding/control coverage.

Tests-first rejected the missing module. Both corpus runs passed all10000
seed2730 cases:8218 valid rows and1782 expected domain rejections, with8008
masked rows and1178 ties. The second run checks carries with independent
prefix sums rather than the producer's recursive carry algorithm. Both runs
have the same frozen SHA-256:
`087e62b41088768faa8dc95a77805fb72b7dd5736d571c3c84c652fa0bf6f84d`.
NumPy selection/differences, scalar maximum, every source root, mask policies,
all byte widths, namespace endpoints and malformed metadata passed.

Primary controls passed all four external/five auxiliary root mutations,
arithmetic-role mutations, valid source substitutions, masked/invalid selection
and supplied receipt/certificate/mask rejection. All20 original-final controls
passed, including public masks under zero multiplication. Expected window,
query/block/keys/unit replays and a forged padded public mask were rejected.
Boundary/alias controls, proof matrices, maximum and local gates remain under
validation; no native/control/profile credit follows from these observations.

All boundary controls passed. Separately valid raw maximum bytes differing
by M31 rejected at Attainment; an offset differing by M31 rejected at
SourceOffset. A false difference shortened by M31 rejected at Difference,
and a later tied key with gap=M31-1 rejected at FirstMaximum. The exact
inclusive delta=2^31 row verified. Actual offset/domain/masked caps and source
padding rejected at their range consumers. Both fields/repetition counts,
the full16384-key proof and local gates remain pending.

All16 complete proofs passed across both fields/repetition counts, with exact
accounts, draw counts and every original consumer. Frozen proof-state SHA-256:
`e96860a9139e74686c61b5a16e1bce54ca231165236a2fda220b854ceaadbd1b`.
The full16384-row proof has started; required local gates remain queued.
Corpus and all negative controls were already passed and were not repeated.

CI retains all 141 inherited commands and adds this consumer's five normal
modes as command 142. A separate full-size job is a required aggregate
dependency. All 11 inventory tests passed, including rejection when any
required result fails, is cancelled, is skipped or is absent. The original
full 16384-key proof and repository gate queue remain pending and are not
restarted by this integration.
