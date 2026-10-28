# Streaming A1 equivalence and buffer-capacity contract

This document is the detailed contract incorporated by RFC-0006 A6. It defines
the CPU reference strategy and its delivery obligations, not a production result.
K is QM31 or OM31, with d=4 or 8 and k=4d serialized bytes per element.
Let N=2^m, a be the number of ordered inputs, delta<=4 the A1 degree, F the sum
of term factor counts, T the term count and b=max(2,delta+1). All size calculations
use checked nonnegative integers. Unsupported sizes or arithmetic overflow reject.

## 1. Source, identity and preparation

The prover source exposes its ordered A1 input ids and m, a rewind operation and
a fallible next-row operation filling a caller-provided a-element K slice. Row j
contains `f_i(reverse_bits(j,m))` for every input i in descriptor order. Rewind
starts at j=0. For a>0 each scan requires exactly N rows and then EOF; early EOF,
extra rows, noncanonical bytes or I/O failure abort with Source. The constructor
and each rewind check metadata against the cached full Instance; shape/id
disagreement rejects as PublicShape. A different Instance rejects as
InvalidStreaming, including changed coefficients or sum.
K values retain every extension coefficient; byte adapters reject noncanonical
limbs rather than reducing them. Supported m satisfies m<=63 and m<usize::BITS.

Replay denotes the same logical input for every scan. The concrete CPU file
adapter holds read-only open handles, one canonical limb file per input; it checks
lengths, consumes consecutive records and checks EOF. Handles, metadata and any
adapter-owned heap exist before the bounded proving call. The file owner must
preserve contents during the attempt. File metadata or a source-reported identity
is not cryptographic authentication, and this contract does not assume a malicious
prover obeys it: all final claims still go to the original authenticated consumer.
A mutable or substituted source cannot replace that consumer. Known source errors
must abort; silent zero-fill, truncation, fallback or stale cached state is forbidden.

The reference preparation adapter converts a canonical row-major input file by
reading record j once and writing it to record reverse_bits(j,m) in a separate
file. It uses a fixed record buffer, sequential input reads and positioned output
writes. Count all reads, writes, seeks, output storage and preparation memory.
The original is preserved; failed preparation yields no usable source. An input
already in the required layout needs no conversion. Resident-input preparation
is also possible, but the resident allocation remains part of its reported peak.
Neither path may be described as free or as sequential output I/O.

The source is prover-side data, not an additional protocol commitment or public
input. This strategy does not authorize replay of weights, including copies of
weight-bearing data. An inference plan may apply it only where RFC-0007's one
weight pass remains true. A standalone source benchmark cannot establish that
integration property. Virtual-tensor recomputation needs its own explicit plan
cost and source-memory evidence; the file adapter does not establish it.

## 2. Explicit schedule and checks

The caller supplies a finite ordered vector of positive window widths w_i with
sum S<=m. Empty schedules are valid dense-tail materialization; m=0 requires one.
No timing-based selection or implicit full-input rescan per round is allowed.
The planner chooses a schedule using integer sizes and measured costs; there is
no claim that every memory budget admits a two-visit schedule. Exactly one window
followed by a tail gives two source visits. W windows give W+1 visits, with
a*N field elements per visit, excluding preparation and final-claim consumption.
For a=0 there are no source elements or source reads; constant-polynomial
multiplicities are still exact. Every size and the whole workspace requirement
are checked before source access. Bad schedules reject as InvalidStreaming;
addressability, workspace or allocation limits reject as Capacity.

## 3. Window construction and round order

After S challenges r are fixed, let w be the next width and q=m-S-w. Consecutive
physical blocks of 2^(S+w) source rows have fixed canonical suffix
`z=reverse_bits(block,q)`. Their original indices enumerate every `(u,v,z)` once,
where u has S bits and v has w bits. Accumulate

`B[v,i] = sum_u eq(r,u) * f_i(u,v,z)`.

Compute each prefix equality weight directly with a scalar product; no 2^S
weight table is retained. For each grid node x in `{0,..,b-1}^w`, interpolate
each input `F_i(x,z)=sum_v eq(x,v)*B[v,i]`, then add P(F_0,...,F_(a-1)) to G[x].
Do not substitute the MLE of a Boolean product. Reset and reuse B for the next
suffix. Repeated factors, unused inputs, zero coefficients and empty terms all
retain A1 semantics. A constant term contributes its exact suffix multiplicity.

Each F_i is multilinear in x, so G has individual degree at most delta. On
ordinary A1 round j, the grid represents the prefix already fixed. Sum the
remaining Boolean coordinates to return precisely the delta+1 evaluations at
0..delta. The engine checks the current sum, absorbs Round and only then draws
the full K challenge. Fold the leading grid coordinate by Lagrange interpolation
on the b distinct fixed nodes. For delta=0, the internal b=2 grid is constant
while the proof still transmits the single A1 endpoint. Challenges 0 and 1 need
no retry, inverse of a challenge or special transcript operation.

Induction on the rounds proves equality to Dense: the initial G is the exact
sum over the unexposed Boolean suffix, interpolation is unique at degree< b,
and fixing each challenge restricts the same polynomial. Suffix enumeration
order only reorders exact field additions. The next window reconstructs the
same original-input restrictions at the complete accumulated prefix.

## 4. Tail and final obligations

After the last window, overwrite the work region with
`H[i,z]=sum_u eq(r,u)*f_i(u,z)`, including every unused input. Source records are
still bit-reversed, but H is placed at canonical row-major suffix index z.
Store all a rows contiguously. Dense leading-coordinate folds operate in place;
forward compaction from a*L to a*(L/2) cells cannot overwrite unread inputs.
The degree-zero and no-input cases use the ordinary A1 constant multiplicities.
At m=0 the tail is the final a values. No source value is silently dropped.

The full original Instance, round messages, m challenges, final values, Final
absorb, ordered claims, SC record and continuation are unchanged. The final
consumer checks the original input identities at the one derived point. Private
inputs require their actual reduction/PCS consumers; a file descriptor, digest
or source assertion cannot discharge a claim. Error after transcript mutation
invalidates the entire attempt; retry begins with a fresh transcript.

## 5. Enforceable workspace and complete resource reporting

The bounded path takes owned, already allocated K storage and preallocated proof
and byte buffers. It validates actual capacities before proving and does not
grow, replace or allocate work buffers during the bounded call. Plain allocating
convenience wrappers may prepare these buffers, but their peaks must be reported.
The ordinary Summand interface may allocate its returned endpoint/final vectors;
that path is not automatically the bounded path. Reuse shared A1 transcript and
round logic; a separate protocol or relaxed verifier is forbidden.

For a window w, reserve G=b^w cells, B=a*2^w cells, one source row of a cells and
one interpolated-value row of a cells. They occupy disjoint contiguous regions.
The source fills the existing row, and B is overwritten after each suffix is
consumed; there is no retained previous block. Grid folds compact within G.
After a window, reuse the same backing storage for the next window or the tail.
The tail requires a*2^(m-S) cells plus one source row of a cells. Thus the work
requirement is exactly the following sufficient logical length:

`L_work=max({b^w_i+a*2^w_i+2a for each window i} union {a*2^(m-S)+a})`.

Own and count the entire supplied Vec capacity, including spare cells. Never
count only a subslice or truncate length and claim its allocation was freed.
The fixed point storage has 64 K slots; interpolation needs at most five weights.
The schedule and full Instance remain fixed borrowed data with their backing
allocations included in the caller's complete accounting. No cloned full input,
2^S equality table, family of per-term grids or retained window copies is allowed.

The bounded engine fills the existing Proof buffers: m rows each of length
delta+1 and a final-values vector of length a. Validate those shapes up front
as ProofShape errors, and count their actual outer/inner capacities. Return the same A1 Proof without
copying it to a second representation. A single byte buffer, reused for absorbs,
must accommodate the largest of these canonical payload lengths:

- Instance: `23+8a+T*(k+1)+4F+k` bytes;
- Round: `12+(delta+1)*k` bytes;
- Final: `12+a*k` bytes.

All arithmetic in these expressions is checked. Serialization fills a prefix
of the supplied byte buffer with exactly the existing A1 bytes; no padding is
absorbed. Interpolation uses fixed-size scratch, and Transcript retains its
existing allocation-free framing. Shape, capacity or source failure cannot
return a completed proof. Unchanged proof capacities and buffer pointers are
checked across the actual bounded call, including each window/tail transition.

The prover's live buffer-capacity accounting includes the entire work allocation,
all proof capacities, the byte buffer, source-owned allocations, the schedule,
Instance backing allocations and any retained caller input/preparation buffers.
Inline strategy/source/transcript state is reported separately using its actual
compiled size. This is a payload/capacity bound, not a portable bound on allocator
metadata, native stack spills, OS caches or RSS. Measure process peak RSS and
external storage separately; never label the workspace formula as total memory.
The complete pipeline reports preparation, proving and original-claim consumption,
their transition overlap and the maximum of their actual process peaks. If the
consumer dominates, retain that result. GPU admission needs its own full device
allocation/transfer measurements and the unchanged CPU/CUDA parity gate.

## 6. Algebraic loss, cost and delivery

No new challenge, transcript label, commitment or SC loss is introduced. The
conditional A1 loss remains m*delta/p^d. Deterministic strategy equivalence does
not establish profile security, Fiat–Shamir bounds, ZK or inference correctness.
There is no new CQIS integer identity or field-faithfulness certificate.

For W windows the source work is a*N*(W+1) field reads. The simple reader's
prefix-weight work costs O(N*S) per visit with S fixed coordinates; the
input multiply/add work is O(a*N). For a window of width w, direct grid work is
O(2^(m-S-w)*b^w*((a+w)*2^w+F+T)); grid folding costs O(w*b^w).
Tail materialization and dense folds are charged too. These move c_sc/T_misc;
layout preparation and source I/O are explicit, and recomputation moves
T_witness only under an accepted integration plan. No optimal complexity or
measured improvement is asserted by this simple algorithm.

E3-05 delivery requires the actual bounded implementation and file adapter,
independent Rust/Python decisions, at least 1,000 seeded cases per degree and
field, every supported schedule boundary, m=0/no-input/constants/unused inputs,
Dense byte/receipt/continuation parity, source EOF/shape/id/limb/I/O errors,
cached-instance rejection and actual capacity-bound tests. Check per-suffix
window contributions sum to the whole window polynomial; this is not a promise
that independently folded nonlinear layer blocks can be added.

NC-0210 holds the original Instance and public consumer fixed, proves an honest
baseline, changes exactly one value of an unused source input after preparation,
and obtains the corresponding real Streaming artifact. All rounds must stay
equal and exactly one final must change nontrivially. Through the existing
ProverHook proof-artifact path, require ClaimMismatch from the unchanged actual
consumer in both fields. Constructor failure or a toy verifier earns no credit.
Malformed/replayed sources additionally have ordinary failure tests.

Publish clean-source complete cost/memory ledgers for both fields, including
preparation, file access counts, all supplied capacities, proof/descriptor/source
state, process peaks, original consumption, and losing schedules. Include a
one-window two-visit case and a multiple-window case, plus a feasible instance
whose dense input state exceeds the selected work budget. The budget is explicit;
it must not be enlarged until the test merely becomes a dense allocation.
No source study, allocation estimator or formula checked against itself completes
this delivery gate. Production execution and measured evidence remain mandatory.
