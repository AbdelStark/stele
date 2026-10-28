# Native code contract (RFC-0010 A4)

This implements the complete encoder and identity boundary of E4-01. It provides
no PCS proof, authenticated commitment, zero knowledge or admitted profile.
E4-03/A3, E4-05, E12-04 and Q12 retain those obligations. Distance metadata is
conditional evidence, never permission to verify an opening.

## 1. Exact identities and map

Support only A2's 21-byte circle identity and the 55-byte expander identity
`stele/expander-seed/v2 || u8(J) || seed[32]`, 3<=J<=15. Reject unknown versions,
extra/truncated bytes, raw graphs and unsupported sizes as InvalidCodeId.
Resolution is bounded arithmetic with no graph/transform allocation. The
identity is an M31-linear map; consumers must bind its full bytes and element
field separately. Do not normalize equal maps with distinct identities.

For expander n=4^J, output length is 2n. J=3 is exactly Circle(6,1).
At each higher level, with A of dimensions n by n/4 and B of dimensions n/2
by n/2, messages are row vectors and
`y=x*A; z=E_(J-1)(y); E_J(x)=x || z || z*B`.
Coefficients lie in M31, including zero. Extend by embedding them into K.
Fixed A degrees for levels 4..15 are
`[25,21,19,19,18,18,17,17,17,18,18,18]`; B degrees are
`[26,21,18,18,18,18,18,18,18,18,18,18]`.
The base is non-systematic; every higher level has the exact x prefix.

For each row generate independent neighbor and coefficient streams. Each block
is the unkeyed BLAKE3 digest of exactly
`stele/v0.1/setup/expander/block/v2 || seed[32] || u8(level) || u8(kind) ||
u32le(row) || u8(stream) || u8(counter)`.
Levels are 4..15, kinds A=0/B=1, stream neighbor=0/coefficient=1, counters 0..31.
Validate coordinates before hashing. J is absent: one seed determines a shared
tower. Each block yields eight u32le words. Neighbor words project by
`word & (columns-1)`; discard repeats, stop at the required degree, sort the
selected columns increasingly. Coefficient words project by `word & (2^31-1)`;
reject only 2^31-1, keep zero and duplicates, retain order, and pair these values
with the sorted columns. Each stream has a strict 256-word cap. Exhaustion is
SamplingExhausted; reject the complete preparation, never substitute a graph.
These are deterministic setup bytes, not proof challenges or a second FS path.

Generate levels J down to 4, A then B, rows ascending, neighbors then coefficients.
Store flat `(u32 column, M31 coefficient)` records in that order. No public raw
setup constructor, source flag or callback may replace this regeneration.

## 2. Typed APIs, errors and capacity

`CodeId` is a closed, privately constructed identity resolved from the bytes.
A sealed `Code` interface exposes identity, derived encoder parameters, encode,
and eval_row. Native element types are the actual M31, QM31 and OM31 types via a
sealed element trait. Existing A2 Circle APIs remain byte-compatible.

Preparation is explicit: `CodeId::prepare(max_setup_bytes)` returns a prepared
code or a typed error. The caller budget bounds retained graph allocation,
not total process memory or encoding workspace. For E(J) equal to the sum of
rows*degree across all levels/matrices, check `E(J)*size_of(Edge)` and the actual
allocated graph capacity against the budget. Reject overflow/reservation failure
as Capacity. No graph is allocated at identity resolution. A2 Circle preparation
has no retained graph. Graph generation uses fixed arrays of at most 26 neighbors
and coefficients, at most 32 hash bytes, and no nested per-row allocations.

All sizes/shifts/products and allocations are checked. Bounded recursion depth
is at most 12 from the validated J, never a proof-provided recursion limit.
Encoding validates the whole row before arithmetic/output allocation. `eval_row`
validates the whole row and every column before any transform/encoding; duplicates
and order are preserved, and empty columns return empty after admission.
Wrong row length is RowShape; out-of-range columns are Column. Allocation failures
are Capacity. Errors return no partial result. No fallback code or implicit padding.

Encoding may use flat per-level outputs and one temporary y. Complete retained
memory includes the caller row, graph, all live ancestor y/output buffers, current
output, base Circle transform/twiddles, selected results and allocator capacity.
A conservative sum of recursive vector payloads is O(n) and must be measured;
the setup budget alone is never reported as the complete peak. Descriptors,
preparation hashing and graph construction are charged, including losing cases.

## 3. Derived metadata, registry and security boundary

Metadata comes only from the identity: message/codeword length, field-independent
symbol distance evidence, setup loss, edge count and raw setup byte count.
Circle's lower bound is N for k=1, otherwise N-k; setup loss and raw graph bytes
are zero. Expander's bound is 64 at J=3, otherwise floor(n/25)+1; raw setup bytes
are 43+8*E(J). The base has zero setup loss; higher levels have the conditional
all-seed error 200431782/2^160 under the exact ideal-oracle assumptions below.
Returned metadata is descriptive and is never accepted back as authority.

The two-entry `codes.toml` is an export of fixed definitions, not a prover parameter
file. Its exact schema/values are the existing research/code-provenance/codes.toml:
version 1, circle then expander. Both `proven` flags mean a complete PCS parameter
set and remain false. Native code does not parse arbitrary registry bytes into a
code. A checker must reject every changed field/type, duplicate, missing/unknown
key/entry, malformed UTF-8/TOML or >4096-byte document. A PCS parameter request for
either profile fails UnsupportedParameters until a separately Accepted contract
provides the missing native opening/composition evidence. No flag enables it.

The distance proof is the finite induction in formal/expander-sampling.md, with
its exact integer/rational checker and Circle base. The capped-stream coupling
and union over all 2^256 seeds in formal/seeded-setup.md bound any successfully
regenerated bad code by 200431782/2^160 in the ideal oracle, including adversarial
classical/quantum seed selection. Regeneration does not certify concrete BLAKE3
or a full profile. RFC-0012 A7's full composition remains Draft. No new production
challenge/loss enum or profile budget is instantiated by this encoder API.

## 4. Delivery

Require independent full encoding/linearity in M31/QM31/OM31, direct generator
matrix parity at small sizes, exact sampler KATs/cap boundaries, empty and ordered
duplicate queries, malformed identity/row/column and insufficient-budget rejection.
Check all 72 sizes without graph allocation and changed-seed separation. Registry
mutations must fail the actual export checker. No test gets NC-0600..0605 credit.
Record adds/multiplications per element, setup hash blocks/time, full preparation,
encoding/query time, all live capacity and measured process memory in clean-source
bench ledgers. Distance estimates are upper observations, never certified bounds.
E4-01 is not done until these gates and workspace/required gates pass.
