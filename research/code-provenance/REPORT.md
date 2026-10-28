# Q23 — Linear encoding is not a distance or proximity certificate

Question: which concrete M31 code and parameter evidence complete E4-01's
`Code`/`codes.toml` contract? Cost terms: per-proof encoding in c_c, downstream PCS
query work/proof size, and memory for graph/permutation preparation. Kill criteria
set before the study: nonlinearity, a false claimed distance lower bound, a theorem
used outside its field/setup hypotheses, or an estimate presented as certification.

## Primary-source findings

[Brakedown](https://eprint.iacr.org/2021/1043) supplies a practical linear-time
encoding route compatible with arbitrary sufficiently large finite fields. It is
the field-agnostic candidate to instantiate explicitly, rather than selecting an
unspecified graph under a family name.

[Blaze](https://eprint.iacr.org/2024/1609) states a binary-field construction. Its
[authors' presentation, slides 24 and 29–34](https://iacr.org/submit/files/slides/2025/eurocrypt/eurocrypt2025/504/504_slides.pdf)
describes repetition, permutation, accumulation, permutation and accumulation;
good distance depends on permutation selection. These sources do not certify a
concrete M31 permutation pair chosen for Stele. This is not a claim that no other
RAA analysis exists. A field-specific theorem must be identified and its concrete
setup/length hypotheses checked before importing a bound.

[Bolt](https://eprint.iacr.org/2026/310) introduces a different sketched-code
construction; its reported binary-field implementation is not a drop-in M31
parameter certificate either. [Khatam](https://eprint.iacr.org/2024/1843) gives
proximity statements in terms of a code's minimum distance. It does not establish
that an arbitrary encoder has the distance supplied to that statement. Distance,
proximity radius, exceptional-combination error and setup failure must stay distinct.
No paper's prover code was copied or imported. Full construction/theorem extraction
is still required; abstracts and the inspected presentation do not complete it.

## Reproducible fixed-map study

Run `python3 research/code-provenance/check_code.py` (standard library only).
This study defines its own small RAA map precisely: repeat the whole message r
times, gather by a validated permutation, prefix-sum, gather by a second validated
permutation, prefix-sum. The initial prefix element is copied, so both passes
execute exactly `2*(r*k-1)` field additions for message length k. This is an
instrumented operation count, not a time, throughput or GPU benchmark.

Repetition is injective, permutations are bijective, and prefix sums invert by
successive differences. The map therefore has full rank over every tested prime
field, irrespective of whether its distance is useful. Its linearity follows
from composing linear maps. Tests check 24 fixed maps, k=1..3, r=2/4, 20 random
M31 linear combinations per map, addition counts and malformed permutations.

For each small map, form its generator matrix by encoding basis messages. For
every set of k-1 independent columns, solve for their one-dimensional null space
over M31 and evaluate the resulting nonzero message. The least weight found is
the exact minimum distance: the zero columns of any nonzero codeword lie in a
proper subspace; extend their span with generator columns to dimension k-1. A
null vector of that span has at least the original zero positions. Some enumerated
set thus attains a weight no greater than any proposed minimum. Full generator
rank guarantees that extension is possible. The script independently checks this
method by exhaustive messages over F2, F3 and F5 for all 24 maps. This exact method
is deliberately limited to small dimensions; it is not a scalable certificate.

If a code has M31 generator coefficients, extension to QM31/OM31 preserves its
minimum symbol distance. Expand any nonzero extension-field message in an M31
basis. At least one component message is nonzero, and its encoded support is
contained in the extension codeword's support. Conversely an embedded M31 message
attains the original minimum. This argument does not transport a binary-field
generator to M31: the characteristics and cancellation rules differ.

## Counterexample to estimate-as-certificate

Take k=16, r=4 and identity permutations. All 1,000 deterministic sampled M31
messages in the script encode to words of weight 64. Yet the nonzero message
`[1,-2,1,0,...,0]` encodes to `[1,0,...,0]` repeated four times, of weight four.
Thus the true minimum is at most four, despite the sampled minimum of 64. The
same construction works for any k>=3, giving relative distance at most 1/k.
Linearity, injectivity, correct permutations and fast encoding all still hold.

Observed nonzero codeword weights give upper bounds on minimum distance. A
sampled minimum cannot be used as a lower bound, a proximity radius, a query
count input, or evidence for `proven=true`. This study does not claim an exact
minimum for the k=16 example, nor refute a theorem with its actual hypotheses met.

## Recommendation

The [finite expander follow-up](EXPANDER.md) supplies exact finite-size and rational
interval sampling bounds; production setup and parameter admission remain unresolved.

Amend RFC-0010 A1 before production code: fix a field-agnostic construction,
canonical setup/code identity, supported lengths, extension semantics, error
behavior, and independent provenance for distance and proximity parameters.
Prioritize extracting the Brakedown construction and its finite-length/setup
conditions. Retain RAA only if an applicable M31 theorem/certificate is supplied;
do not make this deliberately weak research map the production fallback.

E4-01 stays blocked on the complete contract. Its linearity, distance-estimate
script and adds/element ledger remain required production deliverables. E4-03,
E4-05 and E12-04 must still supply actual PCS binding, profile enforcement, theorem
instantiation and full accounting. There is no production `codes.toml` entry,
query count, benchmark, certified profile or changed verifier in this study.


## Canonical recursive encoder study

Question: can the finite expander schedule be made into an exact field-agnostic
map with a concrete base code, unambiguous setup bytes and independent encoding
checks? Cost term: c_c plus setup/matrix storage. Kill criterion: any dense-matrix
disagreement, noncanonical setup admission, or distance/profile claim inferred
from syntax, injectivity or a seeded test generator. All source coefficients and
coordinate order must be explicit; setup provenance remains a separate obligation.


Run `uv run --locked --script research/code-provenance/check_recursive.py`.
The candidate in [recursive-code.md](../../formal/recursive-code.md) fixes
x || E_previous(xA) || E_previous(xA)B, all per-level degrees, canonical ordered
M31 edge records and the accepted circle base. Its deterministic base distance
is at least 64, so the finite induction's base requirement is met. This is not a
certificate for any chosen outer setup.

The script independently re-derives the twelve degree pairs. Nine field/size
cases cover n=64/256/1024 over M31/QM31/OM31, exact sparse-edge counts, full-K
linearity and complete-codeword query parity. The oracle inverts the circle basis
matrix by Gaussian elimination instead of FFT, composes a full generator at
n=256 and uses dense matrix/vector products elsewhere. Malformed setup, noncanonical
coefficients, wrong rows, unsupported fields and invalid columns reject. The
codec checks the implied full byte budget before graph allocation.

A structurally valid setup with all edge coefficients zero encodes (x,0,0) at
n=256. Its minimum distance is exactly one, even though it is linear, injective,
correctly encoded and queryable. The test deliberately preserves this distinction;
no `proven` field or source-authentication flag can convert it into an admitted code.

Recommendation: continue Q23 with this candidate map/base/byte contract. Keep A1
Draft and E4-01 blocked until setup selection/grinding/reuse, authoritative registry,
proximity hypotheses, actual binding consumers and production admission are closed.
The sparse operation formula and O(n) storage analysis exclude base-transform,
parser/allocator and encoding-copy constants; production adds/element and complete
memory ledgers remain required. No small-case result certifies the full supported
size range or the seeded fixture's setup distribution.


## Historical v1 seeded setup and bounded sampling study

The v2 follow-up below supersedes this classical-only candidate; v1 bytes reject.

Question: can a fixed public manifest regenerate the canonical map with exact
uniform-ensemble semantics in a classical random-oracle model, including sampler
exhaustion and adaptive seed attempts? Security property: setup provenance and
its separately accounted failure event. Cost terms: setup hash work, c_c preparation
and retained graph/byte storage. Kill criterion: biased accepted sampling, returning
partial data on exhaustion, ambiguous block domains, or treating regeneration
agreement as a fixed-distance/profile certificate.


Run `uv run --locked --script research/code-provenance/check_sampler.py`.
The [candidate contract and argument](../../formal/seeded-setup.md) specify manifest
bytes, domain-separated BLAKE3 block inputs, fixed rejection caps, whole-setup failure
and exact regeneration. Four fixed vectors cover base-only and n=256/1024 maps.
The checks pass finite sampler symmetry, 256-word cap boundaries, forced whole-setup
exhaustion, independent row expansion, prefix reuse, all-field generated-map parity
and rejection of a changed source coefficient/seed/exponent. No partial setup or
distance-admission flag is returned.

The classical ROM argument charges adaptive first-touched seeds and untouched final
outputs, including discarded attempts and preprocessing. Coupling capped streams to
uncapped independent towers avoids dividing by the probability of sampler success.
The finite event count is 200431782; with Q=2^100,S=1 the conditional arithmetic
bound is below 2^-160. Those inputs do not authorize a profile/query policy.

RFC-0002 permits quantum adversaries. An exact 16-input quantum-search example has
success 13073/32768, exceeding the classical three-query/one-output expression 1/4.
It refutes reuse of that generic classical charge for quantum queries; it is not an
attack on this large expander or a QROM upper bound. Recommendation: keep A1/A7 Draft
and E4-01 blocked, and require an applicable quantum setup theorem plus Q12 FS/H
composition before parameter admission. Revisit finite degrees if that bound needs
more budget. BLAKE3 is a concrete candidate, not a proof of the oracle model.

The <=64 hash blocks per row and geometric O(n) work/storage are operation bounds,
not benchmarks. No maximum-size generation, Rust/GPU parity, production source
authentication, proximity certificate, NC credit, registry or profile is supplied.

## All-seed setup bound: research question

Can stronger finite parameters bound every successfully generated 256-bit seed
simultaneously in the ideal random-oracle experiment, so selection (including
quantum selection) cannot evade the setup event? Security property: setup distance
failure; cost terms: sparse edge work/storage and setup hashing. Kill criterion:
any unsupported finite-support inequality, unnoticed change to seed/domain space,
version confusion, or use of this setup-only result to certify FS/H/proximity.
The existing v1 classical study remains historical evidence, not quantum admission.


Result: the exact finite checker now bounds all 200431782 events by 2^-416.
The versioned v2 map/manifest/block domains use the stronger twelve degree pairs.
The all-seed union is 2^256*200431782/2^416 < 2^-132. Outside that bad-oracle event,
every successfully regenerated supported code is good, so even arbitrary quantum
selection cannot output a bad one. The proof in formal/seeded-setup.md needs no
query cap or selection theorem and accounts for capped-stream rejection. This is
an ideal-oracle setup result, not a concrete BLAKE3 or whole-protocol guarantee.

The checks re-derive every degree, compare interval inequalities with exact finite
combinatorics, retain the small-field exhaustive cases, and reject the old event
budget and an enlarged seed universe as insufficient for the target. V2 fixed
digests, independent expansion, actual generated-map parity, source tampering,
exhaustion and v1 descriptor rejection pass. The generic quantum counterexample
remains to prevent restoration of the inadequate classical-only formula.

Recommendation: continue A1/A7 with v2 and remove the classical query-budget API.
Keep production admission blocked until authenticated identity/registry/consumers,
proximity, allocation policy and Q12 composition are complete. In particular, a
protocol theorem that assumes fresh independent oracle outputs cannot silently
be applied after conditioning that oracle on good setup. Both error events need
an applicable joint argument; neither success of regeneration nor this union
proves the remaining claim graph.

The n=256 sparse map has 9728 edges versus v1's 7424, each costing one addition
and multiplication per field limb. This is an exact algorithmic count, not measured
throughput. Complete recursive edge counts remain E(J); setup caps, linear work
and storage bounds stay fixed. No production coefficient, weight pass, benchmark,
GPU result, PCS control or admitted profile is supplied.

## Code identity and checked registry study

Question: can one checked identity select the exact map, field-independent
parameters and encoding path, without trusting raw graphs or metadata supplied
by a prover? Security property: code identity and parameter provenance; cost terms:
setup preparation, c_c and retained graph/byte storage. Kill criterion: caller
metadata changes a bound/map, unknown or duplicate registry data is accepted,
invalid row/query reaches setup allocation, or syntax is mistaken for PCS admission.


Run `uv run --locked --script research/code-provenance/check_identity.py`.
The [candidate contract](../../formal/code-identity.md) fixes two identity formats,
explicit field selection, derived parameters and a sealed native API proposal.
The research encoder accepts only identities, regenerates actual v2 setups and
uses the existing maps. The catalog checker compares every field and type against
fixed definitions; neither TOML metadata nor a returned parameter snapshot is
consumed as encoding authority. Both PCS proven flags remain false.

Thirty field/map cases pass complete-word and duplicate-query parity. All 72 sizes
resolve in three fields without setup/FFT calls. Each catalog field is mutated
individually; duplicate/unknown/missing/wrong-type/oversized data rejects. Invalid
rows/columns and empty queries reach no setup or FFT work. Different seeds with
equal parameters produce different maps, so consumers must bind the full identity
and field rather than only dimensions or a theorem name.

Recommendation: continue A1 with this common identity boundary. Actual native
capacity handling and authenticated PCS/plan/passport consumers remain required,
as do proximity, query/error composition and profile admission. The extra bounded
registry/descriptor work changes no measured c_c/T_misc constant or weight-pass
count; regeneration, full encoding, raw copies and peak storage are still charged.
