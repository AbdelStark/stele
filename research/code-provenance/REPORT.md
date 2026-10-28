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
