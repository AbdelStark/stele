# Q31 fraction-tree and selector/source reduction evidence

Question and kill criterion: [formal contract](../../formal/fraction-reduction.md).
Run `uv run --locked --script research/logup-characteristic/check_fraction.py`.
The dependency is pinned to official blake3 1.0.11 with a committed uv lockfile.
Research modules do not replace the stele-lookup scaffold or any private consumer.

The study runs 160 tree proofs over full QM31/OM31 values, m=0..4, ordinary and
weighted levels, and some Boolean unit coordinates. Roots agree with the prior
independent bottom-up unit tree. Final original MLEs agree with an independent
half-table fold; the consumer evaluates the Boolean equality sum directly.
Prover/verifier receipts, points, original ids, SC records, total loss numerators,
encoded lengths and transcript continuation agree. Another 80 cases prove the
selected-product leaf equation and consume every actual original source column,
with zero/nonzero selectors, one to three columns and m=0..3.

One-value controls alter root P (FinalEvaluationMismatch or direct LeafMismatch),
an A1 endpoint (RoundSumMismatch), equality coefficient (CoefficientMismatch),
and an otherwise unconstrained child (LeafMismatch at the original consumer).
Leaf controls alter Eq and selector finals with zero summands so the exact
CoefficientMismatch/SelectorMismatch checks, rather than an incidental product
failure, reject them. A zero-coefficient original-source final is accepted only
as a pending obligation and then rejected by SourceMismatch against the actual
originals. Malformed tree counts, fields, descriptor, source order and non-Boolean
selectors reject. The separate root consumer rejects Pole and RootMismatch;
correct cross multiplication with nonzero denominators passes. An explicit
two-row example distinguishes the selected-product MLE from separate MLEs.
Early gamma and early tau attacks choose claims to cancel at a stale challenge;
the actual absorb schedule rejects them. A list/tuple zero-representation alias
exposed a pole-check inconsistency during review; canonical tuple validation
repairs it and the regression rejects NoncanonicalField.
Isolated mutants prepend the child coordinate, reverse weight coordinates or
omit fold losses; check_trees rejects each against its independent expectations.

All sources in closed tests are fixed actual public arrays included in the
initial transcript context. This demonstrates a complete public computation
check, not an authenticated private lookup, canonical inference plan, table-side
committed multiplicity opening or privacy. Error numerators are conditional
interactive algebra, not a production LU record. No runtime/throughput numbers
or native c_lu coefficients are reported. The dense prototype's O(N*m) coefficient
and public-consumer work must not be quoted as the eventual linear prover cost.

Recommendation: continue Q31 / Draft RFC-0008 A2 and RFC-0012 A8 with the exact
source/table identities, committed K-valued consumers, shared multi-tree schedule,
production framing/parser, static admission, accounting and private composition.
The algebraic candidate is executable; it is not permission to accept a reduced
task. E3-07 retains NC-0400..0403, committed table-side sum and measured c_lu.
