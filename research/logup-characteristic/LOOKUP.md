# Q31 complete lookup consumer study

Question: can one ordered single/paired protocol connect the weighted identity,
both fraction trees, selected source leaves and the same pre-challenge committed
multiplicities, without leaving a final value unchecked? Kill criteria: a late
multiplicity choice, reused preliminary challenges, missing source/table consumer,
wrong table padding, or a claimed private PCS result from a revealing adapter.

The study uses the existing RFC-0012 A3 Merkle primitive for actual binding
of base-field source columns and K-valued multiplicities. Complete vector reveals
close their MLE claims. This is an explicit research adapter for testing
the entire computation, not the private PCS, ZK or efficient opening required
by E3-07 and the end-to-end prover. No task criterion or production mode changes.

Run `uv run --locked --script research/logup-characteristic/check_lookup.py`.
The pinned blake3 dependency has a committed uv lockfile. The actual protocol,
payload inventory and conditional losses are in [the contract](../../formal/lookup-consumers.md).

The checker completes 96 invocations across both fields and repetition counts,
source depths 0..3, tuple widths 1/2 and table sizes 1..5 (including non-powers of
two). Inactive positions contain out-of-table values. Weighted multiplicities
agree with an independent histogram MLE fold. All original ids, derived points,
claims, SC records, total numerators, transcript state and actual event sequences
agree. Events check the exact Unit/Beta/Alpha/Gamma/Fold/Sumcheck counts and order.

One-value opening payload changes reject CommitmentMismatch against the original
source or mu root. Changed evaluations reject OpeningMismatch; wrong source ids
reject OpeningIdentity; missing claims reject OpeningShape. Reused repetition
proofs reject FinalEvaluationMismatch; a flipped inactive selector rejects
SelectorMismatch. Malformed dimensions, counts, noncanonical values and duplicate
table entries reject. Distinct mu ids bind even identical vector payloads.

An adversarial proof of honest tree arithmetic over a selected out-of-table
source and zero multiplicities fails RootMismatch. Another adversary first fits
a bad identity using an early alpha; binding its actual mu root changes the
challenge and the verifier rejects RootMismatch. A valid arithmetic proof with
table padding denominator 2 passes the rational root equation but fails the exact
TableDenominatorMismatch consumer. Real zero denominators reject Pole.
Isolated mutants reuse the first unit vector, reuse a mu commitment id, or
replace neutral table-padding denominators by two; the targeted checker rejects each.

The source roots and all mu roots are actual RFC-0012 A3 Merkle outputs, not
metadata claims of authentication. The full openings deliberately expose those
vectors and have linear payload size; this adapter earns no PCS/ZK, native NC,
inference-mask or performance credit. Recommendation: continue Q31 with the
private committed consumers, production descriptors/parser, complete field/profile
admission, native controls, implementation and measured c_lu. E3-07 retains all
original criteria and remains blocked on Draft A2.

## Canonical limb-view evidence for the native contract

The proposed [conditional native contract](../../formal/native-lookup.md)
uses M31 limb messages and actual A9 functionals, with logical zero extension
of the real table prefix. The same checker now includes 258 exact algebra
cases across QM31/OM31, logical depths 0..4, every positive real-prefix length
and every row/column split with the limb axis wholly in columns.

It independently folds the logical K records and compares against the sum of
one or two physical row-combination/column-dot functionals. Cases include full
extension and Boolean points, scalar domains, all prefix boundary classes,
canonical basis bytes and deliberately nonzero physical tails. Changing an
ignored physical tail limb preserves the logical result. Wrong basis order
and an unmasked tail give different results in explicit fixtures. Structural
pieces remain present when their sampled coefficients vanish.

Run only this bounded new check with
`uv run --python 3.12 --locked research/logup-characteristic/check_lookup.py --limb-view-only`;
the existing full checker also runs it. This is algebra/representation evidence,
not native PCS execution, negative-control credit, privacy or a performance
result. Existing A9 arguments supply the separate conditional near-message
interpretation; implementation must still exercise the actual consumers and
complete canonical bytes. No new research command or dependency is needed.
