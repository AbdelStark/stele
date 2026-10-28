# Q31 continuation — Grouped public units

Question: can weighted multiplicities repair characteristic cancellation without
retaining a separate multiplicity vector for every count-bounded partition?
Kill criteria: vanishing fixed-subset polynomial, a schedule attack, wrong
fraction-tree identity or uncharged source work. Terms: c_lu/T_misc, table
indexing, source visits, accumulator/commitment fields and peak state. Run
`uv run --locked --script research/logup-characteristic/check_units.py`.

The [derivation](../../formal/weighted-logup.md) assigns equality-basis units to
fixed groups of B<p source positions. A nonempty subset has a nonzero group-count
MLE of degree at most h=log2(groups). It derives a conditional single identity
bound min(1,(h+N+c*|T|-1)/|K|), including tuple compression. Two independent unit
vectors and both multiplicity commitments preceding every alpha/beta give the
squared identity bound even when the prover jointly chooses the multiplicities.
Source, GKR, PCS, hashing, FS and privacy errors remain outside this bound.

The finite study covers 528 nonempty subsets over 3,618 challenge points and
checks the degree bound plus Boolean recovery of group counts. Explicit cases
show why sharing theta does not square its failure, why selecting bad positions
after theta breaks the premise, and why late multiplicities fit a bad equation.
Across F_3/F_5/F_7, complete nonpole challenge enumerations give 1/p for the
shared-unit cancellation example and 1/p^2 for independent units.
These are algebra diagnostics, not real lookup proofs or native controls.

Across 400 seeded cases in QM31/OM31, both single and paired preparation match
independent group histograms folded as MLEs. Each mode visits 7,142 logical source
records in total, exactly once per case. Virtual trees with weighting only above
the groups equal independently summed weighted leaf fractions, including zero/
one unit coordinates. Altering one multiplicity changes the root equation.
Three constant-unit, unit-coordinate and tree-coordinate mutants are rejected;
malformed shape/table/field-point/selector and source misuse checks also pass.

Paired preparation shares a table-sized base histogram and keeps two K-valued
table accumulators. All table scans and limb updates are counted. Input records,
table indexing, Python overhead, virtual trees, PCS and actual source regeneration
remain additional costs; this is not native streaming or a weight-pass gate.
The dependency lock matches the existing pinned research field oracle.

Recommendation: continue Q31 with this explicit candidate under RFC-0008 A2 /
RFC-0012 A8. Complete source/selector and leaf consumers, canonical bytes,
challenge registration/accounting, K-valued commitment/privacy layout and full
native cost/control evidence before acceptance. No profile, ZK or end-to-end
lookup implementation is claimed, and E3-07 keeps every original criterion.
