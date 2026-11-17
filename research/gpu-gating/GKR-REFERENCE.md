# Production GKR references (E16-40g)

`stele_reductions::zk::claims::bench::observe_gkr` runs the ordinary CPU prover
and observes each genuine GKR step after its rounds, public aborts and final
claim routing. The explicit `bench` feature is off by default. The callback
receives read-only references to the actual instance, point and expanded finals,
plus a copy of the routed claims. It can return success or an error; it cannot
return replacement proof values or borrow the transcript. A callback error stops
the operation. Lifetime sources use the ordinary model-root and disclosure rules.

`GkrCase::reference` calls the production factor builder with the same plan,
lookup state, tree, columns and mask blocks. Its `Masked` result exposes compact
terms, degree, vanishing coordinates and tables, with ordinary rounds and folds.
`final_values` requires every variable to be bound and performs the production
compact expansion, including member-column and mask-block evaluations. For a
device consumer, `expand_at` consumes an unfolded reference and applies that same
expansion to supplied compact values at the given point. Wrong point/value lengths
and already folded references are refused; supplied values remain untrusted.

`GkrCase::route` applies the ordinary public-final checks and returns source
claims, shared mask-block claims and next-layer children. It does not authenticate
non-public claims: their source batches and openings still do that. Compare all
expanded values and routed outputs with the genuine step, not just the number of
factors or a root. First, interior and leaf steps have different input semantics.

These observations contain private witness data, masks and challenges. They are
explicit benchmark inputs, never public topology metadata, and must not be logged
automatically. Keep one observed step at a time; count any deliberate copies and
retained data. Rebuilding factors, reference folds, expansion, claim routing and
the cloned routing receipt are real host work. Separate reference-check overhead
from the measured candidate operation, and charge all host work the candidate
actually needs. Do not apply a rounds-only ratio to the entire GKR stage.

The returned proof is always made from CPU values, even if the callback executes
CUDA comparisons. This interface therefore supplies no integrated GPU proof,
full CPU/GPU proof-parity, complete device-budget, speedup or ADR-127 GO evidence.
It changes no binding, challenge, commitment or dependency. A device consumer
must wait for this interface to merge; core integration still requires the
accepted backend contract and the complete qualification gates.
