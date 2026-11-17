# Claim-batch preparation reference (E16-40e)

`stele_reductions::zk::claims::bench::BatchInputs` exposes the actual production
builders for RFC-0013 A5 item 5 behind the existing off-by-default `bench` feature.
It accepts a prepared hiding source, claims and supplied coefficient values, then
returns the production degree-two instance, weight table and source's `Y=0` face.
No production prover or verifier calls this adapter.

The weight table accumulates repeated positions in claim order and is zero on
the entire `w=1` half. The face includes both data and mask rows, omitting the
`Y=1` columns of every row. Both tables use `(w,row,col)` order. Non-hiding
sources, mismatched claim/coefficient counts and positions outside the data face
are rejected, even when the invalid position has zero weight. Claim values are
not checked here: a one-value near miss still constructs tables and is rejected
by the ordinary dense sumcheck's round-sum check.

```sh
cargo test -p stele-reductions --features bench --test batch_bench --locked --offline
cargo check -p stele-reductions --no-default-features --features bench --locked --offline
```

This adapter retires the risk of using a rewritten preparation reference for a
later device experiment. That consumer must wait for this interface to merge.
Its cost accounting must separate source preparation, these table builders,
copies/transfers, dense rounds and authenticated openings. The returned values
are benchmark witness data, not public geometry or proof metadata.

The supplied coefficients are synthetic benchmark inputs; proof coefficients
still come only from `Transcript`. Constructing these tables or matching dense
rounds establishes neither bound masking nor an authenticated source opening.
No GPU code, timing, device-memory, full-batch/proof parity or ADR-127 GO result
is provided by this interface.
