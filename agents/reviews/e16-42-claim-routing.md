# E16-42 claim routing and batch verification review

Lane E reviewer `resident_actual` accepts the development-tier algebra and
routing at `9e11a5ff` relative to `2b79f5f3`. I traced the ordinary source
batch and shared mask batch through the producer and verifier under RFC-0013
A5 items 4, 5 and 5a and RFC-0008 A7.

For data position `p`, the dense table accumulates every `gamma[a] * weight`
contribution at `p`. By distributivity, summing that table against
`eq(point, p)` equals the sum over claims of `gamma[a]` times the sum of
their weighted equality entries. Both sides count duplicates and preserve
extension-field coefficients. The separate factor `1 - w` sets the mask
face to zero. Both verifier paths derive the equality table from the verified
sumcheck point and source dimensions, validate every position, and check the
claimed public weight final before the committed source opening.

I tried to break it by placing a weight just beyond the data face with a zero
batch coefficient, and the control `matches_reference_sparse_batch_weight`
rejected it. I reran the focused test. It also rejects truncated points and
mismatched claim counts and checks the dense result at both Boolean faces and
an extension-field point.

Ordinary column limbs are one or the extension degree. The lowest limb has
unit basis in both supported fields. The parallel equality table retains
the reference's MSB-first indexing, so limb and mask positions keep their
previous weights. Moving each finals vector transfers the same ordered claims
and blocks into their source batches. The first and second child pairs still
feed the numerator and denominator respectively. The producer checks the
A5 claim-block ranks and the A7 layer-block ranks before routing. Leaf steps
finish before the fold draw. Interior steps draw the same `FractionFold`
after the same finals, and batching retains its `BatchCoefficient` draws.

The change introduces no public item, binding, virtual column, degree or
accounting line. The verifier retains its source certificates, sumcheck
checks, data-face opening and existing NC-0915 control. The full native and
digest gates, and the matched stories42M measurements, remain merge evidence
to collect on the intended tree.

## Measured development workload

Three stories42M T32 proofs on the same 16-thread M4 Max verified against the expected model. Each wrong-model control was rejected. Median self-verification fell from 19.970 s to 14.772 s, GKR claim routing from 7.871 s to 6.351 s and relation claim routing from 2.619 s to 0.902 s. Median whole-proof wall time increased from 261.39 s to 265.73 s. GKR round arithmetic, outside this change, took 94.963 s and 100.576 s respectively. The result supports keeping the change for the three targeted CPU stages. The three samples do not establish a whole-prover speedup. [Baseline ledger](../../bench/ledger/e16-41-dev-zk-stories42m-t32-mac-2.json) and [candidate ledgers](../../bench/ledger/e16-42-dev-zk-stories42m-t32-mac-1.json).

The public evidence archive for measured source `9e11a5ff` has SHA-256 `eb9d11c3ae0d9014342573e6fb53f21966eac7654cba1079c7c98e7a96f649b7`. The terminal audit checked the three captures, model pins, proof byte counts, stage inventory and hashes.
