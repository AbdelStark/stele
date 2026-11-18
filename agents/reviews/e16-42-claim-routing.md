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
