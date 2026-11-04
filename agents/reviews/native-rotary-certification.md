# Native rotary coefficient certification — E5-03

Scope: RFC-0025 §2.4 and encoding appendix §4. This is a same-author
`cqis-numerics` / `soundness-auditor` review of the native coefficient generator.
Registry admission, public-MLE consumers, inference, source authentication and
the complete E5-03 controls remain separate delivery requirements.

## Exact enclosure argument

The target is unchanged: `f = theta^(-2*j/width)`, the explicitly selected
base/linear/llama3 scaling, then signed half-away rounding of
`16384*cos(position*frequency)` and `16384*sin(position*frequency)`.
The native method encloses `f` through `exp(-(2*j/width)*ln(theta))`.
It does not materialize the research method's high-degree integer root.

Every interval endpoint is an integer on the selected 128-, 256- or 512-bit
fractional grid. Products and quotients round outward, with exact integer
remainders. Signed downward rounding uses the ceiling of the magnitude for
negative values; upward rounding uses its floor. No host floating point enters
the generator.

For the logarithm, write `theta = 2^k*x`, `1 <= x < 2`. With
`z = (x-1)/(x+1)`, the exact `z` is in `[0,1/3]`. The positive atanh series
encloses `ln(x)`. After the included terms, its remaining tail is at most
`3*z^(2N+1)`. The code uses an outward upper bound on that next power.
The same construction at `z=1/3` encloses `ln(2)`.

The negative exponential argument is halved until it lies in `[0,1/8]`.
Adjacent alternating partial sums enclose the exponential; outward squaring
restores the argument. Machin's identity uses the alternating arctangent
series at `1/5` and `1/239`. Positive and negative partial sums are accumulated
separately, so uncertain terms cannot cancel their own error intervals.

Llama3 scaling uses monotonic endpoint operations. The difference between the
two rational thresholds is computed exactly from full u64 cross-products.
It is never rounded to a grid before division. Clamping preserves both
endpoints even when the interval crosses a narrow scaling transition.
Multiplication by the absolute position precedes trigonometric evaluation.

The angle interval is halved until its upper endpoint is at most `1/8`.
Adjacent Taylor sums enclose sine and cosine throughout that interval.
Outward double-angle products restore the original angle; intersection with
the proved `[-1,1]` range is valid. This recurrence operates on certified
intervals, never on rounded Q14 coefficients. A pair returns only when both
endpoints of each component round to the same signed Q14 integer. Otherwise
the next precision is tried, with rejection after the final unresolved level.

Scratch remains below 2048 bits. Before angle halving, endpoints require at
most 533 bits. Fixed-point products/division numerators require at most
`2*512+21` bits. Exact threshold endpoint cross-products require at most
`512+212` bits. The existing fallible Natural allocator and its cap are
unchanged. At most three precision caches retain one interval per pair;
each cache belongs to one immutable checked Rotation. Hashing retains one
position-major row of at most 32768 bytes and traverses the entire descriptor
length without the old research materialization cap.

## Evidence

Seed 50333 supplies 10,002 native coefficient pairs from an independent
768-bit Arb log/exp/trigonometric oracle, including maximum width, full u64
rationals, all three families, both layouts and a narrow transition requiring
refinement. Native Q128 enclosures contain the independently rounded reference
enclosures. Selected cases also check the 256- and 512-bit paths. A known
premature-frequency-rounding counterexample remains `(9214,13548)`.

Seven complete data fixtures cover all family/layout combinations and a
maximum-width row. Their hashes include the full canonical descriptor identity;
changing layout changes the data identity even when coefficient arrays agree.
Separate checks cover signed half-away boundaries, invalid positions/pairs and
unsupported precision. The fixture source hashes and generators are committed;
historical research campaign mains were not rerun.

## Workflow 03

1. Public `Rotation::coefficient` and `data_digest` implement RFC-0025 §2.4 and
   encoding §4. They return generated numerical data, not proof admission.
2. No challenge or transcript absorb order changes.
3. No field claim is emitted. Registry and actual public-table consumers must
   still consume the complete generated data identity.
4. The tests check coefficient/range/descriptor identity behavior. NC-0106 and
   the assigned complete-model controls need their actual consuming relations;
   this checkpoint claims no additional control-catalogue coverage.
5. No soundness-accounting line changes.
6. These are real-function enclosures, not field bound certificates. E5-03's
   nineteen-schema static collection remains required.
7. Canonical rotation data has no padding. Proof layouts and padded MLE
   selectors remain obligations of the actual public-table consumer.
8. Precision order, pair/position order and rounding are deterministic.
   Caches contain only locally certified intervals under the same definition.
9. Independent numerical parity passes. No GPU or proof-byte parity is claimed.
10. Generation belongs to offline preparation and public-data costs. No online
    weight pass or measured cost-model constant changes; no benchmark is claimed.
11. The crate remains `no_std` and forbids unsafe code. Geometry precedes
    allocation; buffers are fallibly reserved; incomplete generation returns no digest.
12. Names retain Rotation, Model, Registry, coefficient and absolute position.

I tried to break it by changing positions, pairs, layouts, rational extremes,
precision and signed rounding boundaries, and the control tests rejected invalid
inputs or exposed the changed identity while preserving the independent numerical
results. This same-author review does not approve the unfinished E5-03 task PR.
