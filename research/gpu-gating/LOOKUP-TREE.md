# Production lookup tree reference (E16-40c)

`stele_reductions::zk::claims::bench::LookupCase` is available only with the
off-by-default `bench` feature. It supplies the actual RFC-0008 A7 CPU reference
for a subsequent device experiment. No production prover or verifier calls it;
there is no device consumer or backend approval in this change.

The constructor validates the full public statement and assigned column lengths,
selects one lookup, and converts canonical M31 columns to the challenge field as
the production prover does. This is host setup. A caller supplies synthetic
`beta` and `alpha` values; the adapter neither generates proof challenges nor
changes a transcript.

`inputs(beta, alpha)` uses the production helpers to assemble concatenated shifted
tuples, the public selector, padded table denominators, original multiplicities
and compression powers. The selector is zero off the members; an unselected
lookup leaf has denominator `alpha`. Table padding has denominator one and zero
multiplicity beyond the original table domain. Member padding and coordinate
order come from the actual plan. These are benchmark witness values, not public
geometry: the adapter does not log or persist them.

`reference(beta, alpha)` calls the unchanged production tree builder, including
its host input preparation, and then the committed-top builder. The result keeps
every layer, root first, with numerator/denominator pairs at each position. Its
top contains `p`, `q`, and `h = p/q` at layer `c_D + 1`. A zero top denominator
returns the same `DenominatorZero` error as the ordinary producer.

Future paired measurements must charge the device path for `inputs`, uploads,
device computation, returned material and any host assembly. The CPU reference
already includes its own input preparation; do not add a separate `inputs` time
to it. Constructor costs, cold context/module setup, whole-process costs,
retained material and host/device overlap must also be reported. The adapter
does not establish a complete device-memory peak or source-lifetime policy.

```sh
cargo test -p stele-reductions --features bench,std --test lookup_bench --release
cargo check -p stele-reductions --features bench --no-default-features
```

The tests cover a padded single member, multiple members with a selector and
shift, extension-field tuple compression, exact leaf layout and top equations,
a one-multiplicity near miss,
invalid lookup/column/selector inputs and a zero denominator. There is no timing,
integrated proof, CUDA parity or ADR-127 GO claim; the device consumer must follow
this interface's review and merge.
