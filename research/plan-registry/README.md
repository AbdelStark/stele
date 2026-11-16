# RFC-0026 A16 reference vectors

`vectors.json` pins the Draft A16 entry encoding, request columns, static and
template digests. This is spec-author reference work, not independent verifier
implementation or executed negative-control coverage.

The small cases use opaque `MDL`, `SC`, `P` public blobs and request-only relations.
They test codecs and preflight rules, not valid model registration or inference.
Negative and nonnegative shifts each have windows selecting mantissas 1 and 256,
so retaining the original width during normalization changes the template and
fails the generator's equality assertion. Saturation, checked-prefix, next-token,
zero `below`, padded vocabulary, malformed column and length-precedence cases are
included. The blocked case fixes `ld+lv=30`, requiring two separately named onehot
columns; its sparse positions keep the vector small.

The production pins use the existing synthetic one-layer/T16 and eight-layer/T64
byte-5 fixtures. Every exported proof is verified before writing. The generator
checks every request column against the independently computed integer values,
then records the exact entry, input/proof/relation hashes and template hashes.
Twelve further production declarations vary selected mantissa width and range for
both model fixtures and both shift branches. Each original relation validates;
within each model/branch all three normalized hashes must be equal even though
selected widths differ. They are declaration checks, not proofs of arbitrary tokens.
The CQIS metadata is read with the existing Python reference codecs. These pins
make no security-level or performance claim.

Reproduce from the repository root:

```sh
STELE_DUMP_DIR=/tmp/stele-a16-windows cargo test --release -p stele-prover --test development dumps_byte5_windows_for_the_independent_verifier --locked --offline -- --ignored --exact
STELE_DUMP_DIR=/tmp/stele-a16-windows cargo test --release -p stele-prover --test development dumps_request_layout_variants --locked --offline -- --ignored --exact
uv run --script research/plan-registry/vectors.py . /tmp/stele-a16-windows > /tmp/stele-a16-vectors.json
cmp research/plan-registry/vectors.json /tmp/stele-a16-vectors.json
```

The seven `codec_cases` contain public, relation and entry bytes plus expected
columns. `negative_cases` specify either a replacement relation or one byte edit;
`offset` refers to the relation. For a changed-length column case the independent
unit test checks the column routine; the full wrapper must reject the trusted
length mismatch first. `preflight_cases` explicitly test wrapper precedence.
E8-02f3b must consume these vectors through the fresh independent implementation
and execute NC-1325..1334 with the actual registered entry point. Those controls
remain `todo` until then.
