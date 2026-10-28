# Candidate recursive M31 code map and setup bytes (Q23 / RFC-0010 A1)

Status: Draft. This specifies a candidate encoder and concrete base for the finite
expander schedule. It does not admit a setup, code registry entry, PCS or profile.
Canonical syntax, injectivity and sampling bounds are separate properties.

## 1. Exact map and field

The message length is n=4^J for integer 3<=J<=15; other lengths reject without
implicit padding or fallback. The output has 2n coordinates. For J=3 use exactly
RFC-0010 A2's circle map `Circle::new(6,1)`, with its fixed input/output domains,
basis, order and normalization. This base is non-systematic: its first 64 output
coordinates are not a copy of its input. There is no configurable alternative base.

For J>=4 let A have n rows and n/4 columns, B have n/2 rows and n/2 columns.
Interpret messages as row vectors and use the previous level's exact map:

```
y = x*A
z = E_previous(y)
E_J(x) = x || z || z*B
```

This order is fixed. The top-level map is systematic for J>=4, irrespective of
its edge coefficients. The recursive base remains the named non-systematic map.
Every coefficient lies in canonical M31, including zero. Extend the same M31 map
to QM31/OM31 by applying it to each limb in the RFC-0003 basis, or equivalently by
embedding its coefficients into K. This does not replace M31 with binary XOR.

The following fixed row degrees are re-derived by the existing exact finite-bound
checker; the row domain changes at each recursive level, not with each input.

| J | A degree | B degree |
|---|---|---|
| 4 | 18 | 22 |
| 5 | 16 | 17 |
| 6 | 15 | 17 |
| 7,8 | 14 | 17 |
| 9,10,11,12,13 | 13 | 17 |
| 14,15 | 14 | 17 |

Each row lists that many distinct in-range neighbor columns in strictly increasing
order, paired with M31 coefficients. Zero-valued edges stay in the list; do not
remove them, merge duplicates, sort malformed input or change the degree implicitly.
The uniform-ensemble analysis selects distinct neighbors uniformly and independent
uniform M31 coefficients including zero. Sorting a sampled set changes its storage
order, not that distribution. The seeded research fixture is not a cryptographic
sampler or evidence that a production setup obeyed the sampling assumptions.

## 2. Canonical setup descriptor

The exact descriptor is ASCII `stele/expander-m31/v1`, followed by u8(J), followed
by the 21-byte base identity `stele/circle-m31/v1 || u8(6) || u8(1)`.
This header is 43 bytes. Then serialize levels J,J-1,...,4. At each level serialize
A and then B, rows in increasing input-coordinate order. Each edge is
`u32_le(column) || u32_le(coefficient)` in the row's strictly increasing column order.
Dimensions, degrees, level count and edge counts are derived, not overridable fields.
There is no padding, suffix, terminator, seed, profile flag or configurable modulus.

Let `E(J)=sum_(j=4..J) [4^j*d_A(j)+(4^j/2)*d_B(j)]`. The exact length is
`43+8*E(J)` bytes, including E(3)=0. Validate the header and complete derived byte
budget before allocating rows. Unknown versions/base/exponents, duplicate or
unordered columns, out-of-range columns, noncanonical coefficients, truncation
and trailing bytes reject. Parameter arithmetic/allocation must be checked by a
production implementation; research parsing is not a production resource policy.

These bytes fully determine the map. They are a structural representation, not
semantic normalization: different zero-edge locations can describe equal maps
with different descriptor bytes. A future code identity must bind the complete
chosen descriptor; a family name or seed alone does not identify it. No hash or
registry/profile acceptance is supplied here. Arbitrary `proven` metadata is not
part of this descriptor and cannot enable a consumer.

## 3. Algebra, distance and admission boundary

Each sparse multiplication and the circle base is M31-linear. Their composition
is therefore linear over M31 and its named extensions. For J>=4 the explicit x
prefix proves injectivity; at J=3 it follows from circle interpolation. Base and
extension minimum symbol distances agree by the component-support argument in
[the provenance study](../research/code-provenance/REPORT.md).

The accepted [circle derivation](circle-code.md) gives base distance at least
128-64=64, exceeding the three required in [the sampling induction](expander-sampling.md).
Thus the base-map hypothesis is resolved without a sampled-distance estimate.
The outer bound D=floor(n/25)+1 still depends on the exact A/B support properties.
The existing union bound applies only to its stated uniform ensemble. It does not
certify an arbitrary fixed matrix, seeded PRNG, adversarial setup or reuse policy.

In particular, set every edge coefficient to zero. The descriptor remains valid,
and for J>=4 the encoded word is x followed by n zeros. The map is injective with
minimum distance exactly one. The checker constructs this witness. No successful
parse, linearity test or encoder query may stand in for setup/distance admission.
Proximity, exceptional combinations, grinding/reuse, codeword validity and actual
commitment consumers remain separate Q23/PCS obligations. Q12 is unchanged.

## 4. Operations, queries and evidence

For element-field dimension d, the research sparse loops execute d*E(J) M31
multiplications and d*E(J) M31 additions, even for zero inputs/coefficients. This
counts sparse arithmetic only: the d base component transforms, setup parsing,
byte copying, allocation and coordinate copies are additional. It is an operation
formula, not a throughput benchmark or measured c_c coefficient. With bounded
degrees and geometric recursion this work is O(n); the base size is fixed.

The research implementation retains O(E(J)) setup entries, a transient canonical
setup byte copy and O(d*n) field storage across live recursion/copies. Python object
and allocator overhead are not a production peak-memory bound. `eval_row` validates
zero-based columns, allows duplicates in the supplied order and returns exactly
those complete-codeword coordinates. It currently encodes the full row, including
for an empty query; no sublinear query or second code path is claimed.

The independent oracle builds the circle base by Gaussian elimination on its basis
matrix, then uses dense matrix products. Tests compare the full generator at n=256
and recursive dense products at n=64/1024 in M31/QM31/OM31, with full-extension
linearity, zero input, exact operation counts, query parity and malformed requests.
No maximum-size recursive run, Rust/GPU parity, NC-0600..0605 credit, benchmark or
profile claim follows. Complete setup/registry/admission/proximity contracts and
required reviews remain prerequisites to accepting RFC-0010 A1.
