# Exact gated-product bounds — Q26 research

Status: Draft RFC-0004 A3/A8. E5-03 remains blocked; all original acceptance
criteria and NC-0109 remain unchanged. No admitted proof consumer.

Question: can the exact signed int16-by-int16 product be bound to both factor
sources before gated row conversion, without a modular alias or intermediate
requantisation? Security property: static integer faithfulness and source
association. Cost terms: c_a/T_witness; no measured constant changes.

Kill criterion, stated before implementation: drop this candidate if a false
product or coherent intermediate can pass through an M31 alias, if any bound
uses actual values, or if integer/NumPy references disagree. The product retains
units fu+E and the complete row conversion follows it. SiLU membership, factor
ownership and actual range/source consumers remain separate obligations.

## Expected parameters and ranges

The Spec fixes FFN dimension d in 1..16384, up-projection fraction fu in 0..30
and SiLU-output fraction E in 0..14. The product fraction is exactly fu+E in
0..44. Changing either factor's units changes the record; there is no product
shift, rounding, saturation or independent output fraction. Model templates
use the FFN shape, fu and configured SiLU E, never observed tensor values.

Both separately expected factor tuples have exactly d signed-int16 entries.
The result uses the gated row format [-2^30,+2^30]. This is a conservative
format envelope: not every endpoint is necessarily a member of the selected
SiLU function, whose identity/membership still requires its own consumer.
The input source range alone suffices for this conditional multiplication lemma.

## Offset relation

For each expected pair x,y let u=x+32768 and v=y+32768, each in [0,65535].
The witness supplies h in [0,65535^2] and output z in [-2^30,+2^30]. Enforce:

```
h = u*v
h + 2^31 = (z+2^30) + 32768*u + 32768*v
```

Expanding the second identity after substituting the first gives z=x*y as an
integer. These three byte-column roles implement the identities:

| Role | Count | Left cap | Right cap | Operands |
|---|---:|---:|---:|---|
| product | 1 | 65535 | 65535 | u times v |
| lhs | 2 | 65535^2 | 1 | h plus 2^31 |
| rhs | 3 | 2^31 | 32768 | (z+2^30), u, v with coefficients 1,32768,32768 |

The product result is compared to h through canonical digits. The lhs and rhs
results also compare canonical digits. The source offsets and output offset
are derived from their checked integer ranges; they are not supplied as free
residues. There is no direct wide field equality, sign witness, nonzero bit
or branch on the observed product.

Whole factor ranges imply h<2^32 and actual equation sides<2^33. The generic
rhs role has a conservative cap 3*2^46<2^48 because it applies a uniform bound
to all three operands. This larger cap does not weaken the relation: exact
source digits and the fixed coefficient tuple remain checked. All scalars and
results therefore fit eight canonical bytes without truncation. Operand lengths
are at most four left/two right bytes, with at most six result columns.

The largest raw byte coefficient is <=3*255*(255+128)=292995. A carry bound
of 1149 is inductive because floor((292995+1149)/256)=1149. Both column sides
are <=294399<p/2. The generic engine recomputes tighter per-role caps and
requires zero initial/final carries. This is static over all allowed dimensions,
fractions and factor values; individual coordinates introduce no row sum.

Exact zero products follow from the same identity, including either source
being zero. Signed endpoints and opposite signs require no separate case.
Every returned product is then eligible for the existing gated row conversion,
which retains the complete row and its shared scale before down projection.
No assertion here authenticates where a factor or selected SiLU value came from.

## Encoding and model roles

The tag is `stele/research/q26/gated-product-bounds/v1` plus NUL (43 bytes).
Parameters are little-endian u32 d and u8 fu/E. Then come u32 p, u8 radix bits
(8), u8 scalar count (10), and these u64 scalars in order: product_fraction,
source_max, source_high, source_offset_max, output_max, output_offset_max,
offset_product_max, offset_bias, restoration_factor, entry_capacity. The last
value is the fixed 16384 ceiling, not observed row length or a source bound.

An u8 role count (3) precedes product/lhs/rhs in that order. Each role has local
u8 ID 1..3, u32 count, u64 left/right/result maxima, three u8 digit lengths,
byte digit caps and u32 carry/lhs/rhs caps. The fixed prefix is 136 bytes.
A role is at most 120 bytes, so even three maximum-size roles total 496 bytes,
below the enforced 512-byte capacity. Exact regeneration rejects altered,
truncated or extra data; bytes cannot authorize their own expected metadata.

The adapter emits `layer.i.gated_product` once per block. Its correctness
checksum frames record count, role-name length/name and record length/bytes
under `stele/research/q26/gated-product-bounds-checksum/v1` plus NUL. This is
not a complete certificate-set contract, cqis_id or authenticated source map.

## Tests and composition

Run `uv run --locked --script research/cqis-checkpoint/check_causal_model.py
--gated-product` for corpus/models/controls, or `--gated-product-controls`.
Tests were written first and failed with the missing implementation module.
The checker is compared with exact Python products and NumPy int64 products;
an independent packed-polynomial column oracle, struct framing and NumPy
convolution cross-check every role. Shared generic numerical primitives and
model fixtures are disclosed, not presented as independent audit.

The corpus checks 10000 random rows of 1..9 entries and all allowed unit ranges,
plus 10000 independent static dimensions in 1..16384. A complete 16384-entry
endpoint row checks the maximum actual shape. Controls cover all pairs from
{-32768,-32767,-1,0,1,32767}, zero factors, scalar changes, source substitution,
malformed shapes/types, carries, certificate fields and every representative
encoded byte/truncation/suffix.

A decisive control uses x=y=-32768, true z=2^30 and forged z=-2^30+1. Both
outputs satisfy the gated format and differ by p. Rebuilt rhs columns reject
with IntegerRelation. Another control adds p to h at x=y=0, within h's bound;
this preserves both wide field equalities but fails canonical product binding.
These are conditional factor-range attacks; they do not assert that -32768 is
a valid output of every SiLU function.

Model checks feed verified products into gated row conversion, compare the
shared scale/codes and units, then feed those codes/scales into the scaled
linear checker for every down-projection output channel. Models vary units,
static/dynamic gated policies, shapes and weight formats. SiLU evaluation uses
the existing certified primitive; its transcendental independence and source
membership are not retested or proved by this arithmetic composition.
The pinned baseline and separate block-mode replay both consume this chain.
All prior fixture fields are preserved; serialized sizes are not benchmarks.

The seed2653 corpus and static-dimension checks have frozen SHA256
`23d27d03d47fb95ddee8addd66d2e729f5f0b6573bcd97694e988b038b6d8924`.
Thirty seed2654 models give 28 valid full replays and two arithmetic-overflow
rejections. The pinned fixture adds two records, 908 bytes, checksum
`31624336a98cb3bea846aeddda66b150a4b4c710ae2af7b3e446d102ba72d2a8`.

## Recommendation

Continue Q26 with the existing closed RMSNorm schema's model adapter and then
an explicit complete bound-set/function-registry/source coverage contract.
The exact gate multiplication was absent from the existing gated row schema,
which consumed a separately expected product. This study supplies that missing
conditional arithmetic relation; the source/lookup claim graph remains open.

E5-03/04, E7-05, original NC-0100/0101/0109 and gate-source/unit controls remain
mandatory. No Accepted RFC-0022 format, challenge, loss, cut, weight pass or
production constant changes. The research checker uses O(d) work/data for the
actual factor row; eventual production terms are c_a/T_witness. Native parity,
full inference, fidelity, PCS/ZK/FS and actual range/source/function consumers
remain required.
