# Public coefficient arithmetic (RFC-0006 A7)

This contract specifies pure mathematical evaluation, not source authentication,
a stage descriptor, transcript, claim consumer or CQIS table generator. A caller
must obtain sources from its actual public input or Accepted authenticated
consumer. In particular, supplying a committed private index list here neither
opens it nor preserves zero knowledge. A4 and all E3-06 obligations remain open.

## Definition and admission

An ordered layout has 1..64 axes `(bits, real)`, with bits in 0..63,
`1 <= real <= 2^bits`, and total bits m <= 63. Axis bits are MSB-first;
axes concatenate in layout order. Each axis has either no selector or an exact
bits-long K point z. At Boolean coordinate x, define T(x) as zero if any axis
is padded, otherwise the primitive value below times the product of eq(z,x)
over selected axes. Evaluation returns `sum_x T(x)*eq(r,x)` for a length-m K
point r. This is the MLE of the entire selected Boolean table, never a product
of separately extended masks and selectors. No assumption that r or z is
Boolean is allowed. Typed fields have already passed canonical decoding. Reject a different base
characteristic as FieldMismatch; K must extend M31.

| Primitive | Parameters and value on real coordinates |
|---|---|
| Eq | no parameters; value one |
| CausalMask | distinct in-range axes i,j of equal bit width; value 1[j<=i] |
| WindowMask | same axes, positive u64 width w; value 1[j<=i and i-j<w] |
| OnehotSparse | distinct row/category axes i,j; one u64 q per real row, each below real category length; value 1[j=q[i]] |
| GqaBroadcast | distinct head/group axes h,g, real H divisible by real G; value 1[g=floor(h/(H/G))] |
| RopeTables | nonempty strictly increasing source-axis ordinals; exactly the product of their real lengths in M31 values, unpadded row-major; value the indexed source entry embedded in K |

All other axes broadcast the primitive before padding/selectors are applied.
RopeTables names the exact-table arithmetic used by a RoPE consumer; this API
does not establish that supplied values are valid CQIS rotation values.
Borrowed immutable source slices prevent post-admission mutation in safe Rust.
No tensor id, commitment, source-verified flag or authentication callback exists.

Validate the entire descriptor at construction, including checked products,
all source entries/indices and selector lengths. Shape failures return Shape.
Evaluate rejects wrong point length as PointDimension. Allocation/size overflow
or exceeding the caller's vector-entry budget returns Capacity. The budget caps
the sum of padded axis-vector lengths for source/group kinds; masks/Eq allocate
none. Check it before allocating. Allocation failure also returns Capacity.
The budget is a caller resource policy, never a security bypass or proof field.

## Algorithms and costs

For each axis bit use choice weights `(1-r,r)`, multiplied by `(1-z,z)` if
selected. For independent broadcast axes sum weights over valid indices using
a two-state low-bit borrow DP for `(real-1)-index`. The final no-borrow state
is the bounded weighted sum. Multiply these independent-axis sums.

For mask offset k, sum assignments with j+k<=i and i<R,j<C. Process low bits
with four state bits: carry of j+k, borrow of i-(j+k), borrow of (R-1)-i,
borrow of (C-1)-j. Branch over both i,j choices, multiply their weights and
accumulate into the resulting state. Only final state zero is valid. If
k>=2^bits return zero. Causal is offset(0); window is offset(0)-offset(w).
This uses two arrays of 16 field elements and O(bits) work, including width
zero; it never materializes the position domain. The invariant is that every
partial assignment contributes to exactly its arithmetic carry/borrow state.
Thus final acceptance is precisely the three inequalities, proving the MLE sum.

For onehot/GQA build axis weight vectors in Boolean index order by doubling
prefix weights, then sum row_weight[i]*column_weight[q[i]] (or the group map).
For exact tables build each selected source-axis vector and enumerate real
entries, multiplying the corresponding vector weights and the embedded value.
All operations are field additions/multiplications; no random inversion occurs.
Field genericity is algebraic, not permission to select a protocol field.

With a axes, m bits, S=sum of padded source-axis sizes, R real rows and N real
table entries on k source axes: Eq/masks cost O(a+m) work and O(1) field storage;
onehot/GQA cost O(a+m+S+R) work and O(S) storage; exact tables cost
O(a+m+S+k*N) work and O(S+k) storage. Immutable sources/selectors/layouts remain
caller-owned and must count in complete memory measurements. Admission scans
source indices in O(R), checks exact-table length in O(k), and validates layout
and selector lengths in O(a). No timing, fitted constant or weight pass changes.

## Delivery and protocol boundary

Require independent direct Boolean-table evaluation at 10,000 seeded points for
each kind in each of QM31/OM31, including nonzero extension limbs, overlapping
selectors, irregular padding, reversed mask axes, zero-bit axes and boundaries.
Check malformed descriptors, resource rejection and large masks without table
allocation. These are arithmetic tests, not NC-0203 or source-binding controls.
An embedding reduction still needs the Accepted statement/bytes, degree, final
consumers, source authentication, privacy analysis and actual negative controls.
No challenge, commitment, certificate, ledger line or profile is introduced.
