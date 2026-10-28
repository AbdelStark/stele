# Candidate bounded v2 encoder execution (Q23 / RFC-0010 A1)

Status: §§1–2 are the execution/resource contract adopted by RFC-0010 A4 for the
existing v2 map. The Python study checks algebra, traversal and logical workspace;
it does not implement Rust allocation policy, certify process memory or admit PCS
parameters. The code identity and exact map are unchanged.

## 1. Same map, different traversal

Resolve the exact manifest and field through [code-identity.md](code-identity.md).
The native factory remains closed and its Code implementation sealed. Its element
interface must be sealed to M31/QM31/OM31 in the canonical RFC-0003 representation;
an arbitrary external Field implementation or matching modulus is insufficient
for that trusted factory. Existing Circle APIs are not changed by this proposal.
Validate the whole request before allocation, hashing or encoding. Native typed
canonical field values need no data-dependent normalization; Python checks every
limb. Invalid identity/field/row retain InvalidCodeId/FieldMismatch/RowShape.

For n=4^J, allocate zeroed output of length 2n and scratch of length
S(J)=sum_(k=3..J-1)4^k=(n-64)/3. The public input is borrowed and remains live.
At an outer level, copy x into its output prefix; generate A rows one at a time
and accumulate y=x*A into the next n/4 scratch slots. Recurse on that y using the
remaining scratch and the next n/2 output slots for z. Generate B rows and
accumulate z*B into the final n/2 output slots. Both scatter targets start at zero.
At J=3 call the existing Circle(6,1) encoder, copy its 128 values into the assigned
output region, then release its result. This deliberately charges that overlap.
The scratch regions are disjoint; child inputs remain live until the child returns.
The B input/output regions are disjoint and can use safe split slices in Rust.
No recursive input/output subarray is cloned. Recursion has at most twelve outer
levels, then the fixed base. Rust must use fallible reservations for every vector.

Rows use exactly the fixed block bytes, capped streams, sorted distinct neighbors
and ordered coefficients in [seeded-setup.md](seeded-setup.md). Keep two fixed
arrays of at most 26 u32 entries, one current 32-byte block and bounded framing/hash
state; do not retain a matrix, raw setup serialization or graph cache. Every row
is generated, including for zero inputs; every zero coefficient remains an edge.
There is no successful partial setup, skip based on values, alternative seed or
fallback on exhaustion. Only return the output when the entire traversal succeeds.
Failure drops internal partial results and preserves the borrowed input.

The setup materializer retains its canonical descending-level, A-then-B order.
Encoding instead visits A_J, child levels, B_J. Each block's complete coordinate
is unchanged and each required row stream is consumed once. Since block values
are deterministic and coordinate-separated, traversal changes neither the returned
map nor successful/exhausted status. Every exhausted stream still aborts the whole
operation with SamplingExhausted, even if discovered after earlier arithmetic.
There is no new oracle input, identity, setup distribution or soundness term.

## 2. Checked capacity and complete cost categories

Let w=4*d bytes for d in {1,4,8}; native sizes must agree for the sealed types.
The requested vector payload bound for this execution is:

```
input (borrowed): n*w
owned field payload: (2*n + S(J) + 128)*w
base M31 scratch: 127*4
base vector-of-vector backing: 7*3*sizeof(usize)
owned_payload_bytes = sum of the three owned terms above
```

The existing base forward transform holds 127 twiddles; its inverse holds at most
63 twiddles plus 32 prefix products, so 127 bounds either phase. At most seven
inner Vec headers occupy the outer vector backing. Their stack headers, recursion
frames, sampler arrays, block framing and BLAKE3's internal stack/state remain
separate bounded stack costs. The base-only J=3 bound is conservative: it still
charges both the outer 128-value result and the temporary base result.

Compute counts in checked u64 arithmetic, convert each actual length/byte count
with checked conversion to usize, and reject Capacity before allocation on any
overflow or if either borrowed bytes or summed requested owned payload exceeds
isize::MAX. A smaller address space can reject a mathematically supported map.
Operation counters are u64, not usize: row/hash/edge totals may exceed the address
range even when the live buffers fit. They do not justify allocating a graph.
The research calculator models 32/64-bit targets; native code uses its actual target,
not a caller-supplied width. Allocation failure is Capacity, never fallback.

These are requested payload bounds, not exact allocated capacities, allocator
metadata or RSS bounds. Native delivery must record actual vector capacities and
allocation rounding, bounded stack/hash overhead, retained caller inputs, result
and base overlap, runtime/toolchain overhead and full process peaks. Python tuples,
integers, component FFTs and garbage collection do not obey the native byte formula.
Neither the calculator nor nine small runs discharge that delivery requirement.

For E(J) as in recursive-code.md and R(J)=sum_(j=4..J)(4^j+4^j/2):

- Sparse arithmetic: d*E(J) base-limb additions and multiplications; no zero-edge
  discount. The fixed circle base is additional (the Python oracle runs d components).
- Generation: every row uses two streams, at most 64*R(J) BLAKE3 blocks in total,
  each with 74 input bytes. Masking, duplicate checks, sorting and coefficient
  rejection are additional work with fixed degree/cap bounds.
- Initialization/copying: zero output/scratch, each recursive systematic prefix,
  base result copy, validation and descriptor work are included separately.
- Queries: validate all columns first, preserve order/duplicates. Empty queries
  return empty without encoding. Nonempty queries encode the full row; while
  selecting, the encoded word and q selected values coexist. Check q*w and the
  combined requested payload with the same checked arithmetic before work. The calculator includes q requested result slots and q borrowed
  usize column indices; malformed/overflowing counts reject without allocation.

The native query path must reserve the selected output fallibly before encoding
so a malformed or unrepresentable request cannot cause partial output. The Python
query wrapper checks that budget and reserves its logical result before encoding;
it does not establish native allocation or process-memory behavior. Full encoding is linear in n with fixed degree/caps, but
hash generation occurs on every call and can dominate c_c/T_misc. No amortization,
measured coefficient, GPU throughput or weight-pass improvement is claimed. This
changes no matmul phase and does not add another pass over committed weights.

## 3. Evidence and graduation

Run `uv run --locked --script research/code-provenance/check_bounded.py`.
For J=3/4/5 in all three fields, compare every output with the existing materialized
map, which has separate dense/base oracle evidence. Check exact sparse/hash counts,
no repeated block records, all row streams, scratch extent, query order, zero rows
and linearity. Force exhaustion in outer A, child A, child B and final B; each
rejects without changing input. Wrong shapes/limbs/columns reject before allocation.
All thirteen sizes and both address widths are calculated without generating maps.

The checker initially exposed a capacity mistake that treated operation counters
as address-sized buffers; the corrected rule keeps u64 counters separate and tests
a case whose hash count exceeds 2^32 while its 32-bit requested payload fits.
This is an algorithm/resource-contract study, not production NC, independent audit,
maximum-size execution, native parity or an encoder benchmark. A4 and
[native-code.md](native-code.md) separate native implementation/delivery from A1's
remaining source/parameter consumers; measured cost/memory gates remain necessary. A3/Q12 and all unsupported PCS parameters stay open.
