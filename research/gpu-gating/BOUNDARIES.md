# Field and byte boundaries (E16-40n)

The remaining research copy/source kernels must satisfy GPU-parity guardrail 4:
field outputs leave each kernel canonical even when inputs use lazy limbs in
`[0,2p)`. Hash inputs that represent arbitrary bytes retain all their bits. This
is a representation correction under RFC-0003 and RFC-0014, not a new protocol.

| Kernel | Boundary and reference |
|---|---|
| `mask_kernel` | M31 block selection; production `mask_table`, including reversed coordinate order and an empty coordinate list |
| `tile_kernel`, `dup_kernel` | QM31 repetition; both halves of the in-place duplicate are canonical |
| `eq_kernel` | QM31 equality table and scale; existing CPU `Source::Eq`, including zero variables |
| `transpose_kernel` | M31 row-to-symbol permutation; partial tiles, rows and columns crossing 32 |
| `bitrev_kernel` | M31 symbol permutation; swapped pairs, fixed points and the zero-variable identity |
| `level_kernel`, `scale_kernel` | M31 Circle butterflies/scaling; CPU source arithmetic with canonical and raw twiddles |
| `leaf_kernel` | Canonical field serialization, then BLAKE3 over descriptor, index, presence, salt and column; production `MaskStream` and `blake3_digest` |
| `node_kernel` | BLAKE3 over arbitrary child digest bytes; production hash reference, including words equal to `p` and `u32::MAX` |

The pre-fix actual-expression host test rejected all 1,000 raw cases for each of
mask copy, duplicate, transpose, bit reversal and leaf serialization. Their
canonical counterparts passed. The fix normalizes only field words. Hash
compression, keys, salts, descriptors and digest words retain their byte semantics.
Bit reversal also handles its zero-variable shift without shifting by 64.

The corpus uses 1,000 deterministic seeds per operation, with canonical and raw
representations. Field edges include 0, 1, p-1, p, p+1 and 2p-1. Copy domains cross
thread/block and transpose-tile boundaries; source leaves exercise the 1,024- and
2,048-byte BLAKE3 chunk boundaries. The host probe executes the actual CUDA bodies
as C++, with a serial grid. It emulates transpose's shared tile in two passes:
first fill all cells, then repeat identical input reads before the output writes.
This checks expressions and indexing; it cannot establish CUDA scheduling parity.
The explicitly ignored H100 test runs the same corpus using actual kernels and
fails without H100. The existing complete source-material device test additionally
compares every payload/path with production preparation over its original corpus.

## Work and qualification

The duplicate kernel now writes the original half as well as its copied half:
16 additional bytes per QM31 entry in the original half. Normalization adds no
other global reads or writes to the affected kernels. No measured speedup follows;
future costs in `c_sc`, `c_c` and `T_misc` must include these operations. Hash bytes
must never be reduced modulo p to save work or force field-looking outputs.

Budget: one reviewed implementation and one bounded H100 campaign after the
preceding GKR qualification. Hardware, current-main/intended-merge-tree gates and
independent reviews are pending. CPU expression tests and research observer runs
supply no integrated GPU-proof, complete-memory, performance or ADR-127 GO credit.
