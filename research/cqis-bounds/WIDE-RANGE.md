# Exact wide-word ranges — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8;
reuse Accepted RFC-0006 A3 and RFC-0021 range_8. E5-03 remains blocked
with its original criteria. Full reveals are not private PCS/ZK or an admitted
inference commitment format.

Question: can an exact unsigned cap below 2^160 be enforced on an original
byte-word source through real lookup and consumed zerocheck claims? Coordinate
caps are insufficient: cap 257 gives byte caps (255,1), which also permit 511.
The security properties are original-source equality, byte membership, bounded
column addition and zero carry endpoints. Cost terms are c_a/c_lu/T_misc;
there is no proposed measured constant or inference weight-pass change.

Kill criterion, stated before implementation: stop if a cap violation, different
original source, nonbit carry, nonzero final carry or nonbyte can pass; if any
claim lacks an actual consumer; or if the complete draw/phase accounting differs
from the descriptors. Do not use a verifier plaintext whole-word range scan.

Candidate: verifier-owned caps determine a power-of-two byte-plane count B<=32
and padded row count N<=65536, subject to B*N<=131072. The
[capacity continuation](RANGE-CAPACITY.md) records the expanded narrow-word
domain and its validation. An expected source root binds B*N canonical M31
entries, interpreted as byte planes only after equality to the range-proven
lookup source. The lookup covers both the word and its nonnegative complement,
2*B*N selected bytes, strictly fewer than p. Four k=0 A3 relations enforce
SourceCopy, byte-column addition to the cap, carry Booleanity and zero final
carry. Initial carry is the zero public view. All padded rows have cap zero;
all high byte planes remain checked. No whole-word integer is embedded in F_p.

Each column's nonnegative sides are at most 511 after byte/bit enforcement,
so 2*511<p gives integer faithfulness. Telescoping the column equalities with
zero endpoints yields W+S=cap over integers and hence W<=cap. Every A3 claim
uses the actual opened source or exact public/virtual view. The research roots
reveal originals, lookup bytes, carries and multiplicities; they add no production
cut. Connecting that byte-word source to the real numerical operand, signed
representations, nibble packing, multiplication relations and joint privacy remain
separate mandatory obligations.

Let a=log2(N), b=log2(B), m=a+b+1. Lookup uses one ordinary characteristic-safe
unit with its existing identity term (2*B*N+255)/|K| raised to r and separate
reduction r*[F(m)+F(8)+3m]/|K|, F(n)=3n(n-1)/2+2n. The four A3 relations
have (dimension,degree) (a+b,1),(a+b,1),(a+b,2),(a,1), adding
(9a+7b)/|K|, not squared. They draw 4a+3b weights and 4a+3b tails, with
no skip draw. Nine A3 claims and 2r lookup claims must be consumed.
Binding, FS/H, private source composition and joint ZK remain additional.

## Statement, layouts and actual consumers

The verifier supplies Spec(identity,source,caps,repetitions), field degree 4 or 8,
and an independently expected original source root. Identity is an integer in
[0,2^56), source is a u64 >=2, repetitions is 1 or 2, and caps is a nonempty
tuple of at most65536 integers in [0,2^160), with padded B*N<=131072.
No proof field selects these values.
Let N=nextpow2(len(caps)); let B=nextpow2(max(1,ceil(bitlength(max(caps))/8))).
Both are at least one. The byte-plane count B is fixed by caps, never the witness.
Pad caps with zeros to N. Even a 160-bit cap uses 32 byte planes, with all twelve
extra high planes checked. These are deliberate zero extensions, not free cells.

Reserve base=2^63+64*identity through base+63; source must be outside that span.
Original, lookup and carry trees have ids source, base, base+1, counts BN,2BN,BN,
kind zero and width four, with canonical little-endian u32 field entries. Q31
multiplicity trees use base+2+j and its unchanged extension-field format. Source
bytes use plane-major order, least significant byte first, N rows per plane.
The lookup vector concatenates all B source planes then B complement planes.
Carry planes are C1..CB; C0 is the zero public view. The verifier checks only
canonical field encodings before arithmetic, not that supplied bytes/bits are in
range. The real range_8 lookup and CarryBoolean establish those memberships.

Regenerate the exact RFC-0021 range_8 table and TableId. Select every one of the
2BN entries, including padded rows. This closed standalone research statement
proves zero padding instead of applying an assumed model validity selector.
The unchanged Q31 verifier checks both fraction trees, nonzero roots, the lookup
identity and all source/multiplicity claims against complete Merkle openings.
There is no verifier membership scan, challenge retry or weakened lookup mode.

The A3 public context is the exact domain `stele/research/q26/wide-range/v1\0`,
u8 version=1, u8 degree, u8 repetitions, u64 identity, u64 source, u32 real cap
count, each ordered cap in 20 bytes, and the exact TableId. Integers are little
endian. Append the expected source root, lookup-byte root, carry root and complete
lookup transcript state, all 32 bytes. This distinct research context is not a
registered production label, plan encoding or proof format.

Four A3 invocations run with ids 4*identity+j, j=0..3, always k=0:

| Relation | Dimension | Inputs and polynomial |
|---|---|---|
| SourceCopy | a+b | Original byte-word X and lookup first-half A: X-A |
| CapRelation | a+b | A+B+Cin-256 Cout-capdigit |
| CarryBoolean | a+b | C(C-1) |
| TerminalCarry | a | CB |

The input ids are (source,base+8), (base+8,base+17,base+18,base+1,base+19),
(base+1), (base+21), in that order. Derived ids denote exact slices, shifted
carry or cap-digit views of authenticated originals/public data, not commitments.
Their shapes and source slices are rebuilt from Spec. Every final value is
absorbed and every one of the nine claims is evaluated at the exact returned
point against those vectors. Even B=N=1 retains all four zero-dimensional
relations and all twelve phase records, with no random draws or algebraic loss.

The proof is conditional on the range_8 and A3 relations holding and original
binding. SourceCopy identifies each original field entry with its byte-valued
lookup counterpart, hence fixes the integer byte representation. With byte and
bit membership, both sides of each addition column lie in [0,511]. Their field
equality is therefore an integer equality. Multiplying column j by 256^j and
summing cancels all interior carries; C0=CB=0 leaves W+S=cap. Nonnegative S
implies W<=cap, and zero caps also force padded word/complement bytes to zero.
The argument remains valid for W above p and for high zero-extension planes.
It never treats the whole-word equality as faithful in one base-field element.

## Evidence, costs and next obligations

Run `uv run --locked --script research/cqis-bounds/check_wide_range.py`.
The control script first failed because wide_range did not exist. Seed2668
checks 10000 configurations across 0..160-bit caps, 971914 byte cells, with
independent exact reconstruction and column equations. Frozen witness checksum:
`c3b0e63ec3fd2ae6d773636f7f60d4afa225e3a6ecb0d75ba1fa39c2ed3c205d`.
The 4096-row, 32-plane boundary is a metadata/witness test, not a maximum proof.
Twenty full proofs cover both fields/repetition counts, zero/255/257 caps,
ragged rows, multi-byte and 160-bit caps. All nine A3 and 2r lookup claims,
ordered phase records, loss numerators and challenge counts are checked.
Frozen final-state checksum:
`5899ef889669e2af476aaf025b21f8fa46fbda65121a5b8ab45b665f2b9c3eba`.
Folded A3 proof objects equal the naive reference on zero/one-dimensional cases
in both fields and repetition counts. Shared lookup, Merkle and field engines
are disclosed; these are not independently implemented private-prover tests.

Controls cover the 511-under-257 counterexample and a nonzero byte above the
160-bit cap width. Wrapped complements satisfy all column and bit relations
but fail TerminalCarry. Field-valued nonbit carries can hide a multiple of p
with endpoint zero, but fail CarryBoolean. Wrong original bytes fail SourceCopy;
coordinated finals that preserve its equation fail actual ClaimMismatch. Changed
expected caps also fail the real public consumer. One-value original/carry/lookup
opening mutations fail CommitmentMismatch. A root-bound selected byte p-1 has
valid field column arithmetic but fails the actual lookup RootMismatch. Padded
row corruption, malformed proof lengths, noncanonical fields, invalid expected
specifications, id collision and capacity boundaries have separate controls.
No research control earns native NC credit.

The dense folded reductions and exact per-claim MLE consumers cost O(BN) field
work for these fixed degrees/input counts, plus Q31 table/multiplicity/tree work,
metadata, hashing and transcript operations. Full reveals include BN original
fields, 2BN lookup fields and BN carry fields, plus multiplicities/messages.
This deliberately duplicates original bytes in the lookup representation to
make the source equality an explicit consumed relation. It is not a proposed
private or succinct commitment design, performance measurement or memory claim.
The c_a/c_lu/T_misc terms gain these symbolic costs; no fitted constant, actual
model tensor, checkpoint output, native crate or inference weight pass changes.

The final cost audit replaced the shared folded producer's per-row equality
evaluation with MSB-first table expansion. For a suffix of length k, expansion
uses 2*(2^k-1) field multiplications and k subtractions, including k=0 and
zero/one coordinates, with no inverses. Summed across m tail rounds this is
O(2^m) instead of O(m*2^m) equality work; relation/folding work remains linear
for these fixed degrees. This changes symbolic c_a/T_misc work only, with no
measured speed claim. A tests-first comparison checks 3066 exact values against
the independent per-point equation in both fields, dimensions 0..8 and zero/one
and random extension coordinates. Scalar and wide proof states remain frozen.

Recommendation: continue Q26/Q31 with actual source-to-numerical-operand consumers,
including signed offsets, byte/nibble layout links and the multiplication columns.
The original root here names an unsigned byte word; it is not automatically the
same object as a scalar, signed operand, packed checkpoint or arbitrary limb
vector. Full model range dominance, canonical plan/codec, native parity, complete
private PCS/ZK/FS and fidelity remain required. Draft evidence cannot admit a
production auxiliary root or complete E5-03/E3-07 by itself.
