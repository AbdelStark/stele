# Capped scalar range consumers — Q26 / Q31

Status: research for Draft RFC-0004 A3, RFC-0008 A2 and RFC-0012 A8,
reusing Accepted RFC-0006 A3 zerocheck and RFC-0021 range_8 semantics.
E5-03 remains blocked with its original criteria. This is a revealing research
adapter, not private PCS/ZK, native plan admission or an inference proof.

Question: can exact static caps on canonical M31 source values be enforced by
actual byte lookups and consumed zerocheck claims, instead of a plaintext range
comparison? Security properties are original-source reconstruction, nonnegative
bounded complement, carry Booleanity and final carry. Costs are c_a/c_lu/T_misc;
no performance measurement or inference weight-pass change is proposed.

Kill criterion, stated before implementation: drop the construction if a range
claim can be discharged against different source bytes, an x+p decomposition
can pass, nonboolean carries or a nonzero terminal carry can evade rejection,
any generated claim remains unconsumed, or the actual challenge accounting differs
from its descriptors. Do not replace the existing lookup protocol with a verifier
membership scan. Retain all Q31 pole, multiplicity, table and source consumers.

The candidate uses per-row verifier-owned caps in [0,p-1], a canonical M31 source
vector and four little-endian byte planes each for the source and its complement.
One range_8 lookup covers all eight planes. Four no-skip zerochecks enforce source
reconstruction, byte-column addition to the static cap, carry Booleanity and zero
terminal carry. Padding rows have expected cap zero and are subject to every check.
The byte-column sides are at most 511 once bytes and carries are enforced, so
field equality is integer equality. The terminal condition gives word+slack=cap;
cap<p then excludes x+p aliases in source reconstruction.

The existing revealing Merkle lookup adapter binds original byte and multiplicity
vectors. A separate fixed source root and carry root close the zerocheck views
by full-vector openings and exact MLE evaluation. These research commitments do
not add a production cut or choose an admitted intermediate commitment format.
Private/virtual source consumers and joint masking remain mandatory.

For a row dimension a, the lookup has m=b=a+3, one column and 256 table rows.
Its existing identity and reduction losses remain unchanged. The four zerochecks
have (dimension,degree) (a,1),(a+2,1),(a+2,2),(a,1), totaling (9a+10)/|K|.
They add 4a+4 ZeroWeight and 4a+4 Sumcheck draws, with no skip draw. Bind the
expected statement, all relevant roots and the completed lookup state before the
zerocheck transcript. This is conditional interactive accounting; hash binding,
FS/H, profile admission and private source composition remain unresolved.

## Exact statement, layouts and consumers

The verifier supplies Spec(identity, source, caps, repetitions) and the original
source root, with field degree 4 or 8. Identity is in [0,2^56), source is a u64
at least two, repetitions is 1 or 2, and caps is an ordered nonempty tuple of at
most 4096 canonical M31 integers. Let a=ceil(log2(len(caps))) and N=2^a. Pad caps
with zeros. The original source commits N canonical M31 values, including padding.
No supplied cap, dimension, source id, selector or table chooses this statement.

Reserve base=2^63+64*identity through base+63 for this research invocation; the
original source id must lie outside that interval. Byte, carry and multiplicity
ids are base, base+1 and base+2+j. Derived view ids are base+8..11, base+16..19
and base+21. They are virtual views consumed against the same opened originals,
not additional commitments. Zerocheck invocation ids are 4*identity+j for j=0..3.
The existing Q31 lookup has its own scoped invocation/leaf ids.

The byte vector has eight planes, each N entries: four source-word planes then
four complement planes, least significant byte first. The carry vector has four
N-entry planes C1..C4. C0 is identically zero. Every entry is a canonical M31 field
value before lookup/Booleanity enforcement; the verifier does not pre-scan the
bytes for membership or assume that supplied carries are bits. The original-word
root, byte root and carry root use RFC-0012 A3 kind-0 trees with count N/8N/4N,
width four and canonical little-endian u32 payloads. Full reveals are deliberate.

The public range table is regenerated from the existing RFC-0021 range_8
descriptor, not proof data. The lookup statement has all 8N selectors equal to
one. The entire 8N-entry plane-major vector is one unit. Its static count is at
most 32768, below char(K), so no preliminary unit challenge is needed. The
existing Q31 producer/verifier handles all multiplicities, poles, table leaves,
both fraction trees, selected-product source claims and complete root openings.

After that lookup, initialize the zerocheck transcript with the research domain,
u8 version=1, u8 field degree, u8 repetitions, u64 identity, u64 source, u32 real
cap count, ordered u32 caps, and the exact TableId. Append the expected source
root, byte root, carry root and completed lookup transcript state, all 32 bytes.
All integer fields are little-endian. This is the complete research context, not
a new registered transcript label, native wire encoding or production statement.

Four k=0 A3 relations run in fixed order:

| Relation | Inputs | Polynomial |
|---|---|---|
| Reconstruction | original X and four source-byte planes | X - sum(256^j A_j) |
| CapRelation | A, B, shifted carry-in, carry-out, public cap digits | A+B+Cin-256 Cout-capdigit |
| CarryBoolean | original carry vector | C(C-1) |
| TerminalCarry | final carry plane | C4 |

Reconstruction and TerminalCarry have dimension a; the others have dimension
a+2. Each relation consumes every returned MLE claim at the actual derived point
against the root-bound original or exact public/virtual view. There are twelve
zerocheck claims and two lookup claims per repetition. No receipt alone accepts.
Every ZeroFinal is absorbed before the next relation starts. Scalar a=0 keeps
the reconstruction and terminal checks even though they draw no challenges.

## Integer argument, costs and limits

Lookup membership gives A_j,B_j in [0,255]; CarryBoolean gives each Cj in {0,1}.
Each column's nonnegative sides are at most 511, and 2*511<p. Thus its field
equality is the same integer equality. Telescoping with C0=C4=0 proves
W+S=cap with W,S nonnegative. Therefore W<=cap<p. Reconstruction defines the
source field value as W; because both the canonical source representative and W
are below p, they are equal. Reconstruction is a field-embedding relation, not
an assumption that an unbounded 32-bit integer identity is faithful in M31.
No signed interpretation or arbitrary 160-bit source is admitted by this scalar
consumer. Wider integers still require their complete word/limb source contract.

The folded no-skip producer uses the unchanged A3 schedule and compares complete
proof objects against the naive oracle on both-field scalar-row fixtures. Exact
MLE consumption is linear in the revealed vectors per point; metadata, roots,
field conversion, folds, table work and transcript operations are additional.
Original payloads contain N words, 8N bytes and 4N carries, plus the Q31
multiplicities and proof messages. The representation deliberately reveals all
of them. The original model is not loaded or changed by this study. There is no
private commitment, succinct verifier, native full proof, benchmark or RSS claim.

## Evidence and recommendation

Run `uv run --locked --script research/cqis-bounds/check_capped_range.py`.
The tests failed with missing capped_range before implementation. Seed2667 checks
10000 witness configurations and 119375 padded rows against direct integer
reconstruction/addition, checksum
`67692ccccdf631b46af21c1f1725e659fb8dc2b68bad2a4dbdc26f5911a3876a`.
The 4096-row resource boundary is checked separately without claiming a complete
maximum-size proof. Sixteen complete proofs cover both fields, both repetition
counts, scalar and ragged layouts, zero caps, byte boundaries and cap p-1; final
states and exact phase records are checked for each invocation.
The final ordinary-unit state checksum is
`823a52e835b9c7bbf2aad50a590a422b6d1950723886d91a963a83e0c3a9a4a3`.
All claims, phase records, total loss numerators and draw counts are checked.

Controls produce actual proofs over false data. A coherent x+p decomposition
with wrapped complement passes reconstruction/columns/Booleanity but fails
TerminalCarry. Field-valued carries hiding p pass the other integer-looking
relations but fail CarryBoolean. Invalid selected bytes have honest fraction-tree
arithmetic yet fail the lookup root equation. Wrong original source values fail
Reconstruction. Altered full openings fail CommitmentMismatch. Two coordinated
scalar finals preserve the reconstruction equation but fail ClaimMismatch against
the original vectors. Static cap substitution, source-id substitution, malformed
proof shapes, noncanonical fields and resource bounds have separate controls.
Research checks earn no production NC credit.

The column adapter derives coordinate caps solely from the existing limb Spec
and returns fixed left/right/result/carry coordinates in that order. It rejects
more than 4096 coordinates before inspecting supplied witness payloads, checks
exact shapes/canonical fields and never tightens a cap from observed data. Two
additional complete proofs consume actual byte/nibble limb-column values in
QM31/OM31, including coordinates of a 159-bit source. This proves those scalar
coordinate ranges, not that wide source's reconstruction or the multiplication
columns themselves. Zeroing all witness values leaves every static cap unchanged.
The adapter's tests first failed on its absent function before implementation.

Continue Q26/Q31 by deriving these caps from actual model columns and connecting
the scalar inputs to their real producing reductions/PCS. Signed offsets, wide
word reconstruction, branch selectors, range dominance, native plan/codec and
joint private masking remain mandatory. This does not admit the revealing
auxiliary commitments into Stele or complete E3-07/E5-03/E6 range discipline.

The initial candidate used b=3. The static 4096-row capacity proves that all
8N selected bytes fit one characteristic-safe unit, so the final candidate uses
b=m. This removes r*a preliminary Unit draws and the a/|K| contribution inside
the identity term. These are symbolic work/security changes, not measured speed.
Every lookup/root/consumer check remains. Larger unadmitted inputs cannot inherit
this ordinary-unit bound; their complete layout/count contract must be derived.
