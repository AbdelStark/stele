# Signed byte-word source consumers — Q26 / Q31

Status: research for RFC-0004 A1 and Draft A3, using Accepted RFC-0006 A3
and RFC-0021 range_8. E5-03 remains blocked with its original criteria.
Revealing research roots do not admit production cuts or a private PCS/ZK.

Question, before implementation: can actual two's-complement byte-word sources
of width 8/16/32 bind an exact unsigned magnitude and canonical sign using
only consumed range and A3 proofs? The security property is signed source
faithfulness, including INT_MIN and zero. Symbolic terms are c_a, c_lu and
T_misc; no measured constant or inference weight pass changes.

Kill criterion: stop if a false sign, magnitude, byte range, carry or padded row
can pass; if INT_MIN can be labeled positive or zero negative; if a branch with
coefficient zero can hide an unconsumed source claim; or if static faithfulness,
complete challenge accounting or actual original-root consumption is absent.
Do not substitute a plaintext signed conversion check in the verifier.

Candidate: N=2^a rows, B=2^b bytes, bits=8B, H=2^(bits-1). Authenticate original
raw U and magnitude M from independently expected roots. Use actual wide-word
ranges U<=2^bits-1 and M<=H on real rows; padded rows have cap zero. A third
one-byte range proves a combined vector [sign S, high-seven-bit V], caps 1/127
on real rows and zero on padding. An auxiliary carry root fixes C1..CB with
public C0=0. N<=2048 keeps the combined range within its 4096-row capacity.

Consume six A3 identities in this order:

1. TopBit: U_top-128S-V=0 (a variables, degree 1).
2. Positive: (1-S)(U-M)=0 (a+b variables, degree 2).
3. Negative: S(U+M+Cin-256Cout)=0 (a+b variables, degree 2).
4. CarryBoolean: C(C-1)=0 (a+b variables, degree 2).
5. CarryInactive: (1-S)C=0 (a+b variables, degree 2).
6. Terminal: CB-S=0 (a variables, degree 1).

All byte/sign/carry views derive from the authenticated originals. Positive
rows have U=M<H and zero carries. Negative rows have U>=H and U+M=2^bits
by integer telescoping, hence M=2^bits-U. The top-bit identity excludes both
positive INT_MIN and negative zero. Each integer column has sides <=511,
strictly below p/2; the top-bit sides are <=255. No full int32 field embedding.

The six A3 records contribute (16a+12b)/|K| and 6a+4b draws of each A3 label.
Add the actual three range A3 losses to get (43a+26b+9)/|K|. Lookup dimensions
are a+b+1, a+b+1, a+2; each retains its own identity repetition and all reduction
terms. Every root and completed range state precedes the six A3 invocations.
No new label, challenge retry or division by a random expression is required.

Linear O(NB) witness/reduction work is the target; inherited full-reveal range
and A3 verifiers remain reference implementations. The source slots are canonical
u32 M31 encodings of byte values, not the physical packed model/checkpoint bytes.
Model ownership, virtual-source routing, signed operation composition, native
parity and joint private/FS security remain separate required work.

## Exact framing and consumers

Spec is (identity, source, magnitude, bits, count, repetitions), with identity
in [0,2^53), distinct u64 source/magnitude ids >=2, bits in {8,16,32}, count
in [1,2048], repetitions 1/2, and field degree 4/8. Reserve base=2^63+512*identity
through base+511, excluding external ids. Derive capacities before payloads.
The three wide-range ids are 8*identity+1/+2/+3, with sources source, magnitude,
base. Carry source is base+1. Raw/magnitude bytes are plane-major then row;
sign/high7 is two N-row families. Every source slot is a canonical u32 M31
element, authenticated by the existing kind0 full-vector Merkle consumer.

The signed context is `stele/research/q26/signed-source/v1\0`, followed by u8
version=1, degree, repetitions; u64 identity, source, magnitude; u8 bits; u32
count, all little-endian. Append four roots in raw/magnitude/sign/carry order,
then the three completed range states in raw/magnitude/sign order, each32 bytes.
The complete verifier consumes those actual ranges before the signed relations.

The six A3 invocation ids are 32*identity+24 through +29. TopBit views have ids
base+8 (top raw plane), +9 (sign), +10 (high7). Positive inputs are source,
magnitude, base+11 (broadcast sign); Negative inputs are base+11, source,
magnitude, base+12 (shifted incoming carries), base+1. CarryBoolean uses base+1;
CarryInactive uses base+11/+1; Terminal uses base+13 (last carry plane), base+9.
All are actual deterministic slices/broadcasts of authenticated arrays, with
public C0 zeros. No view is a new root or an unconsumed claimed evaluation.

The complete A3 consumer evaluates every final against its derived table at the
exact emitted point, including inactive branches. Each invocation retains all
three A3 loss records and its Final absorb, even at zero dimensions. There are
16 new claims, plus nine A3 and 2r lookup claims for each nested range. The
research object proof has ranges[3], sign_root, carry_root, carry and zero[6].
All shapes and canonical integer field limbs are checked during replay; neither
supplied sign metadata nor a decoded signed scalar can authorize acceptance.

## Soundness and costs

Condition on the three actual wide ranges and carry Booleanity. TopBit is an
integer equality because U_top and 128S+V lie in [0,255]. Thus S is exactly the
two's-complement high bit. If S=0, Positive gives equality of every byte, so
U=M<H; CarryInactive fixes every carry to zero. If S=1, Negative gives integer
byte identities U_j+M_j+C_j=256*C_{j+1}; both sides are <=511 and 2*511<p.
Sum them with weights 256^j, cancel interior carries, and use C0=0, CB=S to get
U+M=2^bits. Therefore M=2^bits-U in [1,H]. In particular U=0 cannot carry a
negative sign, and U=H has sign1 and magnitudeH. There is no int32/M31 alias.

With m=a+b, signed A3 loss is 2a+3m+3m+3m+3m+2a=16a+12b. Its own ZeroWeight
and Sumcheck draw counts are each 2a+4m. Nested A3 adds 2(9a+7b)+9(a+1), for
43a+26b+9 total numerator. Including all ranges, each A3 label has 18a+10b+4
draws. Lookup dimensions are m1=m2=a+b+1, m3=a+2. For each separately retain
[(2^mi+255)/|K|]^r and r[F(mi)+F(8)+3mi]/|K|, where F(k)=3k(k-1)/2+2k.
No reduction term is squared by r. The units are characteristic-safe ordinary
units: 2BN<=16384 for raw/magnitude, and 4N<=8192 for sign. There are no Unit
draws or new labels. Root binding, FS/H and joint private security remain added
obligations; this research composition does not admit either profile.

Witness construction, view derivation and the new folded A3 producer use O(NB)
work/storage. The inherited A3 full-table consumer enumerates equality values,
so its reference verification is O(NB log(NB)) plus nested range/lookup work.
No succinct verifier or measured prover throughput is claimed. Model byte
ownership/packing, source claim routing and private composition are unresolved.

## Evidence and recommendation

Tests were written before the implementation; the initial run failed for the
missing signed_source module. The independent integer corpus has seed2671,
10000 cases, 178872 byte cells, and checksum
`566f2d7897b5e934fe865ba9c42c4db79a5f6bdac1b8faf608b81f7d5d7ae286`.
It uses Python's signed byte codec as a separate representation oracle, covers
all supported widths, extrema, zero, positive/negative values and padded rows,
and checks every integer column, top bit, carry and endpoint. Capacity2048 is
checked separately; 2049 fails before inspecting the input.

The locked checker exercises 24 complete proofs across both fields, both lookup
repetitions, all widths and one/three real rows, including INT_MIN and zero.
It compares all loss records, labels, claims, dimensions and original consumers;
zero-dimensional signed proofs also match the naive A3 producer byte-for-byte.
The frozen complete proof-state checksum is
`1f13dcf0ecc3e56a4ecd7331f871a96f1cf3bde92d14840c2aac5076549e1bb2`.

Controls target roots, actual raw/magnitude/sign range sources, false magnitudes,
positive INT_MIN, negative zero, nonbit/fractional/inactive carries, padding,
coordinated TopBit/Terminal finals and both zero-coefficient branches. A proof
with U=M=128, S=0, V=128 satisfies every signed equation but its real high7
range rejects at Sign:TerminalCarry:RoundSumMismatch. Magnitude cap+1 similarly
rejects its real range terminal. These are research controls, not native NCs.

A pre-fix control changed a zero field limb to Python False without changing
its numeric value or encoded bytes; the complete verifier accepted it. The
shared research batching/A3 field predicate now requires integer limbs and
valid list/tuple shape. Both direct and nested range controls reject booleans.
The existing canonical corpus decoder already enforced integer limbs; native
code and canonical byte encodings are unchanged. Valid batching/A3 vectors
and complete signed proof states are checked for parity after the correction.

Continue Q26/Q31 with actual signed-operation composition and source routing.
Do not graduate these full-reveal proofs as a model/private proof or accept A3.
