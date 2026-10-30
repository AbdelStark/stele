# Consumed signed gated products — Q26 / Q31

Status: research for RFC-0004 §3 / Draft A3/A8. E5-03 and
original acceptance criteria remain blocked/open. Same-author skill review is
not independent audit; revealing research roots are not production cuts.

Question: can one batched byte-column consumer bind exact signed int16 factors
to the int32 product consumed by gated row conversion? Security properties:
integer faithfulness, both original factor bindings, canonical sign and zero.
Cost terms: c_a/c_sc/c_lu/T_misc. Kill criterion: a false product, wrong source,
unconsumed final or M31 alias passes; a bound uses actual values; or work loops
over independent row proofs instead of batching the element axis.

Use closed gated_product_bounds.Spec(dimension,up_fraction,silu_fraction).
Original dimension1..16384, fu0..30 and E0..14 remain unchanged; units are
exactly fu+E. This revealing adapter has N=2^a padded elements and N<=1024,
because its actual wide carry range has4N words and a4096-word capacity.
Expected roots are raw signed left16, right16 and output32. Three actual signed
source proofs own their raw/magnitude/sign arrays; one wide range owns C<=255.
No output magnitude cap is assumed: after integer multiplication it follows
that |output|<=2^30. SiLU membership and model/physical-source ownership remain
separate, mandatory consumers.

For two-byte magnitudes U=(u0,u1), V=(v0,v1), form four-plane views
A=(u0,u0,u1,0), B=(v0,v1,v1,0), D=(0,u1,0,0), F=(0,v0,0,0).
Output magnitude has four actual byte planes Z. Consume three k=0 A3 relations:

1. ProductColumns: A*B+D*F+Cin-Z-256*Cout=0, dimension a+2, degree2.
2. TerminalCarry: C4=0, dimension a, degree1; C0=0 is public.
3. SignTransfer: (Sleft+Sright-2*Sleft*Sright-Sout)*Z=0,
   dimension a+2, degree3, with signs broadcast across all four byte planes.

Actual input magnitude<=32768 gives top byte<=128. Together with C<=255,
column sides are<=65535<p/2. Every column therefore lifts
to integers; summing times256^j with C0=C4=0 yields U*V=|output|. The signs
are actual bits. Nonzero output has a nonzero byte, forcing XOR sign; zero has
the unique signed-source representation. No wide signed field equality or
plaintext product recomputation belongs in verification. Original padding is
zero and carries are forced zero by initial boundary and product columns.

Parent A3 numerator is9a+14 with3a+4 draws of each label and12 actual finals.
Full A3 numerator is147a+163, full draws each61a+64, with no A1. Ten lookup
dimensions are a+2,a+2,a+2 twice, then a+3,a+3,a+2, then a+3. Preserve each
[(2^m+255)/|K|]^r and r[F(m)+F(8)+3m]/|K| independently. Seven roots and four
verified child states precede all parent challenges. Binding, FS/H and private
composition remain additional; no new label/profile is admitted.

Namespace: identity<2^44 reserves base=2^63+2^18*identity. Expected raw ids
are distinct u64>=2 outside that span. Three magnitude roots use base+1..3,
carry base+4. Signed ids512*identity+1..3, carry range4096*identity+65,
parent invocations16384*identity+512..514, views base+16..25.
Prefix stele/research/q26/gated-consumer/v1 plus NUL; fixed context includes
field/repetitions, four u64 ids, u32 dimension and fu/E bytes.

Tests first: independent integer/NumPy corpus, all endpoint sign/zero pairs,
complete field/repetition matrix, exact accounting and all12 final consumers.
For x=-1,y=1, false output=-2^31, the magnitude difference is -p and signed
field equality holds. Fractional carries[8388608,32768,128,0] satisfy every
parent equation and sign. A forged carry source with range payload for zero
must reject SourceCopy. Also reject the in-domain alias x=y=-32768,
false output=-2^30+1, and a wrong sign with otherwise exact unsigned product.
Test source/root/capacity/schema/field/shape errors and naive A3 parity. Compose
one actual product root into each static/dynamic gated row-code consumer with
matching units; no weaker independent expected product may replace that root.

Preimplementation bound refinement: signed magnitude ranges imply high bytes
<=128 independently of product correctness. Successive honest carry bounds are
254,255,64,0 from coefficients65025,65280,16384,0. Thus a uniform actual
byte cap255 suffices; no packed two-byte carry is needed. This replaces the
initial conservative510 proposal before the prototype or tests are written.

## Actual consumers and integer argument

The four children are signed left16, right16, output32 and carry range, in
fixed order. The parent verifies every child against its expected raw or derived
magnitude/carry roots before its first challenge. Signed sources own canonical
zero and signs; no Boolean sign is accepted solely from a parent polynomial.
The four product views rearrange actual input bytes and insert exact zero planes.
The output magnitude is an actual four-plane source, including its high byte;
carry incoming/terminal views retain the same checked values. Every final uses
the actual MLE at its emitted point, including factors multiplied by zero.

The signed ranges establish each magnitude<=32768 independently of product
correctness. Hence the cross-column coefficient is<=2*255*128; adding actual
carry<=255 gives65535. The low/high/terminal columns have smaller static bounds.
The result side is<=255+256*255=65535. Thus every field equality lifts uniquely
to an integer equality. Telescoping with C0=C4=0 proves U*V=Z; the original
whole ranges then give Z<=2^30. Output sign follows from the cubic XOR relation
on each byte. At nonzero Z at least one byte is nonzero, so the sign is forced;
at zero the signed-source proof permits only canonical zero. This order avoids
using the derived product bound to justify its own field lift.

Exactly three batched A3 invocations cover all elements, with no per-element
proof loop. Context encodes version/field/repetitions, identity and three source
ids as little-endian u64, dimension as u32, then fu/E bytes. Expected dimensions
and fractions come from closed metadata; neither proof nor payload selects them.
All namespace/capacity checks precede payload access. New views use fully
revealed authenticated arrays; no new analytic public-MLE kind is introduced.

## Reproduction and limits

Run `uv run --locked --script research/cqis-bounds/check_gated_consumer.py`.
Tests first failed with the missing implementation module. Seed2678 covers10000
rows,261400 byte cells, every pair from{-32768,-32767,-1,0,1,32767}, and all
allowed fractions. Python integer and NumPy int64 multiplication agree; independent
NumPy convolution checks every column. An exhaustive32769-magnitude check confirms
the high-byte bound, and a complete1024-element endpoint witness checks capacity.
The largest observed carry is254, a correctness observation rather than a bound.
Corpus SHA-256:
`09304ad8f8a13e24a195620d4d7cc6c8f71a80e4d3277f2a0c7bdb771e8e5aa1`.
The16-case full-proof matrix checks both fields/repetitions, scalar/zero/ragged
endpoints, all ten lookup terms, full A3 losses/draws and twelve parent claims.
Frozen16-proof state SHA-256:
`8c555126eb17eb0bb7fd9f3e0c16c85f83c103d7be4202439193fb35e29864cb`.

Controls reject the isolated field-carry alias at Carry:SourceCopy:RoundSumMismatch,
the in-domain signed alias at ProductColumns:RoundSumMismatch, and an otherwise
exact product with opposite sign at SignTransfer:RoundSumMismatch. All parent
equations hold in the first attack. One-value raw/magnitude/sign/carry mutations,
genuine wrong-source proofs, equation-preserving final changes, zero factors,
malformed fields/roots/shapes and metadata/capacity errors also reject. Small
naive/folded A3 proofs agree exactly. Both row-code consumers accept the verified
product root and reject an independently valid proof of a substituted product.
These composition fixtures derive gated-row units as fu+E from expected metadata.

Witness/views/folded parent work is O(N), plus all nested range/lookup/hash
consumers in c_a/c_sc/c_lu/T_misc. No measured constant, benchmark, inference
weight-pass change, production NC credit or independent audit is claimed.
Recommendation: continue Q26/Q31 with actual SiLU membership, physical/model-owned
sources, native stacking/lowering, private PCS/ZK/FS and independent review.
The original16384-element schema and full inference criteria remain unchanged;
canonical-u32 research roots are not physical packed roots or production cuts.
