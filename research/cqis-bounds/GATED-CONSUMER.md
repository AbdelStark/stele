# Consumed signed gated products — Q26 / Q31

Status: preimplementation research for RFC-0004 §3 / Draft A3/A8. E5-03 and
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
A=(u0,u0,u1,0), B=(v0,v1,v1,0), D=(0,u1,0,0), E=(0,v0,0,0).
Output magnitude has four actual byte planes Z. Consume three k=0 A3 relations:

1. ProductColumns: A*B+D*E+Cin-Z-256*Cout=0, dimension a+2, degree2.
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
