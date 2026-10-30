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
