# Candidate lossless packing and its PCS obligations (Q28)

Status: Draft, RFC-0010 A6 / RFC-0007 A1 / RFC-0008 A1. Question: which injective
packing map and authenticated decomposition preserve integer values and the fused
weight opening? Security properties: source identity, range and field faithfulness.
Cost terms: message/encoded sizes, decomposition, row work and weight passes.
Kill criterion: a collision among supported source values, a noncanonical alternate
decomposition, or a claim that packed and original row vectors are the same.
This note proposes a codec and identifies the missing proof consumer. It does
not enable a commitment format, admit a profile or complete E4-03/E4-04.

## 1. The existing 32-bit-to-M31 statement is impossible

Four unrestricted int8 values and two unrestricted int16 values each have 2^32
possible tuples. M31 has p=2^31-1 elements. No function from all those tuples to
one M31 element is injective. This does not depend on signed representation.

For little-endian two's-complement bytes, (0,0,0,0) and (-1,-1,-1,127) are valid
int8 tuples with packed unsigned integers 0 and p. Reducing modulo p maps both
to zero. Likewise int16 tuples (0,0) and (-1,32767) collide. Rejecting the second
tuple as a noncanonical field word instead excludes a valid source value; it
does not implement the stated unrestricted format. Byte storage and field-message
packing must be distinguished explicitly in RFC-0010 §8 and RFC-0007 §3.

An independent range issue survives even for a legal short word: base-256 digit
pairs (0,1) and (256,0) both recombine to integer 256. The latter is not a byte
decomposition. A field equality without the actual digit-range consumer cannot
discharge NC-0603. Nor can a prover-supplied assertion that a source was int8.

## 2. Candidate fixed 30-bit row codec

For a logical row of T>=1 signed w-bit values, w in {8,16}, use the exact w-bit
two's-complement representation u_t in [0,2^w). Concatenate their bits in logical
row order, least-significant bit first inside each value. Never cross row boundaries.
Partition this bit stream into consecutive 30-bit words. The final short word is
zero-extended in its high bits. Thus S=ceil(T*w/30) words suffice, each in
[0,2^30), strictly below p/2. Pad with exactly C-S zero words to the selected
supported code's message length C>=S. No modular reduction, saturation, optional
endian convention or value-dependent output length is permitted.

The authenticated layout must fix T,w,C, row order, logical tensor-axis mapping,
format version and every padding rule. They are not recoverable from a root or
an encoded word alone. An empty logical row is unsupported in this candidate;
scalar tensors still have one logical value. C comes from the validated code
identity. The prototype permits power-of-two C only; native support must match
the actual code factory, not this shape condition alone.

Decoding checks the exact C-word length, each word's 30-bit range, zero high bits
after bit T*w and all C-S zero suffix words before returning exactly T signed
values. A signed value is u_t minus 2^w when its sign bit is one. Unknown widths,
invalid source ranges, truncated/extra words, nonzero tail/padding or resource
overflow reject. Resource budgets can reject a request, never change its layout.

Injectivity follows without a probabilistic assumption: each admitted word has
a unique 30-bit expansion; removing only the prescribed zero suffix recovers
exactly T*w bits; splitting into w-bit values and signed decoding are bijections.
Re-encoding a canonical word sequence returns that same sequence. Bounds and
word count depend only on the public shape/format, never observed values.

A streaming codec uses a bounded bit accumulator (at most 45 occupied bits for
w<=16), O(T+C) work and O(1) scratch beyond caller input and output. The prototype
is checked against a separate whole-byte-integer construction. Those are codec
properties, not actual native allocation or proof-performance measurements.

Thirty bits is a simple fixed-width candidate, not an optimality claim. A full
31-bit rectangular domain also fails: its all-one value equals p. More elaborate
base-p/escape formats require their own canonical fixed-shape, privacy, cost and
consumer proofs. The current proposal avoids that exceptional input entirely.

## 3. Packing changes the fused functional

Even a valid injective integer codec is not an isomorphism of arbitrary K-linear
functionals. Consider two rows, two nonnegative byte lanes and their legal packed
word P=x_0+256*x_1. Let r=256/257 in M31 and a=(1-r,r). For source matrices

`M_A=((0,1),(0,0))` and `M_B=((0,0),(1,0))`,

the packed row vectors are (256,0) and (0,1). Both have the same packed opening
u_P=256/257. Their original first-lane values a^T M[:,0] are 0 and 256/257.
Thus u_P alone cannot determine the original functional. The two source roots
would differ; this example is not a Merkle collision or a complete PCS forgery.
It disproves an unqualified identification of packed u_P with the original B.

In this nonnegative case u_P=B_0+256*B_1, rather than B itself. Signed values add
their two's-complement sign correction, and 30-bit boundaries may split a lane.
No extension-field digit extraction or range claim on the challenge-dependent
u_P follows from the original integers being small. A field-MLE value need not
be an integer in the original digit range. An arbitrary original column functional
b is not generally a multiple of the packing-weight vector.

Consequently a packed commitment requires an explicit reduction connecting each
original lane claim to its packed source, with range, sign, fragment, position and
padding checks. Alternatively, one field message element per original value
preserves the existing linear B identity while raw source storage can remain
int8/int16 bytes; that is a different commitment layout and cost. Neither option
is silently selected or credited here. The full requested packing and one-pass
requirements must be reconciled by an Accepted plan, not bypassed by the codec.

## 4. Required authenticated consumer and cost evidence

For the 30-bit candidate, each word can be decomposed into two range-15 parts
L,H with P=L+2^15*H. This identity has static bound 2^30-1<p/2. Further fragments
reconstruct each w-bit unsigned lane, and its sign relation gives the signed
value. Every fragment needs its exact range and position; the range-table registry,
decomposition reduction and plan's dominating-check rule must cover them. It is
not enough to check only that decoded honest inputs fit. Final tail bits and
message padding have their own zero obligations. All newly introduced integer
identities need verifier-recomputed RFC-0004 bound certificates.

The consumer must bind the complete original/packed layouts and source identities,
route every emitted claim to its actual reduction/PCS consumer, and enforce all
decompositions against that same committed source. A local encode/decode check
on revealed values is not a zero-knowledge proof of a private decomposition.
NC-0603 must change one source digit while retaining the same recombination and
be rejected by the real range/claim consumer. Fused tests must detect replacing
original B by packed u_P, retain the actual source object and count the complete
weight reads; algebraic research examples earn no such credit.

Charge R*C message symbols and R*N encoded symbols, not the impossible original
four-byte-per-M31 ratio. Before power-of-two padding the candidate uses
ceil(T*w/30) symbols per row; padded C can materially increase that count. Count
raw source bytes, packed words, decomposition state, caller buffers, encoding,
Merkle, opening and all copies/overlaps. Weight registration and per-proof cut
work have different lifetimes. A one-pass fused implementation must accumulate
every necessary authenticated functional during its actual single source visit;
no additional original-weight pass is authorized by this research.

Q28 remains open until the consumer/claim schedule, canonical formats, static
certificates, ZK and complete native costs are specified and tested. No new
challenge, soundness term, transcript label, committed intermediate or measured
constant is introduced here. E4-03, E4-04 and downstream inference remain unfinished.
