# Q28 — Packing capacity and fused original-value openings

Question: which injective packing map and source-consumption reduction preserve
the committed integers and original B identity? Security: range/position/source
binding and field faithfulness. Cost terms: packed/padded message counts,
decomposition, c_c/T_misc and the full weight-pass schedule. Kill criterion:
any supported-value collision, alternate invalid decomposition or silent
identification of packed u with the original weight partial evaluation.

Run `python3 research/packing/check_packing.py` (standard library).
The [formal note](../../formal/packed-commitments.md) proves that the current
32-bit-to-M31 packing count is impossible by cardinality and gives concrete
int8/int16 collision pairs. Recombining (0,1) and (256,0) also demonstrates why
field equality without the real range consumer does not bind byte digits.

The candidate fixed codec stores 30 bits per M31 word, with two's-complement
source bits, little-endian bit order, separate rows, exact high-tail zeros and
zero padding to the selected code message length. An independent whole-byte
integer oracle agrees on 87,042 cases: every signed int8/int16 value, 10,000
rows per width crossing word boundaries, and all four-entry tuples over five
boundary values. Each case round-trips; re-encoding canonical data is checked.
Shape, width, source/word range and budget rejections pass, along with exactly
112 one-high-bit tail mutations and 120 one-word padding mutations.

The fused example uses two legal two-lane byte matrices and the tensor point
r=256/257 in M31. They have the same packed row evaluation and different first
original-lane evaluations. Their roots would differ, so this is not a Merkle
attack. It shows why a decoder or metadata assertion cannot equate packed u
with original B. Signed corrections and split lanes add further consumer work.

The codec uses O(T+C) work and a bounded bit accumulator; its message count
is ceil(T*w/30) before code padding. These are derived algorithmic quantities,
not benchmark observations. Thirty bits is a simple candidate, not an optimal
encoding or a measured improvement. The private decomposition/range/sign/
padding reduction, table identities, static certificates, ZK, source claims,
full memory and native fused read-count evidence remain unsupplied.

Recommendation: amend RFC-0010 through A6 with companion RFC-0007 A1/RFC-0008 A1;
keep them Draft until the complete consumer and one-pass schedule are specified.
Keep E4-03 blocked on A3/A6, retain every original packing/fused/negative-control
criterion, and continue the complete PCS/inference objective. No core protocol,
transcript/ledger, code identity, admitted format or measured constant changes.
