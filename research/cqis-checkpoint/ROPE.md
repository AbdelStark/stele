# Q26: certified rotary coefficients

Question: which exact frequency/scaling functions and canonical Q14 rounding
replace supplied rotation fixtures with reproducible public coefficients?
Security property: table/position/config identity; costs: preparation, public
MLE evaluation and c_a/T_misc. Kill criteria: an enclosure misses the target,
a rounded coefficient disagrees with an independent oracle, a frequency is
rounded before multiplying by position, or identity permits a changed variant.
Research for Draft RFC-0004 A7; [same-author review](../../agents/reviews/certified-rope-draft.md).

## Definition and sources

For rotary width r, pair j and absolute position t, start with f=theta^(-2j/r).
Base uses f, linear f/a. Llama3 uses f*(1/a+(1-1/a)*g), with
 g=clamp((L0*f/(2*pi)-lo)/(hi-lo),0,1).
The continuous expression equals the three wavelength regions in
[Meta's pinned reference](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/llama3/model.py#L45).
The base rotation/frequency construction is from
[RoFormer §3.2](https://arxiv.org/html/2104.09864v5#S3.SS2).
The target here uses exact real functions and Q14 nearest rounding; it does not
reproduce the reference implementation's floating-point arithmetic.

C=R(16384*cos(t*lambda)), S=R(16384*sin(t*lambda)), signed ties away. Theta and
scaling parameters are exact rationals, never implicit machine floats. Pairing
is adjacent or split as in the projected-attention study; the coefficients are
identical under layout changes but their consuming configuration identity differs.
Base/linear/llama3 are explicit families, not automatic length-selected modes.
Unspecified NTK/YaRN/other variants reject; all remain required where named by
E13-01. This study does not replace those tasks with a smaller supported set.

## Exact enclosure argument

`rope.py` imports only exact integer FLINT operations, Fraction arithmetic and
the existing rational arctangent enclosure. The independent test uses Arb real
balls; those real-arithmetic operations are confined to the research oracle.
For exponent p/q=2j/r and U=2^b, compute
k=floor_root_q(floor(U^q*theta_den^p/theta_num^p)). Check both integer-root
inequalities. Thus k/U<=f<=(k+1)/U; exact equality is retained when established.
No integer-root result is accepted without its defining inequalities.

Machin's pi identity with alternating arctangent bounds encloses the scaling
function. Positivity and monotonic clamping give lower/upper scaled frequencies,
even when an interval crosses a scaling boundary. Multiply by t before rounding.
Halve the angle interval until its upper endpoint is <=1/8 (at most 23 halvings).
At its midpoint, alternating Taylor sums enclose sine/cosine. Widen by the radius
using the derivative bound 1, then round endpoints outward to the b-bit grid.
Double with sin(2x)=2*sin(x)*cos(x), cos(2x)=2*cos(x)^2-1, outward integer interval
products and intersection with the proved [-1,1] range. This is not Q14 recurrence.

Try b=128,256,512 in fixed order. Return a coefficient only when rounding both
endpoints agrees; otherwise reject Precision. This proves each returned result,
not universal termination for every parameter. Each coefficient error is <=2^-15.
For int16 inputs, coefficient approximation contributes at most
(|x|+|y|)/32768<=2 integer units per rotated output, before its final rounding.
Full activation conversion and model fidelity are separate obligations.

## Candidate identity and resource limits

Descriptor = ASCII `stele/research/rope/v1` followed by NUL, then little-endian
`<HIBBI>`: width, position length, mode (base=0/linear=1/llama3=2), layout
(adjacent=0/split=1), original length. Append four `<QQ>` rational pairs in order
(theta,a,lo,hi), lowest terms, positive denominators. Total: tag length + 76 bytes.
Identity is BLAKE3 of this descriptor. Decode must re-encode identically; expected
configuration remains separate. Table bytes contain `<hh>` (C,S), position-major
then pair-major, with no implicit padding. A digest alone does not prove generation.

Widths are even 2..16384; lengths 1..2^20; rational fields have u64 numerators/
denominators and the A7 ranges. Root integer intermediates are bounded by
(512+64)*8192 bits. The frequency memo holds at most 3*8192 entries. Materializing
a table is capped at 2^16 pairs; individual positions still cover the entire
mathematical domain. Neither limit is a native profile or field certificate.
Generation is O(L*r) coefficient evaluations after frequency preparation; data is
2*L*r bytes, plus bounded arithmetic/memo state. Large-grid streaming, verifier
MLE evaluation and authenticated table reuse need explicit costs. No benchmark,
GPU parity, weight pass or native memory-performance claim is made.

## Evidence and recommendation

Run `uv run --locked --script research/cqis-checkpoint/check_rope.py`.
Seed 2629: 10,000 coefficient pairs agree with independent Arb log/exp/trig
intervals and enclose their tighter intervals; all use b=128. Corpus SHA-256:
`6ee6188be3a3789f85e1fad18ad5ebd81dfa32c97c1cf1e5dd6f622fecd5ad06`.
A separate narrow transition requires b=256; direct enclosure checks at all three
precisions request oracle precision at least b+256, rather than stopping once its
rounded value is unique. Maximum width/position and near-one
u64 rational bases pass. All three scaling regions are covered. A full 132-pair
table matches, every descriptor-byte mutation rejects, and altered coefficients,
certificates, aliases, scope, bounds and unsupported parameters reject. A populated
frequency cache must reject a Boolean alias of an integer key; typed memo keys
enforce this. Six
prefixes feed generated coefficients through the actual projected-attention API.

For theta=10000,r=4,j=1,t=100000, true frequency 1/100 gives (9214,13548).
Rounding that frequency to Q14 first gives (-6067,15219), a different function.
Oracle mechanics use the documented [Arb interval API](https://python-flint.readthedocs.io/en/latest/arb.html);
integer root checks are exact and independent of those transcendental routines.
No third-party prover is copied or imported. Canonical native FunctionId/registry,
public MLE/padding rules, full forward, actual source/lookup/PCS consumers, joint
ZK and fidelity remain open. Retain A7 as Draft; continue Q26 to native admission.
