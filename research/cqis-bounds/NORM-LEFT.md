# RMSNorm left-factor product (Q26 / Q31)

Revealing research under Draft RFC-0004 A3 for RFC-0022 §§2.1,2.3,5's
left role. The question is whether the full row can bind q=t*L with a
positive configured-factor source, whole q<=32768 and every high output
byte checked, while retaining lookup dimension18. Costs are c_a/c_sc/c_lu/
T_misc. Kill this design if a zero product hides an original operand, a
source can be substituted, high result bytes are dropped or a supplied
factor range is mistaken for configured-branch authentication.

Consume whole ranges t<=2^44 and q<=32768, using their actual eight-plane
and two-plane roots. Range scalar L-1<=Lmax-1, then reconstruct positive
L and its exact eight-slot root from verified bytes. The factor bundle's
actual slice34:42 has this encoding. Its complete proof and same-exponent
authentication remain required; a scalar range alone does not identify L.
The product source and signed-output magnitude must also join actual proofs.

Derive the closed left-role certificate from expected metadata. Partition
C1..C8 into two four-plane families, with expected zero caps for padded rows,
terminal carries and unused columns. Include only families with a nonzero
static cap, retaining their reserved ids otherwise. At maximum Lmax65536,
caps are0,254,509,510,510,510,272,17,0. Each active family uses at most
two byte planes over4N words, fitting131072 bytes. For Lmax1 all carries
are public zero. The full static certificate's maximum column side is130815,
with twice that below p. Bounds never depend on observed witnesses.

One degree-two A3 over8N entries uses three shifted t-byte views and three
scalar L-byte views, followed by Cin, q and Cout. It proves the convolution
t_k*L0+t_(k-1)*L1+t_(k-2)*L2+Cin=q_k+256*Cout. Missing input digits
are public zero. The q source is zero-extended from two to eight planes;
all high planes remain in the relation. Each of the nine original views
has an independent consumer at its emitted point. Padded t/q/carries are
zero, so broadcasting scalar L preserves padded equations. C0 and the closed
terminal/unused carries remain zero. No supplied selector or certificate
is accepted. Faithful columns plus whole bounds establish q=t*L in integers.

Namespace: identity<2^44, base=2^63+2^18*identity. Fixed range roles use
4096*identity+1..5 for t, q, offset and two carry families. Product and
quotient sources are external; offset/carries use base+1..3. Parent A3 id
is16384*identity+512, with original views base+16..24. Three distinct
external ids stay outside the whole parent span. Complete expected norm
bytes, all external/auxiliary roots and verified child states precede parent
weights/rounds/finals. Reconstructing the factor adds no challenge.

Account before implementation: let a=log2N, bl be the offset byte-width
exponent, g count active carry families and bg their width exponents.
Total A3 numerator is(21+9g)*a+37+7bl+18g+7*sum(bg); each nonlookup
label has(9+4g)*a+15+3bl+8g+3*sum(bg) draws. Lookup dimensions are
a+4, a+2, bl+1 and a+bg+3 per carry family. Retain each separate identity
((2^m+255)/|K|)^r and reduction r*[F(m)+F(8)+3m]/|K|,
F(m)=3m(m-1)/2+2m. At full a14/bl1/g2/bg1,1, A3=640 and each
nonlookup label has278 draws, with dimensions18,16,2,18,18. Static checks
cover all17 Lmax exponents: exponents1..8 use one-byte carries;9..16 use
two-byte carries. Runtime receipts must agree, including the no-carry case.

Tests first:10000 independent NumPy int64 products/convolutions, all static
width transitions, ragged rows and exact receipts across both fields and
repetition counts. Whole t*L fits int64 even when q would overflow, so the
producer corpus must cover those large products separately from valid q
proofs. Forge fresh false q, field aliases, carry endpoints and high q bytes.
Retain original factor claims at zero t, source substitution and actual
product/signed-output/factor composition. A full16384-row maximum proof is
required before publication. At L=65536, q<=32768 forces t=q=0; this is an
essential honest boundary, not permission to omit any operand consumer.

Continue Q26/Q31. Selecting e<0, forcing unused qd/r to zero, the right
branch and signed output remain wrapper obligations. Native/model/private
inference, fidelity and original task criteria remain open. No Accepted
cut, native control credit or performance measurement is claimed.
