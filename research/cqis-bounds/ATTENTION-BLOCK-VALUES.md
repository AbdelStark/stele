# Complete restored attention block

Q26/Q31, E5-03; Draft RFC-0004 A3/A6 and RFC-0009 A2. Before code: can one
consumer bind restoration and the zero-scale rule for all 1024x16384 signed
codes, using complete source consumers and one A1 over rows? Costs are
c_a/c_x/c_sc/c_lu/T_misc and temporary storage. Kill the design if a missing
group, changed source, false restored value, nonzero code at zero scale,
zero-hidden original, field alias or unchecked padding can be accepted.

Expected metadata fixes the attention schema, canonical block, identity,
three external source ids and repetitions. C=min(1024,L-1024*block), with
0<=block<ceil(L/1024), in both accumulation modes. All C rows are mandatory;
there is no probability mask here. Width w<=16384 and C*w<=2^24. Partition
consecutive whole rows into groups of at most floor(16384/w) rows, at most
1024 groups. Each group consumes a complete signed8 proof, the same magnitude
under the tighter symmetric code cap, and complete U in 0..2S. Dynamic
S=127*259; static S=s*min(127,floor((65536+s)/(2s))).

External roots retain one raw-code plane, four U planes over the flattened
row-major domain padded once to N=next_power_of_two(C*w), and two scale
planes over R=next_power_of_two(C). Every byte uses a four-byte M31 payload.
Discard only proven-zero group padding. Spool one raw byte and four U bytes
per actual entry, at most 5*2^24 bytes. Replay reauthenticates raw, magnitude
and compact U group roots. Canonical signed8 consumption fixes sign=raw>>7
and magnitude=raw if raw<128 else 256-raw; neither needs a global table.

Dynamic scales consume complete s in 0..259, n in 0..1 and k in 0..258.
One A3 over 2R proves s=k+n and s*(1-n)=0, including zero padding. Static
scales equal the configured public vector. After all roots, verified child
states and the scale-predicate proof, draw a=log2(N) coordinates theta and
an independent eta for dynamic mode. Let lambda_i=eq_theta(i), then form
B_j=sum_c lambda_(jw+c)*(256*sign_jc-raw_jc),
M_j=sum_c lambda_(jw+c)*magnitude_jc and
T=sum_actual_i lambda_i*(S-U_i). One degree-two A1 over R rows proves
sum_j s_j*B_j + eta*(1-n_j)*M_j = T in dynamic mode; static omits the second
term and eta. Pad every row table with zero. Consume every original view at
the emitted point, including factors hidden by zero. The verifier computes
linear projections of authenticated digits, not signed value-scale products.
Restoration sides are bounded by max(2S+256*smax,S+255*smax)<=16908030<p/2;
the zero-scale identity is bounded by the symmetric code cap.

Project flat rows with maximal aligned dyadic intervals. Cache suffix equality
weights of sizes at most w (total below 2w), and traverse prefix weights with
a depth-a stack. Base-field matrix multiplication projects each interval;
extension multiplication combines its prefix. No full N extension table is
allocated. Parent storage is O(w*d+C*d+groups), plus one child proof and the
spool. Caller/codec peaks are additional. This is not measured memory evidence.

Reserve I<2^37, B=2^63+2^25*I. Group g<1024 has base B+2^14*g;
raw/magnitude/U source ids add 1/2/3. Signed identity is 65536*I+32*g+1;
tight magnitude/U wide identities are 524288*I+256*g+65/66. Dynamic common
wide identities are 524288*I+262144+1..3. Their n/k source ids are
B+2^24+1/+2; scale uses its external id. Parent predicate/A1 identities are
2097152*I+1048576+64/+65. Predicate views are B+2^24+512..515 and A1 views
B+2^24+1024..1027. External roles are distinct and outside the entire span.

For group padded exponent ag and compact U byte exponent bg, independent
lookup dimensions are (ag+1,ag+1,ag+2,ag+1,ag+bg+1). Its A3 numerator is
61ag+9+7bg and each nonlookup label has 26ag+4+3bg draws. Dynamic common
lookup dimensions are (ar+2,ar+1,ar+2), ar=log2(R); common ranges and predicate
A3 contribute 30ar+17 and 13ar+7 draws of each nonlookup label. Parent
projection identity loss is (a+dynamic)/|K|; separate A1 loss is 2ar/|K|.
Parent Sumcheck draws add a+dynamic+ar. Each lookup retains its independent
identity ((2^m+255)/|K|)^r and unsquared reduction
r*(F(m)+F(8)+3m)/|K|, F(m)=3m(m-1)/2+2m. Binding/FS/H and upstream ownership
remain additional. Receipts must match these counts exactly.

Tests first: 10000 independent projection cases per field, zero/one challenge
coordinates, irregular row partitions, invalid shapes, and full-domain
closed-form projection checks; all full parameter and namespace boundaries;
complete finite proof matrix; changed valid sources, exact stream roster,
tighter cap, zero-scale and false U controls; every original view; complete
small source joins. Require complete 1024x16384 dynamic/static proofs,
1023x16383 ragged proof and tail block without shrinking domains. Full model,
projection-row/GQA/cache ownership, native private PCS/ZK/FS, GPU parity,
resource evidence, fidelity and independent audit remain open. Original task
criteria and live runs are unchanged. No production coverage is earned.

The tests-first executions rejected both missing modules. Flat projection then
passed 10000 random cases per field, 36540 row intervals and 75000 cells;
counts and SHA-256 are frozen in the checker:
`df1424e9bff587280b74434f0084246230a7a814d9178bfd0f686cab89cbd4aa`.
Both fields passed the streamed 2^24-entry closed-form arithmetic check and
the ragged 3x10923 group projection/replay checks. These are arithmetic tests,
not complete large source-proof coverage. Source substitutions, false U,
compensating entries, zero-scale codes, tighter caps, padding, high planes,
flat layout, M31 aliases and original-view controls passed. Complete small
prepared-row to restored-block to weighted-sum joins passed for both policies.
The full shape/corpus run, complete proof matrix and repository gates remain
in validation. Full-size consumers and independent resource evidence remain
required. See the [author review](../../agents/reviews/attention-block-values-draft.md).
