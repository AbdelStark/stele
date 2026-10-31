# Complete global attention maximum

Q26/Q31, E5-03; Draft RFC-0004 A3/A6, retaining RFC-0009 A1. Before code:
can a full row of L<=2^20 signed32 scores establish one attained maximum,
the first allowed tie and every exponential-domain difference, with bounded
parent storage and one A1? Costs are c_x/c_sc/c_lu/T_misc and source storage.
Kill the design if an omitted key, false maximum, later tie, masked selection,
changed score, field alias, bad carry, domain overflow or unchecked padding
can be accepted. Keep the existing 16384-entry consumer unchanged.

Expected metadata fixes the maximum schema, query, sequence interval and
window. The score roster is exactly 0..L-1; no sparse replacement is allowed.
Derive allowed(j) as start<=j<stop, j<=query and window=0 or query-j<window.
Require start<=query<stop, so at least the query is allowed. All scores,
including masked scores, lie in [-S,S], with 0<=S<2^31. Set H=2S and
Dmax=min(H,2^B), 7<=B<=31, from expected metadata.

Partition consecutive scores into groups of at most 16384 entries. There
are at most 64 groups. Each group consumes seven complete wide ranges:
raw signed32 bytes, offset O in 0..H, difference D and gap G in
0..Dmax*allowed, and four Boolean planes for each of three carries C0/C1/C2.
Padding caps are zero, including all carry planes. A separate complete scalar
range consumes the four raw maximum bytes. All ranges remain independent;
there is no loop of local-maximum proofs or per-group restoration parents.

Four external roots bind the complete raw source, raw maximum, selected
absolute key and complete differences. Source and differences use four
byte planes over N=next_power_of_two(L), padded once; maximum uses four
byte leaves and selection one canonical u32 leaf. Every leaf has a four-byte
M31 payload. Group roots are compact range views, with only proved-zero
local padding discarded. They are revealing research roots, not new cuts.

Spool 28 bytes per actual entry: four bytes each for raw/O/D/G and the
four one-byte carries for each of C0/C1/C2. The maximum spool is 28*2^20
bytes. Replay reauthenticates every compact group root. Read selected raw
and offset bytes from that authenticated group. Check selected is allowed,
its root matches the expected selection, and its raw bytes equal the complete
maximum bytes exactly. This is a byte join, with no signed32 equality in M31.
The producer can prepare this same fixed-width file in one input pass, writing
raw bytes and reserving the other slots while finding the allowed maximum.
It then fills each group in place. No full-row integer vector or second
full-row spool is included in the stated storage bound. Verifier group
retention writes the same records from complete checked child openings.

The row identities are the existing byte-column identities:
raw+S+incoming(C0)=O+256*C0;
allowed*O+D+incoming(C1)=allowed*O_selected+256*C1;
G+prefix+incoming(C2)=D+256*C2.
Prefix is one only in byte zero for allowed keys preceding selected.
All incoming byte-zero carries are zero. Terminal C1+C2=0; their Boolean
ranges imply both are zero. Terminal C0 is allowed, representing signed wrap.
Every side is at most 511<p/2. Together with O<=2S these identities prove
the signed bound, global maximum, domain bound and first allowed tie.

After every expected root, compact group root and verified child state, draw
theta of dimension a=log2(N), then beta and gamma. Project every actual entry
with lambda_j=eq_theta(j); padding contributes zero. Project masked O with
the verifier's mask. Real-row, allowed-row and prefix weights are public
projections. The selected offset is an authenticated four-byte scalar view.

For each byte k form projected residuals R0_k,R1_k,R2_k above, and
T=sum_j lambda_j*(C1_(3,j)+C2_(3,j)). One A1 over the four byte positions
proves sum_k gamma^k*(R0_k+beta*R1_k+beta^2*R2_k)+beta^3*T=0.
Place the terminal term only in byte zero. The allowed-row projection is a
verifier-computed scalar coefficient of O_selected, so A1 degree is two.
Consume all sixteen original tables independently: raw, bias, incoming C0,
O, C0, masked O, D, incoming C1, selected O, C1, G, prefix, incoming C2,
C2, terminal and gamma powers. No supplied projection or receipt is admitted.

Aligned full groups share the last fourteen equality coordinates; a short
tail uses its own padded suffix. Cache only the required suffix matrices,
multiply base-byte/selector matrices by them and apply the prefix weight.
At most 16384 equality weights are needed per suffix, with total below 32768.
There is no N-entry extension table. Parent storage is one group of bytes,
O(16384*d+groups) projection/root state and the spool, plus one complete
child proof. Caller/codec peaks are additional. No measured memory is claimed.

Reserve I<2^39, base=2^63+2^23*I. Group g<64 has wide identities
131072*I+1024*g+1..7, with source ids base+65536*g+32768+1..7.
The scalar maximum range identity is 131072*I+65536+1 and uses the external
maximum source id. Parent view ids are base+2^22+1024..1039; the A1
identity is 524288*I+262144+64. Four external ids are distinct and outside
the entire reserved span. Validate every namespace at maximum I before code.

For each complete range with exponents ai,bi retain independent lookup
identity ((2^(ai+bi+1)+255)/|K|)^r and unsquared reduction
r*(F(m)+F(8)+3m)/|K|, m=ai+bi+1, F(m)=3m(m-1)/2+2m.
Range/A3 numerator is sum_i(9ai+7bi); child nonlookup draws per label are
sum_i(4ai+3bi). Before A1, the residual polynomial has total degree at most
a+5: theta contributes a, the largest mixed term is beta^2*gamma^3, and
the terminal term has beta degree three and gamma degree zero. Its identity
loss is (a+5)/|K|. The separate A1 loss is 4/|K| and total parent Sumcheck
draws are a+4. Byte attainment and streaming add no challenge or algebraic
loss. Binding/FS/H and actual model/score provenance remain additional.

Tests first: 10000 independent integer rows with carries checked by prefix
sums; 10000 projection agreements per field; full parameter/namespace
boundaries; every source, selection, domain, carry, padding and original-view
control; separately valid source replacements, including masked larger scores;
signed aliases differing by p; later ties across groups; exact roster and EOF;
both fields/repetitions with exact receipts. Require complete L=2^20 proofs,
including the inclusive D=2^31 endpoint, a window spanning group boundaries,
ragged L=2^20-1 and L=16385. Global differences must compose with actual
exponential consumers on compatible byte roots in small complete cases.
Full Q/K/V and model ownership, private selection/PCS/ZK/FS, native/GPU
parity, resources, fidelity and independent audit remain open. Original task
criteria, Accepted text, production coverage and all live runs are unchanged.

The compact-replay correction is inherited before implementation. It rejected
all twenty unused-high-byte mutations and preserved eight complete proof
states in both fields. New group replay must likewise authenticate all
stored bytes before projection, including zeros beyond each compact width.

The implementation now consumes the complete range roster and reconstructs
all sixteen views. Complete root, roster and original-value controls passed,
as did terminal wrap, later-tie, signed-alias, padding/carry, masked-selection
and domain-overflow controls. Both fields passed a complete maximum to
exponential join with separately authenticated compact and four-plane roots.

Independent projection checks passed 10000 cases per field and ten group
boundary cases. Seed 2763 produced SHA-256
`8c77add9fe27d8dc207f62a8e729bf500f20e6b0882ddcb4edfaa9caaa51193a`.
All 28 temporary byte positions rejected replay substitutions. These
projection and replay checks are arithmetic checks, not complete proofs.
The corpus, complete proof matrix, full-size cases and repository gates
remain in progress or queued; no resource or native inference claim follows.
