# RFC-0021 — Canonical nonlinear functions, tables and representations

Status: Draft · Version: 0.1.0 · Depends: RFC-0003, RFC-0004, RFC-0008, RFC-0012

## 1. Statement and authority

This contract defines integer functions, canonical table data and their identities.
It authorizes native generators and deterministic public-table evaluation, not
lookup inclusion, a private opening, a complete CQIS forward pass or a profile.
RFC-0004 A4, RFC-0005 A1, RFC-0008 A4, RFC-0009 A1 and RFC-0011 A2 coordinate
the consumers. Earlier numerical studies are evidence, not alternate definitions.

Parameters are exact integers with the bounds below. An absent parameter has no
implicit default unless expressly stated. Unknown versions, names, parameter
lengths and noncanonical encodings reject. All arithmetic is exact; host floats,
saturation, wrapping, guessed tails and backend-dependent variants are forbidden.
One failed entry rejects a whole table. No partial table is an admission result.

Write R(z)=sign(z)*floor(abs(z)+1/2), with sign(0)=0. Thus rounding is signed
half-away, including exact ties. An activation input integer t has real value
x=t/2^F and its output integer Y has units 2^-E. Scaling is part of the function,
not a claim about a selected model's fidelity. E5-03 chooses model scales;
E5-04/E5-05 deliver reference inference and fidelity under RFC-0004 §8.

## 2. Protocol and exact function definitions

There are no prover messages, challenges or transcript operations in this
deterministic contract. Actual reductions must supply their own Accepted schedules,
static bound certificates, consumers and soundness-accounting lines.

### 2.1 Exponential functions

For product exp, parameters B,F,E,k satisfy 7<=B<=31, 0<=F<=30, 0<=E<=14,
1<=k<=16 and 0<=B-k<=15. Put Q=2^E. For -2^B<=t<=0, uniquely write
u=-t=2^k h+l, 0<=l<2^k. Define

    H[h]=R(Q exp(-2^k h/2^F)),  h=0..2^(B-k),
    L[l]=R(Q exp(-l/2^F)),      l=0..2^k-1,
    P_k(t)=floor(H[h]L[l]/Q).

The inclusive domain has 2^B+1 values; the last h is legal only with l=0.
H has at most 32,769 entries and L at most 65,536. P_k(0)=Q and
0<=P_k(t)<=Q. P_k is not necessarily monotone. The split k changes its integer
function and must be encoded, including k=7 when selected.

Nearest exp has parameters B,F,E with 7<=B<=15 and the same F/E bounds:
D(t)=R(Q exp(t/2^F)) on the same inclusive domain. It is monotone. A corrected
representation chooses valid k and C_k(t)=D(t)-P_k(t), then returns P_k+C_k.
C_k is an input-indexed table with 2^B+1 entries, not a four-row lookup merely
because its values lie in {-1,0,1,2}. Direct D and corrected D are the same
function; P_k is a different function. Nearest/corrected B>15 is unsupported
in this version and rejects before allocating a full-domain table.

No score clipping, tail truncation or implicit rescaling is permitted. B=14 and
E=12 remain configuration defaults from RFC-0004 §2, resolved to explicit bytes;
there is no implicit F. Domain failures reject. A quantiser/plan must establish
the configured domain and all field-faithfulness bounds from authenticated shapes
and CQIS parameters; runtime observations do not replace those certificates.

### 2.2 Activations and ranges

For t=-32768..32767, 0<=F<=30, 0<=E<=14, let Y=R(2^E f(t/2^F)) and require
Y in signed int16. The entire 65,536-row table must succeed. Functions are:

| Name | f(x) |
|---|---|
| sigmoid_q | 1/(1+exp(-x)) |
| silu_q | x/(1+exp(-x)) |
| softcap_q | c tanh(x/c), c=cap_m/2^cap_f |
| gelu_q | x Phi(x), Phi the standard normal CDF |
| gelu_tanh_q | x/2*(1+tanh(sqrt(2/pi)*(x+(8943/200000)x^3))) |

Softcap requires 1<=cap_m<=65535, 0<=cap_f<=30 and cap_m odd when cap_f>0.
Other activations have no cap parameter bytes. Exact GeLU and tanh-GeLU cannot
substitute for one another. Neither SiLU nor GeLU is required to be monotone.
The range_b table, b in {8,12,16}, has one column containing 0..2^b-1 exactly.
Other widths require an Accepted decomposition, not an unregistered table.

### 2.3 RMSNorm and its rsqrt table

Parameters (d,F,G,E,en,ed) satisfy 1<=d<=16384, 0<=F,G<=30, 0<=E<=14,
1<=en,ed<2^32 and gcd(en,ed)=1. Epsilon=en/ed is strictly positive, with no
default. X_i,H_i are signed int16, representing x_i=X_i/2^F, g_i=H_i/2^G.
The real reference is g_i*x_i/sqrt(mean_j(x_j^2)+epsilon). Define

    S=sum_i X_i^2, N=ed*S+en*d*2^(2F), P=ed*d*2^(2F), q=N/P.

Choose the unique a such that 16384<=q/4^a<65536, with -23<=a<=9. Set
M=floor(q/4^a). Preserve the exact identity A=M D+R, 0<=R<D, where
(A,D)=(N*4^-a,P) for a<0 and (N,P*4^a) otherwise. The intervals tile the
positive axis; S=0 and nondivisible statistics are valid. An integer algorithm
starts at floor((bit_length(N)-bit_length(P)-14)/2) and decrements once iff
A<16384D. It never rounds away the remainder.

The fixed rsqrt table is J(M)=R(2^21/sqrt(M)) for M=16384..65535. Its
49,152 values lie in [8192,16384]. Generate b=isqrt(floor(2^42/M)), then
increment b iff 2^44>=M(2b+1)^2. Equivalently, certify
M(2J-1)^2<=2^44<M(2J+1)^2. Padded entries are not valid mantissas.

Set T_i=X_i H_i J and e=F+G+21+a-E. For e<0, Y_i=T_i*2^-e exactly.
Otherwise Y_i=sign(T_i)*floor((abs(T_i)+h)/2^e), h=2^(e-1) for e>0,
h=0 for e=0. Require signed-int16 Y_i, with no double rounding. This is the
wide norm output; the int8 conversion in RFC-0004 §3 is a separate operation.
The existing int32/nonnegative-shift Requant API must not be used for this
wide product/possibly negative shift. Zero inputs produce zero outputs.

Normalization is total; output overflow still rejects. Larger d, negative
fractional-bit parameters and other formats need an amendment, including any
chunked extension; this version does not pretend to implement them. Native
forward inference and static norm certificate schemas remain E5-03/E5-04 work.

## 3. Generator algorithm and cost

Every nonlinear entry is certified with exact integer/rational bounds. The
reference precision schedule is b=32,64,128,256, in that order; reject Precision
after the last unresolved interval. Series below have a 512-step cap. Reject
the configuration on interval failure, output overflow or unsatisfied capacity.
Certificates are generation evidence; their Python dictionary representation is
not protocol data. Canonical table bytes contain only the exact integer rows.

For exp(-x), x>=0, use the exact singleton at x=0. For x>=b+1 use the strict
bound 0<exp(-x)<2^-(b+1). Otherwise halve to y=x/2^s<=1/2, set p=b+s+4,
and use adjacent odd/even alternating Taylor partial sums until their rational
width is at most 2^-p. Floor/ceil outward onto denominator 2^p and square s
times with outward rounding. The final width is strictly below 2^-b. Multiply
by Q and round both endpoints; equal integers certify an exponential entry.

Activations use strict intervals for x!=0. Their strict exp helper uses
0<exp(-x)<2^-b for x>=b; below that use the preceding enclosure. Transform
z=exp(-abs(x)) by 1/(1+z) or z/(1+z) for sigmoid, multiply by x for SiLU,
and transform z=exp(-2abs(x)/c) by c(1-z)/(1+z) for softcap, restoring sign.
At x=0 use exact 1/2 for sigmoid and zero otherwise. Never replace a finite
tail by its limiting zero. For a strict interval (l,u), compare R(l+) and
R(u-): R(v-)=R(v)-1 at positive half-integers, R(v+)=R(v)+1 at negative
half-integers, and ordinary R elsewhere. Equal extremes certify the entry.

For GeLU, bound pi by 16 atan(1/5)-4 atan(1/239). To obtain c=1/sqrt(2pi)
at dyadic precision t=b+8, bound each arctangent by adjacent alternating sums
to width strictly below 2^-(t+8), combine with reversed subtraction endpoints,
then apply outward integer square-root bounds with denominator 2^t. Check the
root inequalities exactly. For a=abs(x)<8, bound
I(a)=sum_n (-1)^n a^(2n+1)/(2^n n!(2n+1)). After n>=a^2/2, update odd/even
bounds, intersect with (0,a), and stop at width below 2^-(b+8). Bound
Phi(-a)=1/2-c I(a), intersecting with (0,1/2). For a>=8 use
0<Phi(-a)<exp(-a^2/2)/(2a). For tanh-GeLU, with v=a+(8943/200000)a^3,
bound z=exp(-4cv) using reversed c endpoints and Phi's substitute z/(1+z).
Restore a(1-q) for positive x and -a q for negative x; apply strict rounding.
These are distinct real functions. Exact zero remains a singleton.

The derivations and independent oracles are in the linked
[exp](../../formal/cqis-exp.md), [wide exp](../../formal/cqis-wide-exp.md),
[activation](../../formal/cqis-activations.md), [GeLU](../../formal/cqis-gelu.md)
and [norm](../../formal/cqis-rmsnorm.md) studies. Their reference source at commit
c8995be7bc77d950c43c8e0cc808ac1a72da291a fixes the stated stopping/guard-bit
conventions for native parity; caches and research certificate JSON are not
part of the function. A reference algorithm change requires versioned review.

Generation/validation costs O(sum Lc) entries plus bounded exact arithmetic and
hashing, in T_misc, where L<=65536 and c<=2. Norm evaluation costs O(d) plus
bounded normalization and one rsqrt membership per row; all limb/range/output
work remains in c_a. Product exp uses two memberships, corrected exp three,
direct exp/activations one: charge those terms in c_lu, plus recombination and
range work in c_a. No full correction table cost may be omitted. No measured
constant, extra weight pass or committed intermediate is introduced.

## 4. Canonical bytes, verifier algorithms and resources

H is ordinary unkeyed BLAKE3-256. All lengths count bytes, fixed unsigned
integers are little-endian, and no terminator/alignment/trailing data is allowed.
All named definition versions are exactly u32 1. TableId hashes

    ASCII("stele/v0.1/table/identity") || u16(name_length) || ASCII(name)
    || u32(version) || u16(parameter_length) || parameter_bytes.

The closed component schemas, with rows ordered by increasing input, are:

| Name | Parameters | Rows |
|---|---|---|
| exp_q/hi | u8 B,F,E,k | (h,H[h]) |
| exp_q/lo | u8 B,F,E,k | (l,L[l]) |
| exp_q/direct | u8 B,F,E | (t,D(t)), B<=15 |
| exp_q/correction | u8 B,F,E,k | (t,C_k(t)), B<=15 |
| sigmoid_q, silu_q, gelu_q, gelu_tanh_q | u8 F,E | (t,Y(t)) |
| softcap_q | u8 F,E; u16 cap_m; u8 cap_f | (t,Y(t)) |
| rsqrt_q | empty | (M,J(M)) |
| range_8, range_12, range_16 | empty | (v), one column |

Derive real rows N, padded rows L=2^ceil(log2 N), and c from the descriptor.
Canonical table data is ASCII("stele/v0.1/table/data") || TableId[32] ||
u32(N) || u32(L) || u8(c) || row-major i32 entries for L rows and c columns.
i32 is signed two's complement. Rows N..L-1 contain only zeros. Expected
descriptor-derived shape and exact byte length are checked before row allocation;
the complete regenerated definition and padding are checked before admission.
An honest TableId or self-consistent data digest does not validate arbitrary rows.
Field-congruent alternative integers are invalid canonical encodings.

FunctionId uses the same framed fields with prefix
ASCII("stele/v0.1/function/identity"). Names/parameters are exp_q/product with
u8 B,F,E,k; exp_q/nearest with u8 B,F,E; rmsnorm_q with u16 d, u8 F,G,E,
u32 en,ed; and activation/range names with their component parameters.
Descriptor decoders cap total bytes at 128, name bytes at 32, parameter bytes
at 64 before parsing, then enforce the exact closed schema. Boolean/float host
values are not integer parameter encodings. Unknown names and versions reject.

A representation encodes ASCII("stele/v0.1/function/representation") ||
FunctionId[32] || u8(mode) || u8(parameter_length) || parameters ||
u8(component_count) || ordered TableIds[32 each]. RepresentationId=H(these bytes).
The only modes are 0: direct nearest/activation/range, no parameters, one direct
table; 1: product exp, no parameters, hi/lo; 2: nearest exp, one u8 k, hi/lo/
correction; 3: RMSNorm, no parameters, fixed rsqrt. All components are derived
from the function and mode parameters, including every exp parameter. Wrong
count, role, order, split, substitution or unused byte rejects. The expected
representation comes from authenticated configuration, never proof metadata.

The function manifest rejects duplicate FunctionIds, including two selected
representations of one function. Sort functions by raw FunctionId; derive the
exact component union and sort by raw TableId. Reject unequal descriptors with
the same identity. Counts must fit u32. Canonical manifest bytes are

    ASCII("stele/v0.1/cqis/functions") || u32(function_count)
    || for each: u16(function_descriptor_length) || function_descriptor
         || u16(representation_length) || representation_bytes
    || u32(component_count)
    || for each: u16(table_descriptor_length) || table_descriptor
         || H(canonical_table_data)[32].

Empty sets have zero counts. Verification derives the expected set/bytes from
the verifier-owned configuration, regenerates all table data digests, and compares
the entire record. No supplied count, digest or representation is authority.
The manifest is a function set, not operation order, tensor-source binding,
the complete cqis_id preimage or a passport. RFC-0005 A1 and RFC-0011 A2 bind
these objects at their actual consumers. No opaque unvalidated model-config
blob can authorize an inference merely by being placed beside this manifest.

For public MLE evaluation, lift each integer v canonically into M31 as v mod p,
then into QM31/OM31 with all nonconstant coefficients zero. Integer artifact bytes
and field limb bytes differ. For r in K^log2(L), column j evaluates as
sum_(i=0..L-1) eq(MSB_bits(i),r)*T[i,j]. The public valid-row selector is
sum_(i<N) eq(MSB_bits(i),r). Zero padding is not selector enforcement. Native
evaluation costs O(Lc) K work and supports canonical QM31/OM31 only; it does
not draw a challenge, authenticate r or establish membership.

Native types keep checked descriptors/representations and generated tables
private and immutable. Parsing metadata is not content verification. Raw table
bytes become a generated-table object only after checking the expected descriptor
and complete canonical definition. There is no external table-authority callback,
unchecked constructor, caller-supplied field limit or verification bypass.
Length/index/capacity arithmetic and integer conversions are checked. Allocation
failure rejects Capacity atomically, preserves borrowed inputs and returns no
partial object; use fallible reservation for owned buffers. Scratch arithmetic
must be bounded by these parameter/precision caps, not untrusted claimed lengths.

## 5. Soundness, error bounds and profile boundary

These are deterministic numerical and encoding statements, not an IOP or FS
theorem. For H,L nearest rounding, |HL/Q-Q exp(t/2^F)|<=1; flooring gives
-2<P_k-Q exp(t/2^F)<=1. Thus product error is strictly below two output units.
D and every activation have error at most 1/2 output unit relative to their
own real functions. C_k belongs to {-1,0,1,2}. Range tables are exact. These
are uniform proofs, not sampled maxima or model-fidelity claims.

For norm inverse I=J/(2^21*2^a), 1-2^-14<=I sqrt(q)<1+delta, where
delta=2^-15+2^-14+2^-29=49153/536870912. Mantissa truncation, rsqrt rounding
and final rounding are separate: output error is at most
2^E*(32768/2^G)*ceil(sqrt(d))*delta+1/2 integer output units. This norm is
not correctly rounded exact real RMSNorm. The bound applies to successful
outputs; it does not waive overflow checks or establish model fidelity.

Component coordinates have magnitude <=65535, but operation relations may be
wide. S<=d*2^30; byte-split sums have bounds d*128^2, d*128*255, d*255^2.
Conservatively N<2^107, P<2^106, A<2^153, D<2^124, abs(T)<=2^44,
left-shifted products<=2^60 and biased right-shift magnitudes<2^90.
The exp input u can equal 2^31. No single-M31 equality may represent these
wide identities without explicit range/limb consumers and verifier-recomputed
static certificates. RFC-0004 §6/A3 remains required; witness generation is not
a proof. This contract neither supplies nor weakens those certificate schemas.

Injective framing reduces distinct-data identifier collisions to H collisions,
under the existing hash assumption. All identifier/data/commitment hashing must
be counted in H/FS as applicable; this is not a concrete hash-query budget.
No SC/RLC/LU/PCS/MASK challenge or loss is introduced by an unused deterministic
primitive. Actual consumers must account for their own instances. Both profiles
retain Q12 and all lookup/PCS/privacy gates; neither profile is admitted here.

## 6. Controls and native delivery

Reserve NC-0412 for a changed configured FunctionId/semantic parameter,
NC-0413 for a changed selected representation/component role, and NC-0414 for
one altered table-data entry under the correct descriptor. Existing NC-0404,
NC-0405, NC-0104/0105 and NC-0701 retain table/passport, recombination, domain,
norm and commitment bindings. Proof controls require their real consumers.
Research assertions and primitive identifier sensitivity earn no such credit.

E5-02 native delivery requires all of the following, without marking E3-08,
E5-03/E5-04/E5-05 or E10 complete:
1. Every component/function/representation schema, exact generator and canonical
   byte validator, with sealed expected authority, whole-table failure and
   checked no_std consumption. Generation may use alloc exact big integers;
   dependencies require ordinary lockfile/bans/no_std review, not floats.
2. Rust versus independent exact Python generation for full representative tables,
   at least 10,000 varied supported inputs per nonlinear function and boundary
   parameters, plus NumPy integer table-gather/rounding parity. All committed
   descriptor/data/manifest vectors match. No reference subprocess in the core.
3. Canonical QM31/OM31 MLE evaluation versus an independent Boolean-table oracle
   at 10,000 points per supported evaluator kind, including maximal shapes,
   two-row high components, signed lifts and zero padding.
4. Native mutation checks for version/parameters/role/order/id/entry/padding,
   malformed/trailing lengths, field aliases, capacity and whole-table overflow.
   Every actual new binding ships its control in the implementation PR. This
   RFC grants no new exception to Workflow 08's real-consumer requirements.
5. Digest, negative-control, soundness-accounting, fmt/clippy/workspace and
   dependency gates. GPU changes additionally require the actual parity gate.
   No benchmark number without a clean-source ledger; no performance extrapolation.

The remaining reduction/registry/passport deliveries must connect every original
claim, enforce selectors and all ranges, and exercise the reserved controls under
their unchanged real consumers. A generated table or manifest is never proof
acceptance. Fidelity and full causal/decode parity remain original E5 criteria.

The native generation/byte primitives themselves do not create a claim-graph
edge or authenticate a model's configuration. Their mutation tests are ordinary
primitive tests, as with RFC-0010 A4's encoder; they are not catalog controls or
a synthetic proof verifier. Reserved controls apply when the actual consuming
proof/plan/passport binding is implemented, with its honest real baseline.

## 7. Open questions and preserved work

Q25's numerical/table/function contract is addressed here; native delivery and
consumer integration remain tasks. Q26 covers quantisation, scale selection and
static certificate schemas. Full canonical operation/source plans and passport
proofs remain E6/E10; a missing accepted contract there still blocks those tasks.
Q12, Q29 and Q31 retain full FS, privacy and lookup obligations. RoPE variants
remain public tensors under RFC-0017 and need their own E5-04 parameter contract;
they are not silently admitted as lookup components by this closed registry.

## 8. Amendment log

Initial contract. Companion amendments preserve the full inference objective and
all original downstream acceptance criteria. No model-fidelity default, completed
native task, independent audit or production inference claim follows from adoption.
