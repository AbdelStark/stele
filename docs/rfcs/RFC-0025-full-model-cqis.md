# RFC-0025 — Canonical full-model CQIS and checkpoint conversion

Status: Accepted · Version: 0.1.0 · Depends: RFC-0004, RFC-0005, RFC-0011, RFC-0017, RFC-0021, RFC-0022

Task: E5-03b. Question Q26. This accepts the complete numerical/source contract
and its outer identity definitions. Native implementations must also satisfy
their complete governing child contracts before proof or passport admission.
All original implementation, privacy, profile, fidelity and benchmark criteria remain.
Review: [skill sign-offs and all twelve answers](../../agents/reviews/full-model-cqis-draft.md#coordinated-acceptance-sign-offs).

## 1. Statement and authority

The numerical statement is that the exact quantised physical tensors selected by
an authenticated configuration evaluate a specified token sequence under that
configuration. A complete inference proof must additionally bind those tensors,
the inputs, outputs, decoding policy and every intermediate relation through the
accepted claim graph. Numerical execution, a content hash, a certificate parser
or a self-selected configuration does not establish that proof statement.

The mandatory named targets are GPT-2-small and Llama-3.1-8B. GPT-2 uses learned
position embeddings, affine mean-centering LayerNorm, biased attention/FFN
projections, tanh-GeLU and a tied embedding/head. Llama uses RMSNorm, GQA, scaled
RoPE, SiLU gating and its configured untied head. Their source architectures are
pinned to [OpenAI's reference](https://github.com/openai/gpt-2/blob/9b63575ef42771a015060c964af2c3da4cf7c8ab/src/model.py)
and [Meta's model definitions](https://github.com/meta-llama/llama-models/blob/0e0b8c519242d5833d8c11bffc1232b77ad7f301/models/sku_list.py).
The integer functions below are CQIS choices, not reproduction of host floating
point or a claim of fidelity. Other RFC-0017 architectures remain required by
their original tasks; an unsupported family must reject explicitly.

All dimensions and numerical choices are independently expected configuration.
There are no inferred source names, automatic precision changes, saturating
operations, fallback on overflow, or model-specific hidden defaults. A named
target must use its actual layers, vocabulary, dimensions and physical roles;
changing them defines a different model, even if a smaller example executes.

This contract covers positive context capacity at most 2^20, vocabulary at most
2^20, 1..128 layers, residual/FFN widths 1..16384, 1..128 query heads, positive
KV groups dividing the head count, and head width with h*d_h<=16384. These
domains include both targets. Hardware allocation limits are checked separately;
the research implementation's 2^22-element cap is not a semantic model limit.

## 2. Deterministic protocol and numerical definitions

There are no messages or random challenges in numerical preparation/evaluation.
Proof reductions retain their own accepted schedules and accounting. Write
R(n/d)=sign(n)*(floor(abs(n)/d)+[2*(abs(n) mod d)>=d]) for integer n and d>0.
Zero has positive canonical sign where a sign witness is used. Every displayed
sum/product is exact before the explicitly named R. Every required int16 result
lies in [-32768,32767]; a failure rejects the entire operation without a partial
output or cache update. Int8 conversion uses the symmetric range [-127,127].

### 2.1 Source conversion and physical tensors

Selected checkpoint scalars are little-endian binary16, bfloat16, binary32 or
binary64. Decode sign/exponent/significand with integers, including subnormals;
reject every NaN/infinity. Both signed zeros map to zero. The resulting dyadic
rational, not a host cast, is the conversion input. No calibration is implicit.

For a weight tensor with explicitly selected b in {4,8}, q=2^(b-1)-1 and
output-channel maxima M_j, let M=max_j M_j. If M=0, e=0 and every m_j=1.
Otherwise choose the least integer e with M<=q*65535*2^e, then
m_j=max(1,ceil(M_j/(q*2^e))). The stored code is R(w/(m_j*2^e)). Thus
1<=m_j<=65535, |code|<=q and absolute conversion error is at most m_j*2^(e-1).
All-zero channels retain their tensor's e and m_j=1. The source domain gives
-1099<=e<=1024. This is a weight exponent, not an int32 Requant shift.

Learned norm gains and all affine biases use signed int16 codes: a separately
configured fraction G in [0,30] gives R(source*2^G); overflow rejects rather than
changing G. Bias conversion is explicitly included, extending the old gain-only
research choice. Each bias's fraction is bound at its consuming operation.

Matrices are canonically output-channel major. Embedding and learned-position
rows use their row as the scale channel. Tied roles reference one identical
physical record, including its codes and scales. GPT-2's source Conv1D transpose
and fused Q/K/V partition must be explicit source-map operations; they cannot
be inferred during execution. Source mapping is offline preparation, not another
online proof weight pass. The [encoding appendix](full-model-encoding.md) defines
the exact physical role order, transform bytes, fused partitions and alias rules.
The [conversion appendix](full-model-conversion.md) fixes original-byte scalar
access, complete scale derivation and streamed Artifact completion semantics.

### 2.2 Row conversion, affine projection and residual alignment

A row's codes, scale and source fraction are one semantic bundle. For an int16
row X in units 2^-f, dynamic mode has M=max_i |X_i|, s=ceil(M/127), and
q_i=R(X_i/s) if s>0. At M=0, s=0 and every code is zero without division.
Static mode fixes s in [1,65535], computes the same R and rejects codes outside
[-127,127]. Static mode never changes to dynamic mode on failure. Both modes
must be encoded explicitly. Dynamic int16 scales are at most 259.

For a code row q with scale s and fraction f, a weight output channel with
codes w, mantissa m and exponent e, define A=sum_k q_k*w_k. In target units
2^-fo, an unbiased projection is Y=R(A*m*s*2^(e-f+fo)). With bias B in units
2^-fb, it is Y=R(A*m*s*2^(e-f+fo)+B*2^(fo-fb)). There is exactly one rounding,
after the bias addition; no rounded matmul result is used as its input. Require
int16 Y. A zero row scale requires zero codes/A, but does not remove the bias.

For residual inputs X,Y in units 2^-fx,2^-fy and result units 2^-fo, set
c=max(fx,fy,fo) and return R((X*2^(c-fx)+Y*2^(c-fy))/2^(c-fo)). Require int16.
The units of each residual cut must equal the next norm's input units. Adjacent
blocks and the final norm must agree without an implicit conversion.

### 2.3 RMSNorm and exact-mean affine LayerNorm

RMSNorm is exactly RFC-0021 §2.3, including its positive rational epsilon,
normalization remainder, rsqrt table and single output rounding. It has no bias.
It cannot substitute for LayerNorm. Both norm kinds select their kind and every
parameter explicitly; their physical gains/biases are distinct source roles.

For LayerNorm, parameters d,F,G,E,en,ed have RFC-0021 §2.3's domains, and
the bias fraction Gb lies in [0,30]. X_i,H_i,B_i are signed int16. Define

    S=sum_i X_i, Q=sum_i X_i^2, V=d*Q-S^2, C_i=d*X_i-S,
    N=ed*V+en*d^2*2^(2F), P=ed*d^2*2^(2F), q=N/P.

Thus q is the exact population variance in real input units plus epsilon.
Never round S/d or replace V by an RMS statistic. V>=0 follows from
V=sum_(i<j)(X_i-X_j)^2; positivity of epsilon gives N,P>0 even at d=1.
Use the same unique normalization a, M, A, D, remainder and rsqrt J as
RFC-0021 §2.3, applied to this N/P. Here -23<=a<=9 also suffices because
2^-32<q<2^33. The inclusive mantissa range remains 16384..65535.

Set e=F+G+21+a-E, k=max(e,Gb-E,0), and

    U_i=C_i*H_i*J*2^(k-e)+d*B_i*2^(k+E-Gb), D_out=d*2^k,
    Y_i=R(U_i/D_out).

All powers have nonnegative exponents in U_i. Require int16 Y. This is one
rounding of the scaled normalized value plus bias. There is no integer mean,
intermediate normalized-output rounding, or bias added after rounding. Constant
rows produce the rescaled bias; d=1 is valid. LayerNorm's function identity must
include Gb; the gain/bias source identities are operation bindings, not table ids.
Its only nonlinear component is the existing fixed rsqrt table.

### 2.4 Attention, rotary positions and complete row scope

Use the restored-value definition from RFC-0004 A6, made explicit here. Q/K
projections are int16 in configured fractions fq/fk. Optional RoPE rotates each
configured adjacent or split pair with public Q14 coefficients and a single
signed rounding per rotated output; unrotated channels are unchanged. Require
int16 before converting the complete Q projection row and complete K projection
row once each. V conversion covers the complete V projection row once. Head
and group views inherit those scales and cannot recompute them.

Head t uses KV group floor(t/(h/g)). For query i and key j,
score=R(dot(q_i,k_j)*sq_i*sk_j*m_score*2^(e_score-fq-fk+Fexp)), where
1<=m_score<=65535, -62<=e_score<=30 and Fexp is the selected exp function's
fraction. This dyadic score multiplier is explicit; no implicit sqrt(d_h).
The static worst absolute score, using the complete successful int16 row-policy
domains, must be below 2^31 before execution, as in RFC-0004 A6. An actual small
or zero score cannot rescue an inadmissible configuration. Masked scores still use the
same arithmetic. Each real causal query has its own unmasked key, so its set
is nonempty. Choose the first unmasked maximum; only unmasked differences enter
the exact selected RFC-0021 exp function. Enforce its entire inclusive domain.

P_hat_j is that exp output and Z=sum_j P_hat_j>0. A restored value is
D_jc=sv_j*v_jc in units 2^-fv. Exact mode uses T_c=sum_j P_hat_j*D_jc and c=0.
Block mode uses absolute blocks [1024b,1024b+1023],
B_bc=R(sum_(j in block b) P_hat_j*D_jc/2^c), T_c=sum_b B_bc. The configured
c in [0,62] must satisfy R(1024*2^E*S/2^c)<=32767 using A6's full
restored-value bound S, even for a shorter request/capacity. Masked slots contribute zero;
keys are not compacted and blocks are not selected from the current length.

For output fraction fo, the wide result is R(T_c*2^(fo-fv+c)/Z), requiring
int16. For e=fo-fv+c, put U=abs(T_c)*2^max(e,0), D=Z*2^max(-e,0); division
has U=qD+r, 0<=r<D and magnitude q+[2r>=D]. Source/sign/zero/strict-remainder
checks remain distinct. Assemble all heads in head order, then convert that
whole output row once for the O projection. No per-head output conversion.

RoPE uses RFC-0004 A7's exact base/linear/llama3 frequency definitions, with
exact rational theta/scaling parameters and Q14 nearest coefficients. No frequency
or angle is rounded before the trigonometric evaluation. GPT-2 selects absence
of RoPE and a learned-position source. Llama-3.1-8B selects theta=500000,
factor8, thresholds1/4, original length8192 and its actual source pairing.
Native certified generation, scalable data/registry identities and public-MLE
consumption remain mandatory native delivery work, not supplied table authority.

### 2.5 Complete decoder blocks and model boundaries

Every projection below uses §2.2, including each configured bias. The first norm
reads the incoming residual cut; its whole output row is converted before Q/K/V.
Attention follows §2.4; O is projected and aligned with the incoming residual to
form R_mid. The second norm reads R_mid, followed by whole-row conversion.

GPT-2's FFN projects to up, applies the exact RFC-0021 gelu_tanh_q table, converts
its complete int16 output row, then projects down. There is no gate projection
or extra product. Its norm kind is §2.3 LayerNorm and all published affine biases
are present. Llama's FFN separately projects up U and gate G, applies silu_q to
G, and forms the exact signed int32 product U*silu_q(G) without int16 narrowing.
Its units are 2^-(fu+E_silu). Dynamic conversion uses M=max |product|,
s=ceil(M/127), including s=0 at zero; static conversion uses its explicit scale.
The dynamic scale bound is ceil(2^30/127)=8454661, not 259. The down projection
uses these units/scales. Align down with R_mid once to form the next residual cut.

At token t and absolute position p, an embedding channel contributes
e_tk*m_t*2^ee. GPT-2 adds its learned-position channel e_pk*m_p*2^ep in exact
real units, then rounds the sum once into the first residual fraction f0. Llama
rounds its token contribution alone. There is no token-vector int16 rounding
before the position addition. Both sources use their actual indexed row scales.
Require int16. Token range, position range, row selection and source identity
are all obligations. Learned position embeddings are not public rotation data.

After every block, apply the configured final norm and whole-row conversion.
The final vocabulary projection uses the selected head in common output units
2^-fl, fl in [0,30], and requires int16 logits. A tied head references precisely
the token embedding's codes/scales; it is not independently quantised or transposed.
The head is unbiased for both mandatory targets. Every role and all layer counts
must be present; a supplied artifact cannot choose the operation sequence.

### 2.6 Full causal evaluation and decoding

Real positions are 0..n-1. Full and cached evaluation use identical configured
attention modes, conversion scopes, absolute positions, masks and units. A cache
retains the exact post-rotation K codes/scales, V codes/scales and configuration
identity. It cannot mix models or renumber an evicted key. The mandatory dense
targets retain the complete prefix; other attention policies require their own
explicit architecture contract.

Greedy chooses the least vocabulary id attaining the previous position's maximum
logit. A nonempty prompt is followed by at most maximum_new tokens; the first
generated member of the explicit nonempty EOS set is included and stops generation.
Prompt EOS does not stop. At zero maximum_new return the prompt with limit reason.
EOS takes precedence when it coincides with the token limit. Prompt plus
maximum_new must fit context capacity. The [request contract](full-model-request.md)
fixes exact request/token-I/O bytes, stop arithmetic and original source joins.
Every returned token, including EOS, is evaluated when checking full/cache parity.
The [numerical execution appendix](full-model-execution.md) describes the complete
Artifact-backed research composition and its internal full-prefix cache boundary.
Sampled decoding has the same prompt/limit/EOS semantics. Its exact
policy, byte identity and required hash/selection consumers are in the
[decoding appendix](full-model-decoding.md). Independent numerical evidence and
the coordinated accounting/consumer review are recorded in §7. Actual sampled
consumers remain required; greedy alone cannot complete RFC-0004 §7.

### 2.7 Canonical configuration, artifact and source identities

Separate the following objects: the source file/bundle and source map, offline
quantiser configuration, canonical quantised tensor data, numerical operation
configuration, function/representation/data registry, static bound collection,
canonical proof plan, and passport/public statement. No one object's hash can
stand in for another. Expected identities come from authenticated caller/statement
authority, not from a matching self-supplied digest.

Reuse the exact scalar/scale/continuous-nibble rules in §2.1 and the existing
RECORDS/ARTIFACT studies, under separately specified production domains. Int4
excludes -8, int8 excludes -128, and an odd final int4 high nibble is zero.
Tensors have exact positive shapes, no data padding, explicit channels/fractions
and exact physical lengths. Reject extra/missing/duplicate roles or records,
noncanonical encodings, inactive parameters and trailing data. Tied roles alias
one physical record; numerical equality does not authorize arbitrary aliasing.

The encoding appendix fixes physical roles, source transforms, runtime numerical
configuration and preparation/artifact frames. The Registry and
[Bounds collection](full-model-bound-collection.md) have complete closed schemas.
Encoding §6 and the public-input/passport appendices fix the complete identity
join. A structural Model digest alone is not the complete numerical identity.
Single-file SHA-256 and the typed indexed-shard bundle identity remain distinct;
hash original file bytes, never reconstructed JSON. Selection and ignored entries
are explicit and checked against the mandatory model role set.
The [source appendix](full-model-source.md) closes Source/Assets file frames,
exact container/selection checks and immutable original-byte slices. Config,
tokenizer and generation semantics still require their authenticated consumers.
The [source-architecture appendix](full-model-source-architecture.md) binds the
explicit adapter and original config to Model/Map/Assets, including all norm
epsilons, rotary layouts and physical source-role transforms. It does not
establish tokenizer execution or the generation/stop-policy join.
RFC-0011 A8 accepts the corresponding complete physical Artifact/Preparation
binding. Structural streaming validation of those bytes is separate from
reproducible source conversion and the proven commitment-to-Artifact hash join.
The [public-input appendix](full-model-public-input.md) fixes the complete outer
statement envelope, actual request geometry and both I/O reference modes. Full
passport/template/instance/ledger/private-source codecs and authenticated proof
consumers remain required; none is replaced by a digest field in that envelope.
The [passport composition appendix](full-model-passport-composition.md) fixes
the subject/evidence/registration/signature order and final-root preimage. It
retains every required child artifact and avoids self-referential attestations;
complete child schemas, authority and proof validation remain mandatory.

### 2.8 Static arithmetic and consumer inventory

For each operation instance, independently expected shapes, formats, numerical
parameters and source roles derive its complete integer ranges. Runtime values,
sampled fit, artifact-provided bounds and a caller-selected modulus are not
authority. Exact maxima may use a proven range of a completely checked table;
they may not use an observed checkpoint/activation maximum to tighten a format.

An integer identity in M31 must have enforced ranges on both sides, with their
difference strictly between -p and p. For centered identities check 2C<p using
exact integers, never the inclusive 2^30 endpoint. Wider words require all byte
ranges, signs, carries, high planes and final zero carry at actual consumers.
Each word width and each column bound is derived statically. There is no generic
certificate type that accepts arbitrary operator text or a prover-supplied tuple.

The full inventory must expand these families, including every branch and index:

| Family | Required identities and source/range obligations |
|---|---|
| Physical input | canonical source decoding, selected physical roles, exact code/gain/bias ranges and original source authority |
| Embedding/position | token/public-position bounds, both gathers, row scales, exact aligned sum, single rounding and int16 output |
| Projection | signed dot sources/result, scale products, optional aligned bias, rounded output and all quotient/remainder/zero branches |
| RMSNorm | original statistic, normalization factors, M/D/remainder, table membership, gain/source association and signed output |
| LayerNorm | original S/Q, C=dX-S, V=dQ-S^2, positive epsilon denominator, shared normalization/reciprocal, affine numerator and output division |
| Row conversion | canonical absolute value/sign, first attained maximum, exact ceiling/slack, scale/code bounds, static failures and zero-row branch |
| Rotation | absolute position/pair mapping, complete coefficient definition, both signed products/sums, single rounding, unchanged tail |
| Scores/mask | Q/K source views and inherited scales, GQA group, dot/multiplier, score range, Boolean/causal selector and attained maximum |
| Exponential | unmasked difference range, inclusive endpoint, selected function/representation, every component and recombination |
| Weighted attention | original V scales/codes, probability sum, weighted restored products, absolute block partition, signed block/global sums, positive scaled divisor, strict division and final row assembly |
| FFN | selected activation membership, correct source/units, optional exact gated product, proper complete-row conversion and down projection |
| Residual/final | one-round aligned source sum, cross-layer units, final norm/head source/tie, vocabulary range and logit output |
| Decoding | previous-position logit source, token bounds, first maximum or complete sampled policy, EOS/length/cause and cache/full identity |

For LayerNorm specifically, |S|<=32768d, Q<=d*2^30,
0<=V<=d^2*2^30, |C_i|<65536(d-1) for d>1, and C_i=0 for d=1.
For the variance bound, averaging (X_i+1/2)^2 and subtracting
(S/d+1/2)^2 gives V/d^2<2^30. Also C_i=sum_(j!=i)(X_i-X_j), so
|C_i|<=65535(d-1), independently of the observed row.
Derive N/P and both signs of a directly from these bounds. A safe global bound
is N<2^121, P<2^120, A<2^167 and D<2^138. For each allowed a, derive
Tmax=65535(d-1)*32768*16384 and
Umax=Tmax*2^(k-e)+d*32768*2^(k+E-Gb), D_out=d*2^k.
The quotient/remainder, rounding increment and output range are separate checks.
These bounds describe exact integers; a single field element cannot hold them.

The [static arithmetic appendix](full-model-bounds.md) specifies the new affine,
learned-position and exact-mean LayerNorm records and their word/source obligations.
The [flow-bound appendix](full-model-flow-bounds.md) adds complete-row conversion,
one-round residual alignment and the exact gated product, including the full
gated static scale range and canonical first-maximum/zero branches.
The [attention-input appendix](full-model-attention-bounds.md) covers full rotary
source indices, statically admissible scaled scores, causal first maxima and
complete inclusive exponential indices.
The [function-bound appendix](full-model-function-bounds.md) covers selected exp
recombination, complete component addresses and activation source/lookup words;
all canonical table definitions must still pass before operation admission.
The [weighted attention appendix](full-model-weighted-bounds.md) covers complete
probability/value sums, every fixed block and variable normalization, with
radix-16 columns through the full context domain.
The [RMSNorm appendix](full-model-rms-bounds.md) integrates the unchanged
RFC-0021 statistic, shared exponent factors, reciprocal lookup and signed output
into a complete record, including original source and padding obligations.
The [decoding-bound appendix](full-model-decoding-bounds.md) adds original logit
maxima, one-round temperature and complete sampled permutation/prefix/CDF/draw
arithmetic. The [request contract](full-model-request.md) adds schema 18 and exact
stop/token-I/O subrecords; their full public-statement and source joins remain required.
The [physical record appendix](full-model-physical-bounds.md) adds schema 19 for
complete tensor coordinates, packed payload addresses and original code/scale
words, including addresses larger than p. Canonical Artifact and source owners
must still consume these bounds and their original bytes.
The [collection appendix](full-model-bound-collection.md) fixes all nineteen
schemas' slot order, Model/Scales/Registry parameter joins and complete bytes.
Its qualification and consuming-reduction mapping are recorded in §7;
the actual native consumers remain delivery work. The old twelve-family numerical record
collection alone is insufficient. Unsupported shapes have an explicit rejection;
neither DPA nor a new advice cut is an implicit fallback.

The [operation and consumer inventory](full-model-consumers.md) expands both full
architectures and names every required source/range/branch/index dependency.
It is a required implementation inventory, not an accepting proof plan or a claim
that all its named consumers already exist.

## 3. Preparation, evaluation and prover cost

Preparation reads the authenticated selected checkpoint, derives exact physical
records and validates the entire resulting configuration/registry/bound set.
Weight maxima require a prior preparation pass or retained data; charge this
offline cost explicitly. Native loaders must stream full-size artifacts with
checked u64 lengths and fallible bounded buffers. The small research caps cannot
be inherited as the mandatory named models' native capacity limits.

Forward execution, including learned positions, biases, LayerNorm, all conversions
and cache storage, contributes T_witness. LayerNorm's extra row sum, centered
variance, mean-scaled sources, bias products and wide divisions contribute c_a
and T_misc; its reciprocal table remains one row membership. Existing activation,
exp and range memberships contribute c_lu/c_x at their actual counts. No count,
lookup, normalization branch or allocation can be omitted from the eventual ledger.

The proof remains subject to one online pass over each original physical weight
source. A tied embedding/head must share the physical source and satisfy both
functional consumers without a second source pass. Exact source ordering,
retained-row use and private/virtual source closure belong to the full plan.
This contract adds no committed tensor, proof bypass, fitted constant or measured
performance result. Its new numerical relations cannot authorize a new advice cut.

## 4. Verification algorithm and cost

The verifier derives the complete configuration and plan from independently
authenticated identities, reconstructs every static bound/registry expectation,
and compares complete canonical supplied records before any use. It never
recomputes inference as a substitute for checking the proof. Actual reduction
consumers must close every row in §2.8 to original authenticated sources and
preserve point identity, range discipline, selectors, transcript order and all
existing conditional losses. No numerical record or validation flag constructs a
successful proof record. Full verifier/codec/resource limits remain mandatory.

Public table regeneration/validation, metadata and bound derivation are charged
to T_misc; each actual proof reduction/opening retains its complete own costs.
The full plan must account for all byte-word state and simultaneous buffers,
not just the scalar formulas or numerical prototype's retained arrays.

## 5. Soundness and numerical error

No probabilistic soundness term changes in this contract. The integer derivations
are deterministic, conditional on their enforced ranges and source relations.
RFC-0012 still accounts for every actual SC/RLC/LU/PCS/MASK/FS/H event. There is
no new profile admission: standard and treaty remain subject to their complete
original bounds, Q12/Q29 and joint privacy obligations.

Weight conversion has the half-scale error from §2.1. Every explicit final R
has error at most one half in its output units relative to that operation's
exact rational argument. RFC-0021's table and reciprocal errors remain separate.
LayerNorm uses the same reciprocal approximation to its positive exact variance
plus epsilon; it is not correctly rounded real LayerNorm. The reciprocal relative
error bound is the RFC-0021 delta=49153/536870912. Since the normalized centered
coordinate has magnitude at most sqrt(d), the output error against exact affine
LayerNorm is at most 2^E*(32768/2^G)*ceil(sqrt(d))*delta+1/2 for successful
outputs. The exact added bias contributes no error beyond its separate source
conversion and final R. These uniform bounds do not establish model fidelity.

## 6. Negative controls and delivery evidence

All original NC-0100..0109, attention, lookup, PCS, source/passport and decoding
controls remain. Acceptance must reserve additional ids for mean/RMS substitution,
rounded mean, omitted/substituted bias, position-source/index substitution, wrong
FFN family, missing source roles, tied-head duplication and model/config identity.
Only the actual consuming implementation earns coverage; research controls do not.

Native delivery requires bit-exact Rust/NumPy arithmetic at 10000 randomized
inputs per operation plus complete boundary/error cases; full named-model forward
and cached decoding parity; actual certificate/role/identity tamper controls;
complete raw-source/artifact/plan/proof identities; and all required gates.
Fidelity is the original RFC-0004 §8 protocol, not agreement between two integer
implementations. W8 remains GPT-2-small with complete proving and verification.

The following additional reservations are `todo` in the control catalogue.
Each requires an accepted honest baseline, one independently changed value and
rejection at its actual owning consumer. Rebuilding dependent encodings or
witnesses must not replace the independently expected source or policy. A parser
failure or an unexecuted reservation supplies no proof-binding coverage.

| Controls | Required binding | Native owner |
|---|---|---|
| NC-0110..0112 | LayerNorm kind, exact mean and original affine bias | E5-04, E6, E7-03 |
| NC-0113/0114 | Original learned-position source and absolute index | E6, E7-08 |
| NC-0115/0116 | Original projection bias and rounding after addition | E7-01, E6 |
| NC-0117 | Prescribed FFN family/activation role | E6, E7-05 |
| NC-0118/0119 | Complete physical roles and identical tied-head source | E5-03, E6, E7-02/08 |
| NC-0120/0121 | Complete numerical identity and original source configuration | E5-03, E6, E12-05 |
| NC-0122 | Full gated scale, including its high bytes | E5-03, E7-01/05/09 |
| NC-0123/0124 | Complete-row attention scale and absolute block position | E6, E7-06/07 |
| NC-0125/0126 | Actual stopping reason and absolute sampling position | E6, E7-08, E8/E14 |
| NC-0704..0710 | Complete child references, preparation, typed source, assets, evidence subject, key authority and signatures | E5-03, E12-05/06, E14-02 |
| NC-1204..1206 | Request-specific plan, minimum profile and original I/O source | E6, E8-02, E12/E14 |

NC-0108 still covers the wrong seed, NC-0700 the final passport root and
NC-0412..0414 the configured function/representation/table data. Their existing
scope remains; the added reservations cannot mark any original control done.

## 7. Acceptance record and remaining native delivery — Q26 / E5-03b

The [coordinated review](../../agents/reviews/full-model-cqis-draft.md#coordinated-acceptance-sign-offs)
closes these five specification requirements. The source-pinned independent
evidence is in [REPORT.md](../../research/cqis-model-contract/REPORT.md), with the
[identity/consumer/DAG review](../../agents/reviews/full-model-delivery-closure.md).
The task still requires all local and selected hosted gates before normal merge.
The requirements are retained here so their scope stays explicit:

1. Complete the exact binary model/source-map/quantiser/artifact/bound schemas and
   their cqis_id/passport/public-statement join, including partitioned/transposed
   checkpoint sources and alias authority. No opaque unvalidated config field.
2. Close the complete static-bound expansion and consuming-reduction dependency
   inventory for every §2.8 relation, including source/range/branch/index checks.
   Distinguish an accepted specification from required native delivery evidence.
3. Produce independent exact evidence for all new choices: affine projection,
   exact-mean LayerNorm, learned-position addition, both complete FFN/model flows
   and malformed/changed identity rejection. Preserve the frozen earlier evidence.
4. Finish the exact sampled-decoding contract required by RFC-0004 §7 and bind
   full/cache/generation stopping semantics. Greedy evidence cannot discharge it.
5. Review coordinated append-only RFC-0001/0003/0004/0005/0009/0011/0017/0021 changes,
   reserve actual new controls, and retain a sequential DAG through original
   E5-03/04/05, E6, E7, E8 and benchmark tasks. No accepted parent requirement is
   removed, weakened or reclassified as numerical-replay completion.

These specification items and required skill reviews are closed. Native
implementation, named-model fidelity, private PCS/ZK, profile
admission and complete end-to-end proof delivery remain required after acceptance.

### 7.1 Coordinated amendment disposition

The following accepted append-only entries adopt the reviewed package.
Historical Draft entries and evidence remain unchanged; supersession is explicit.

| Existing proposal | Accepted authority | Disposition |
|---|---|---|
| RFC-0003 A2/A3/A4 | RFC-0003 A5 and this RFC's complete Bounds definitions | Retain strict integer endpoints and actual source enforcement; use full wide gated records. |
| RFC-0004 A3/A6–A12 | RFC-0004 A13, §§1–6 and linked canonical appendices | Supersede partial numerical descriptors and the old gated u16 restriction; preserve all original native completion gates. |
| RFC-0009 A2/A3 | RFC-0009 A4 and §2.4 | Complete configured source/scale/block semantics; actual reverse reductions remain mandatory. |
| RFC-0011 A3–A7 | RFC-0011 A8 and exact source/passport appendices | Require original source, complete physical Artifact and acyclic attestation joins; native children remain mandatory. |
| RFC-0017 A1/A2 | RFC-0017 A3 and complete model/source definitions | Fix both mandatory families; preserve every other architecture target. |
| RFC-0021 A1/A2 | RFC-0021 A3 and §2.3/encoding §6 | Adopt the exact LayerNorm definition/identity; native descriptor, evaluator and source consumers remain required. |
| RFC-0001 A1/A2, RFC-0005 A4, RFC-0016 A2/A3 | RFC-0001 A3, RFC-0005 A5, RFC-0016 A4 and their linked frames | Retain the exact policy, model-wide template, request instance and acyclic evidence/statement order. |

Accepted RFC-0004 A1/A4/A5, existing function bytes and existing native proofs
are unchanged. The package defines numerical/source contracts and the outer
identity joins; it does not instantiate a full proof plan, private commitment,
certificate, signature suite, authority policy or security profile.

The complete typed child schemas and actual validators remain prerequisites of
their accepting consumers in E6/E8/E12/E14. They must be separately specified
and accepted before production instantiation, with original source/point/range,
privacy, transcript, accounting and control obligations. No root/reference or
metadata success may bypass them. Their absence prevents native proof/passport
admission, not definition of the numerical computation that they must prove.
The [identity review](../../agents/reviews/full-model-delivery-closure.md#5-final-outer-identity-and-authority-review)
checks this exact join and every owning task. Its definition grants no native
child-validation or admission credit; complete task qualification still applies.

Native Rust/NumPy parity, NC-0109, full named inference/fidelity, actual private
proofs, profiles and W8 remain completion criteria of their original tasks.
The sequential DAG preserves those criteria and splits prerequisite artifact
production from final workload delivery, so a final passport or proof is not
required to construct its own evidence.
The [delivery audit](../../agents/reviews/full-model-delivery-closure.md) records
the prerequisite artifacts and moved edges. No Draft protocol or placeholder profile is enabled.

## 8. Amendment log

Initial acceptance: the complete numerical/source/outer-identity definitions and
all nineteen linked appendices are Accepted with the §7.1 companion entries.
Review: the same-author skill and crate-owner sign-offs linked above; ADR-051.
This does not complete any native implementation, privacy, profile or workload task.

### A1 — Completion dependencies for co-owned production controls (Accepted; Q32)

Motivation: E5-03 requires all controls assigned to it in §6, while their actual
plan, reduction and passport consumers depend on E5-03. The explicit YAML graph
is acyclic, but its completion requirements cannot be executed in that order.
The [native completion audit](../../agents/reviews/e503-completion-dependencies.md)
records the exact paths and the separate pending original Llama source.

Add immediately after the §6 owner table:

> A task claiming any control in this table requires the actual owning consumer
> to execute its honest baseline and specified rejection. The completion graph
> must include that requirement, including when the table lists multiple owners.
> A task whose completion requires an unfinished descendant must remain blocked
> until an explicit dependency resolution is Accepted. Numerical preparation or
> parsed metadata does not replace a proof consumer. A resolution must preserve
> every original acceptance criterion and named workload, identify each earlier
> artifact and actual later consumer, and give an executable order consistent
> with the one-task-at-a-time workflow. It must not mark a reserved control done,
> remove a binding, or use a partial-task PR as completed task delivery.

Apply the following dependency replacement. All existing task acceptance lines
remain verbatim, and no control or task becomes complete through this amendment.

| Task | Complete prerequisite list after replacement |
|---|---|
| E5-03 | E5-01, E5-03a, E5-03b, E5-03c, E6-01 |
| E5-04 | E5-02, E5-03c |
| E6-01 | E6-00, E8-02 |
| E6-02 | E6-00 |
| E12-05a | E5-03c, E5-05, E6-02, E3-08, E4-05, E8-05a |

Add E5-03c with prerequisites E5-01/E5-03a/E5-03b, and E6-00 with prerequisites
E5-03c/E3-08/E4-05. Their complete acceptance criteria are the two `add_tasks`
acceptance arrays in the [pinned proposal](../../agents/reviews/e503-sequencing-proposal.json)
at commit a9b6d0be403fd25c77fb8af6cd1669c22cd9fba2, copied into the task graph.
The proposal's pending statuses are historical and are not acceptance criteria.
E5-03c delivers full original GPT-2-small and Llama-3.1-8B numerical preparation,
including both int8 and int4 matrices. E6-00 delivers complete native lowering
with genuine source providers after all its child contracts are Accepted.
Neither prerequisite grants the original parent's completion or any production
control credit. The parent controls run through their actual consumers.

Finish, validate and merge one complete prerequisite before starting another
implementation task. E5-03 and E6-01 remain incomplete until all their original
criteria pass. Final E6-01 follows E8-02, reaching all ten E7 tasks, full passport
and checkpoint/proximity evidence, and native W8 verification. E5-03 follows
that completion. Dependency reachability alone never executes a control.
All other dependency lists and original completion requirements remain intact.

Soundness impact: none; no challenge, theorem, transcript, proof relation or
ledger term changes. Cost-model impact: none; no measured constant or weight
pass changes. Affected tasks: E5-03, E6-01/02, E7-01/02/05/08/09, E12-05a/05/06
and E14-02, plus their transitive dependants and the two named prerequisites.
The [same-author acceptance review](../../agents/reviews/e503-sequencing-acceptance.md)
covers soundness, RFC consistency and affected crate ownership. Q32's sequencing
question is resolved; source access, child protocols, native delivery and actual
control execution remain separate requirements.

Decision: the user delegated sequencing and approved the complete checkpoint.
Adopt the [reviewed prerequisite split](../../agents/reviews/e503-sequencing-proposal.md).
Existing implementation and frozen numerical evidence move forward on the
E5-03c branch without rewriting the E5-03 branch or claiming it complete.
Approval to obtain the checkpoint does not supply missing provider credentials;
full authorized original bytes remain mandatory before E5-03c is complete.
